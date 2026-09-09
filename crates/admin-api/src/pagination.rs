//! Cursor pagination: opaque to the caller, cheap for the database.
//!
//! # Why a cursor and not an offset
//!
//! `OFFSET n` makes the database walk and discard `n` rows, so the last page
//! of an audit trail costs the whole trail; and it is *wrong* under
//! concurrency — a row inserted while an operator pages through moves every
//! subsequent row along by one, so a page is skipped and nobody can tell.
//! A cursor names the last row seen and the next page is a range scan from it,
//! which is both a constant cost and a stable sequence.
//!
//! # Why it is opaque
//!
//! [`Cursor`] serialises to `v1.<base64url of the key>`. The key is a column
//! value, not a secret, and this is not encryption: a caller who decodes one
//! learns the id of a row they were just shown. What the opacity buys is the
//! freedom to change the key later — to a compound `(created_at, id)`, say —
//! without breaking a console that had started parsing it, which is the
//! failure mode of a cursor that looks like something.
//!
//! The version prefix is what makes that safe: a cursor minted under `v1` and
//! presented after the scheme changes is refused rather than misread as a key
//! of the new shape.
//!
//! # Why an unparseable cursor is a 400 and not an empty page
//!
//! Because the alternative is a paging loop that silently returns nothing and
//! an operator who concludes there is no audit trail. A cursor the server did
//! not issue is a client bug, and a client bug that reports as "no data" is
//! the expensive kind.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use crate::error::AdminError;

/// The most rows one page may hold, whatever the caller asks for.
///
/// A cap rather than a suggestion: `limit` arrives from the network, and an
/// unbounded one is a request for the server to materialise the whole table
/// into memory on the caller's behalf.
pub const MAX_LIMIT: usize = 200;

/// The page size when the caller does not choose one.
pub const DEFAULT_LIMIT: usize = 50;

/// The scheme version this build mints and accepts.
const VERSION: &str = "v1";

/// The longest key a cursor may carry, before decoding.
///
/// A tenant id is 64 characters and a UUID is 36; 512 is generous for the
/// compound keys this will grow and still refuses a caller who sends a
/// megabyte of base64 to see what happens.
const MAX_KEY_LEN: usize = 512;

/// An opaque position in a listing: the key of the last row already returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(String);

impl Cursor {
    /// Mints the cursor that resumes *after* `key`.
    #[must_use]
    pub fn after(key: &str) -> Self {
        Self(key.to_owned())
    }

    /// The key, for the `WHERE id > $1` the caller will write.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.0
    }

    /// The wire form: `v1.<base64url>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{VERSION}.{}", URL_SAFE_NO_PAD.encode(self.0.as_bytes()))
    }

    /// Reads a cursor a caller presented.
    ///
    /// # Errors
    ///
    /// [`AdminError::CursorInvalid`] for anything this build did not mint: a
    /// missing or unknown version, a body that is not base64url, bytes that
    /// are not UTF-8, an empty key, or one over the maximum key length.
    // fuzz-target: admin_cursor
    pub fn decode(raw: &str) -> Result<Self, AdminError> {
        if raw.len() > MAX_KEY_LEN {
            return Err(AdminError::CursorInvalid);
        }
        let (version, body) = raw.split_once('.').ok_or(AdminError::CursorInvalid)?;
        if version != VERSION {
            return Err(AdminError::CursorInvalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| AdminError::CursorInvalid)?;
        let key = String::from_utf8(bytes).map_err(|_| AdminError::CursorInvalid)?;
        if key.is_empty() {
            return Err(AdminError::CursorInvalid);
        }
        Ok(Self(key))
    }
}

/// What a caller asked for: where to resume, and how many rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    /// Where to resume, or the start of the listing.
    pub after: Option<Cursor>,
    /// How many rows, already clamped to [`MAX_LIMIT`].
    pub limit: usize,
}

impl PageRequest {
    /// Reads the two query parameters.
    ///
    /// A `limit` that does not parse is refused rather than defaulted: a
    /// console sending `limit=fifty` has a bug, and quietly serving fifty rows
    /// hides it.
    ///
    /// # Errors
    ///
    /// [`AdminError::CursorInvalid`] for a cursor this server did not issue,
    /// and [`AdminError::Invalid`] for a `limit` that is not a positive
    /// integer.
    pub fn parse(cursor: Option<&str>, limit: Option<&str>) -> Result<Self, AdminError> {
        let after = cursor.map(Cursor::decode).transpose()?;
        let limit = match limit {
            None => DEFAULT_LIMIT,
            Some(raw) => raw
                .parse::<usize>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    AdminError::Invalid("limit must be a positive integer".to_owned())
                })?,
        };
        Ok(Self {
            after,
            // Clamped rather than refused: asking for more than the server
            // will give is not a bug in the caller, and 200 rows plus a cursor
            // is a complete answer.
            limit: limit.min(MAX_LIMIT),
        })
    }
}

/// One page of results, as it appears on the wire.
///
/// `next_cursor` is `null` on the last page. Absent-versus-null matters to a
/// console writing `while (cursor)`, so it is always present.
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    /// The rows.
    pub items: Vec<T>,
    /// Where to resume, or `null` when there is nothing after this.
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Builds a page from `limit + 1` rows fetched to answer "is there more?".
    ///
    /// Over-fetching by one is how a listing knows whether to mint a cursor
    /// without a second `COUNT` query — and without the bug of minting one on
    /// a full last page, which sends the console round again for nothing.
    ///
    /// `key` names the cursor column of a row.
    pub fn from_overfetched(mut rows: Vec<T>, limit: usize, key: impl Fn(&T) -> String) -> Self {
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = has_more
            .then(|| rows.last().map(|row| Cursor::after(&key(row)).encode()))
            .flatten();
        Self {
            items: rows,
            next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_through_its_wire_form() {
        // Arrange
        let minted = Cursor::after("acme");

        // Act
        let read_back = Cursor::decode(&minted.encode()).expect("its own cursor");

        // Assert
        assert_eq!(read_back.key(), "acme");
    }

    /// The opacity that buys the freedom to change the key: the wire form is
    /// not the key.
    #[test]
    fn the_wire_form_does_not_show_the_key() {
        assert!(!Cursor::after("acme").encode().contains("acme"));
    }

    /// A cursor minted under another version of the scheme is refused rather
    /// than read as a key of this one.
    #[test]
    fn a_cursor_from_another_scheme_version_is_refused() {
        // Arrange
        let foreign = format!("v2.{}", URL_SAFE_NO_PAD.encode(b"acme"));

        // Act / Assert
        assert!(matches!(
            Cursor::decode(&foreign),
            Err(AdminError::CursorInvalid)
        ));
    }

    #[test]
    fn a_cursor_that_is_not_base64_is_refused() {
        assert!(matches!(
            Cursor::decode("v1.not base64!"),
            Err(AdminError::CursorInvalid)
        ));
    }

    #[test]
    fn a_cursor_with_no_version_is_refused() {
        assert!(matches!(
            Cursor::decode("YWNtZQ"),
            Err(AdminError::CursorInvalid)
        ));
    }

    #[test]
    fn an_empty_key_is_refused() {
        assert!(matches!(
            Cursor::decode("v1."),
            Err(AdminError::CursorInvalid)
        ));
    }

    #[test]
    fn a_cursor_carrying_invalid_utf8_is_refused() {
        // Arrange
        let bad = format!("v1.{}", URL_SAFE_NO_PAD.encode([0xff, 0xfe]));

        // Act / Assert
        assert!(matches!(
            Cursor::decode(&bad),
            Err(AdminError::CursorInvalid)
        ));
    }

    #[test]
    fn an_absurdly_long_cursor_is_refused_before_it_is_decoded() {
        // Arrange
        let long = format!("v1.{}", "A".repeat(MAX_KEY_LEN * 4));

        // Act / Assert
        assert!(matches!(
            Cursor::decode(&long),
            Err(AdminError::CursorInvalid)
        ));
    }

    #[test]
    fn no_parameters_means_the_first_page_at_the_default_size() {
        // Act
        let request = PageRequest::parse(None, None).expect("no parameters");

        // Assert
        assert_eq!(request.after, None);
        assert_eq!(request.limit, DEFAULT_LIMIT);
    }

    /// The cap is what stops `limit=100000` from being a request to
    /// materialise a table.
    #[test]
    fn a_limit_above_the_cap_is_clamped_to_it() {
        // Act
        let request = PageRequest::parse(None, Some("100000")).expect("a numeric limit");

        // Assert
        assert_eq!(request.limit, MAX_LIMIT);
    }

    #[test]
    fn a_limit_that_is_not_a_positive_integer_is_refused() {
        for bad in ["fifty", "0", "-1", ""] {
            assert!(
                matches!(
                    PageRequest::parse(None, Some(bad)),
                    Err(AdminError::Invalid(_))
                ),
                "accepted {bad}"
            );
        }
    }

    /// The over-fetch: `limit + 1` rows means there is another page.
    #[test]
    fn a_full_page_with_one_row_over_mints_a_cursor() {
        // Arrange
        let rows = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];

        // Act
        let page = Page::from_overfetched(rows, 2, Clone::clone);

        // Assert
        assert_eq!(page.items, ["a", "b"]);
        assert_eq!(page.next_cursor, Some(Cursor::after("b").encode()));
    }

    /// The bug over-fetching exists to avoid: a full last page must not mint a
    /// cursor, or the console pages once more for nothing.
    #[test]
    fn an_exactly_full_last_page_mints_no_cursor() {
        // Arrange
        let rows = vec!["a".to_owned(), "b".to_owned()];

        // Act
        let page = Page::from_overfetched(rows, 2, Clone::clone);

        // Assert
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn an_empty_listing_mints_no_cursor() {
        // Act
        let page = Page::from_overfetched(Vec::<String>::new(), 10, Clone::clone);

        // Assert
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);
    }
}
