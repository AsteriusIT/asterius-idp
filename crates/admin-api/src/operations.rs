//! The route registry: one declaration per operation, and the types that make
//! a wrong declaration unwritable.
//!
//! Everything downstream reads this one list — the axum router
//! ([`crate::router`]), the `OpenAPI` document ([`crate::openapi`]) and the
//! table-driven authorization test. A route that is not here is not mounted,
//! and a route that is here carries its required authority in a field that has
//! no default and no `Option`.
//!
//! # The refusal of `GET` on a mutation is structural
//!
//! ADR-0009 requires that a state-changing route *cannot be mounted on `GET`*,
//! not that reviewers remember not to. `SameSite=Lax` does not protect a
//! top-level `GET`, so a mutating `GET` is a CSRF hole that the synchroniser
//! token cannot close — a top-level navigation carries the cookie and carries
//! no header at all.
//!
//! So there is no `Method` enum with five variants and a comment. There are
//! two disjoint enums, [`Safe`] and [`Mutating`], neither of which can express
//! the other's verbs, and two constructors:
//!
//! * [`Operation::read`] takes a [`Safe`] and produces [`Effect::Reads`].
//! * [`Operation::mutation`] takes a [`Mutating`] and produces
//!   [`Effect::Mutates`].
//!
//! `Mutating` has no `Get` variant to pass, so "mount this mutation on GET" is
//! not a mistake to be caught in review — it is a program that does not
//! compile. `ast-t9k` is the reason the distinction between "type-enforced"
//! and "enforced by one caller staying private" is spelt out here: the two
//! constructors are the *only* way to build an [`Operation`], because its
//! fields are private and it has no other public constructor.
//!
//! The belt-and-braces test `every_mutation_refuses_get` still exists. It
//! costs four lines and it is what fails first if somebody ever widens `Safe`.

use crate::rbac::Authority;

/// A verb with no side effects.
///
/// One variant today. It is an enum rather than a unit so that `HEAD` can join
/// it without changing a signature — and so that the *type* is what carries
/// "this verb is safe", which is the property [`Operation::read`] relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Safe {
    /// `GET`.
    Get,
}

/// A verb that changes state.
///
/// **`Get` is deliberately absent and must stay absent.** Adding it here would
/// silently undo ADR-0009's structural guarantee, which is why the doc comment
/// says so at the one place somebody would type it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutating {
    /// `POST`. Creation, and the only verb this API requires an
    /// `Idempotency-Key` on.
    Post,
    /// `PUT`. Whole-document replacement.
    Put,
    /// `PATCH`. Partial change.
    Patch,
    /// `DELETE`.
    Delete,
}

/// Whether an operation changes anything.
///
/// Derived from which constructor was used, never set by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Reads. No CSRF check, no idempotency key, no audit record.
    Reads,
    /// Changes state. Subject to CSRF, and audited with its actor.
    Mutates,
}

/// The HTTP verb an operation is mounted on.
///
/// Produced from [`Safe`] or [`Mutating`]; there is no way to build one
/// directly, so there is no way to pair `Get` with [`Effect::Mutates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// From [`Safe::Get`].
    Get,
    /// From [`Mutating::Post`].
    Post,
    /// From [`Mutating::Put`].
    Put,
    /// From [`Mutating::Patch`].
    Patch,
    /// From [`Mutating::Delete`].
    Delete,
}

impl Method {
    /// The verb as it appears on the wire and in the `OpenAPI` document.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    /// The lowercase spelling `OpenAPI` uses for a path item's key.
    #[must_use]
    pub const fn as_openapi_key(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Put => "put",
            Self::Patch => "patch",
            Self::Delete => "delete",
        }
    }
}

/// One declared route.
///
/// Fields are private so that [`Operation::read`] and [`Operation::mutation`]
/// are the only ways to make one. A public field would let a caller build the
/// combination the two constructors exist to prevent, and the guarantee would
/// again rest on nobody doing so.
#[derive(Debug, Clone, Copy)]
pub struct Operation {
    id: &'static str,
    path: &'static str,
    method: Method,
    effect: Effect,
    authority: Authority,
    summary: &'static str,
    paginated: bool,
}

impl Operation {
    /// Declares a read.
    ///
    /// `authority` has no default: an operation cannot be declared without
    /// saying what it needs, which is the property the table-driven test in
    /// [`crate::router`] depends on being unforgeable.
    #[must_use]
    pub const fn read(
        id: &'static str,
        path: &'static str,
        method: Safe,
        authority: Authority,
        summary: &'static str,
    ) -> Self {
        let method = match method {
            Safe::Get => Method::Get,
        };
        Self {
            id,
            path,
            method,
            effect: Effect::Reads,
            authority,
            summary,
            paginated: false,
        }
    }

    /// Declares a state change.
    ///
    /// There is no `Mutating::Get`, so this cannot mount one on `GET`.
    #[must_use]
    pub const fn mutation(
        id: &'static str,
        path: &'static str,
        method: Mutating,
        authority: Authority,
        summary: &'static str,
    ) -> Self {
        let method = match method {
            Mutating::Post => Method::Post,
            Mutating::Put => Method::Put,
            Mutating::Patch => Method::Patch,
            Mutating::Delete => Method::Delete,
        };
        Self {
            id,
            path,
            method,
            effect: Effect::Mutates,
            authority,
            summary,
            paginated: false,
        }
    }

    /// Marks a read as cursor-paginated, which the `OpenAPI` document turns into
    /// the `cursor` and `limit` parameters and the envelope's `next_cursor`.
    #[must_use]
    pub const fn paginated(mut self) -> Self {
        self.paginated = true;
        self
    }

    /// The stable identifier: the `operationId` in `OpenAPI`, the label in the
    /// rate-limit bucket and in a log line.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// The path, relative to [`crate::BASE_PATH`], in axum's syntax.
    #[must_use]
    pub const fn path(&self) -> &'static str {
        self.path
    }

    /// The verb.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Whether it changes anything.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// What a caller must hold to be allowed through.
    #[must_use]
    pub const fn authority(&self) -> Authority {
        self.authority
    }

    /// One line, for the `OpenAPI` summary.
    #[must_use]
    pub const fn summary(&self) -> &'static str {
        self.summary
    }

    /// Whether the response is a cursor page.
    #[must_use]
    pub const fn is_paginated(&self) -> bool {
        self.paginated
    }

    /// Whether a `POST` body must be made idempotent by a key.
    ///
    /// `POST` only. `PUT` and `DELETE` are idempotent by their own definition
    /// (RFC 9110 §9.2.2), and demanding a key for them would be ceremony
    /// without a property behind it.
    #[must_use]
    pub const fn needs_idempotency_key(&self) -> bool {
        matches!(self.method, Method::Post)
    }

    /// The full path a client calls, including the API's base.
    #[must_use]
    pub fn full_path(&self) -> String {
        format!("{}{}", crate::BASE_PATH, self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::{Authority, Reach};

    fn a_read() -> Operation {
        Operation::read(
            "thing.get",
            "/things",
            Safe::Get,
            Authority::new(Reach::Tenant, "admin.things:read"),
            "Reads a thing",
        )
    }

    fn a_mutation() -> Operation {
        Operation::mutation(
            "thing.create",
            "/things",
            Mutating::Post,
            Authority::new(Reach::Tenant, "admin.things:write"),
            "Creates a thing",
        )
    }

    /// The guarantee ADR-0009 asks to be structural. The compiler enforces it
    /// — `Mutating` has no `Get` — and this is the test that fails if somebody
    /// widens the enum.
    #[test]
    fn every_mutation_refuses_get() {
        for operation in crate::registry() {
            if operation.effect() == Effect::Mutates {
                assert_ne!(
                    operation.method(),
                    Method::Get,
                    "{} is a mutation mounted on GET",
                    operation.id()
                );
            }
        }
    }

    /// The other direction, which is the one a careless refactor breaks: a
    /// `GET` that quietly acquired a side effect.
    #[test]
    fn every_get_is_declared_as_a_read() {
        for operation in crate::registry() {
            if operation.method() == Method::Get {
                assert_eq!(
                    operation.effect(),
                    Effect::Reads,
                    "{} is a GET that changes state",
                    operation.id()
                );
            }
        }
    }

    #[test]
    fn a_read_is_never_a_mutation() {
        assert_eq!(a_read().effect(), Effect::Reads);
        assert_eq!(a_read().method(), Method::Get);
    }

    #[test]
    fn a_mutation_is_never_safe() {
        assert_eq!(a_mutation().effect(), Effect::Mutates);
        assert_ne!(a_mutation().method(), Method::Get);
    }

    /// RFC 9110 §9.2.2: `PUT` and `DELETE` are already idempotent, so only
    /// `POST` is asked for a key.
    #[test]
    fn only_post_asks_for_an_idempotency_key() {
        assert!(a_mutation().needs_idempotency_key());
        assert!(!a_read().needs_idempotency_key());

        let removal = Operation::mutation(
            "thing.delete",
            "/things/{id}",
            Mutating::Delete,
            Authority::new(Reach::Tenant, "admin.things:write"),
            "Removes a thing",
        );
        assert!(!removal.needs_idempotency_key());
    }

    #[test]
    fn a_full_path_is_the_base_plus_the_route() {
        assert_eq!(a_read().full_path(), "/admin/api/v1/things");
    }
}
