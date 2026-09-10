//! The pages a user sees, and the rule that they escape everything.
//!
//! Every page is an askama template with autoescaping on, rendered through
//! [`crate::Document`] so that the CSP nonce reaches the markup and the header
//! from the same value.
//!
//! # What is untrusted here
//!
//! Nearly all of it. A `client_name` comes from a registration document, a
//! `login_hint` and a `state` come from an authorization request, a scope
//! description may come from tenant configuration. None of it is this server's
//! text, and all of it lands in HTML.
//!
//! askama escapes by default for `.html` templates, so the defence is the
//! absence of `|safe` rather than the presence of a call. There is exactly one
//! `|safe` in the tree — the CSP nonce attribute, which this crate generates
//! and which is base64url by construction — and `crate::source_audit` fails the
//! build if a second appears.
//!
//! # No JavaScript
//!
//! Not a preference. Every page must work with scripting disabled
//! (`ast-2vk.1`), and a tree with almost no `<script>` in it is the version of
//! `script-src 'nonce-…' 'strict-dynamic'` that is hardest to get wrong. The
//! source audit asserts the absence.
//!
//! There are exactly three exceptions, each named rather than
//! pattern-matched.
//!
//! [`PasskeyPage`] (`ast-ndk.7`) and [`LoginPage`] (`ast-2vk.4`):
//! `navigator.credentials.create()` and `navigator.credentials.get()` are
//! JavaScript APIs, so a WebAuthn ceremony cannot be run from markup at all.
//! Both scripts are inline, carry the per-response nonce, and interpolate
//! nothing — every value reaches them through escaped `data-` attributes — and
//! on both the button starts `hidden` and is revealed by the script that can
//! use it. What remains without script differs: the enrolment page offers a
//! link to the password path, and the sign-in page *is* the password path,
//! form and all.
//!
//! [`FormPostPage`] (`ast-gxh.5`): no markup submits a form on its own, and
//! `<noscript>` renders rather than acts, so the auto-submission a `form_post`
//! response mode is expected to perform needs one line of script. The page it
//! runs on is a working page without it — a form with a real submit button
//! that the user presses — which is why the two halves of that acceptance
//! criterion are not in conflict.
//!
//! Everything added since — the device flow's three pages, registration, email
//! verification and the two password-reset pages (`ast-ndk.2`) — is unscripted,
//! including its focus management: `autofocus` on the shared error summary is
//! HTML doing what a page would otherwise need a script for.
//!
//! # A fixed set of pages, and tenants change tokens and strings
//!
//! The product rule this bead exists to hold is that a tenant supplies no
//! markup. There is no field on any type here that carries HTML, no template
//! renders one unescaped, and `crate::source_audit` fails the build if either
//! stops being true. What a tenant does get is the design tokens of
//! `style.css` (`ast-ndk.1`) and, once `ast-ndk.5` lands, the strings — which
//! is why [`LoginPage::locale`] already exists on every page and
//! does nothing but write the `lang` attribute.
//!
//! Every page is pinned as bytes in both locales; see `crate::snapshots`.

use crate::csp::Nonce;
use askama::Template;

/// A scope, as shown on the consent screen.
///
/// The description is separate from the name because a user consents to a
/// meaning, not to an identifier: "read your payment history" is a decision,
/// `payments:read` is a token. Both are rendered — the name so that a
/// technical user can check what was actually asked for.
#[derive(Debug, Clone)]
pub struct ScopeLine {
    /// The scope token, as it appeared in the request.
    pub name: String,
    /// What it means, in the user's language.
    ///
    /// `None` renders the bare token. That is deliberately ugly: an
    /// unexplained scope should look unexplained rather than familiar.
    pub description: Option<String>,
    /// Whether the user may untick it and still proceed.
    pub required: bool,
}

/// One `authorization_details` element, as shown on the consent screen
/// (RFC 9396 §2).
///
/// # Why there is no JSON here
///
/// An `authorization_details` element is a JSON object a client composed, and a
/// consent page that rendered it would be showing a person attacker-composed
/// text and asking them to agree to it. RFC 9396 §12 requires the user to be
/// able to understand what they are approving; a JSON blob is a prompt nobody
/// reads.
///
/// So the page shows the operator's own sentence for the type — from the
/// tenant's registry, escaped like everything else — and the §2.2 common fields
/// that have an agreed meaning: `locations`, `actions`, `datatypes`. The
/// element itself is authorised and stored; it is not displayed.
#[derive(Debug, Clone)]
pub struct DetailLine {
    /// The `type`, shown so a technical user can check what was asked for.
    pub name: String,
    /// The operator's sentence for this type.
    ///
    /// `None` renders a plain statement that the type is undescribed. That is
    /// deliberately ugly, like an undescribed scope: an unexplained
    /// authorization should look unexplained.
    pub description: Option<String>,
    /// RFC 9396 §2.2 `locations`: the resource servers this element is for.
    pub locations: Vec<String>,
    /// RFC 9396 §2.2 `actions`: the operations it authorises.
    pub actions: Vec<String>,
    /// RFC 9396 §2.2 `datatypes`: the kinds of data it reaches.
    pub datatypes: Vec<String>,
}

/// The sign-in page.
///
/// # The scripted half is an enhancement, and the form is the mechanism
///
/// The password form is the page. It carries a synchroniser token, it posts to
/// the interaction, and nothing about it depends on script — which is why the
/// no-JS path this bead's parent asks for is not a fallback anybody has to
/// maintain: it is the ordinary path.
///
/// On top of it sit two things a browser API is the only way to reach.
/// [`Self::passkey_options_action`] and [`Self::passkey_finish_action`] are
/// where the script runs a `navigator.credentials.get()` ceremony, behind a
/// button that starts `hidden` and is revealed by the script that can use it —
/// `passkey.html`'s pattern, because as there the button *is* the script.
/// Conditional mediation is the second: the username field asks for it with an
/// `autocomplete` token, and a browser that has never heard of it ignores the
/// token.
#[derive(Debug, Template)]
#[template(path = "login.html")]
pub struct LoginPage<'a> {
    /// BCP 47 tag for the `lang` attribute.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Where the form posts to, and where a passkey sign-in navigates on
    /// success — it is the same interaction, at whatever stage it has reached.
    pub action: &'a str,
    /// Where the script asks for `PublicKeyCredentialRequestOptions`.
    pub passkey_options_action: &'a str,
    /// Where the script posts the assertion it got back.
    pub passkey_finish_action: &'a str,
    /// The synchroniser token for this rendering.
    ///
    /// One token, carried by the form as a hidden input and by the script as a
    /// `data-` attribute: they are two ways to submit the same interaction and
    /// there is no reason for them to hold different tokens.
    pub csrf: &'a str,
    /// `login_hint` from the request, prefilled into the username field.
    ///
    /// Attacker-influenced: a client chooses it. It is escaped like everything
    /// else, and it is only ever a *prefill* — it does not identify the user
    /// and does not survive into the session.
    pub login_hint: Option<&'a str>,
    /// A previous failure, if this is a retry.
    ///
    /// Fixed strings chosen by this server, never a reason echoed from input.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute, rendered raw. See the module docs.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and by construction unchanged by escaping; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The consent screen.
#[derive(Debug, Template)]
#[template(path = "consent.html")]
pub struct ConsentPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// The client's registered name. Attacker-chosen at registration time.
    pub client_name: &'a str,
    /// Who is signed in, so a user on a shared machine can see it is them.
    pub username: &'a str,
    /// The host the user will be returned to. See the template.
    pub redirect_host: &'a str,
    /// What is being asked for.
    pub scopes: Vec<ScopeLine>,
    /// Whether a refresh token was asked for.
    pub offline_access: bool,
    /// RFC 8707 resource indicators named by the request.
    pub resources: Vec<String>,
    /// RFC 9396 `authorization_details`, one line per element.
    pub authorization_details: Vec<DetailLine>,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The logout confirmation question.
///
/// OIDC RP-Initiated Logout 1.0 §2: the OP asks the End-User whether to log
/// out when it cannot verify the request. The page therefore carries **no**
/// relying-party name, logo or URL — see the template for why that is a
/// security property rather than a missing feature — and it is rendered
/// before anything about the session has changed.
#[derive(Debug, Template)]
#[template(path = "logout_confirm.html")]
pub struct LogoutConfirmationPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name. The only name on the page.
    pub tenant_name: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The neutral end of a logout.
///
/// Shown when there is no post-logout redirect to perform (§3), and when the
/// user chose to stay signed in. It names the provider and nothing else.
#[derive(Debug, Template)]
#[template(path = "logged_out.html")]
pub struct LoggedOutPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Whether the session was actually ended.
    pub signed_out: bool,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The passkey enrolment page: the one page in this tree that runs script.
///
/// A WebAuthn registration ceremony is a call to
/// `navigator.credentials.create()`, which no amount of markup can make. So
/// this page carries one inline bootstrap under the per-response nonce, and
/// `source_audit` names it as an exemption rather than relaxing the rule for
/// everyone.
///
/// Nothing here is interpolated *into* the script. The endpoints, the token and
/// the destination arrive on `data-` attributes, which askama escapes like any
/// other attribute value, so the script's source text is a constant that a
/// reviewer can read once.
///
/// # Without JavaScript
///
/// The button is `hidden` in the markup and revealed by the script, so a
/// browser with scripting off — or one where the script was blocked, which
/// `<noscript>` does not cover — shows no button at all. The link to
/// [`Self::password_href`] is unconditional, and the `<noscript>` block says
/// why the button is missing.
#[derive(Debug, Template)]
#[template(path = "passkey.html")]
pub struct PasskeyPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Who is enrolling, so a user on a shared machine can see it is them.
    pub username: &'a str,
    /// Where the script asks for creation options.
    pub options_action: &'a str,
    /// Where the script posts the attestation it got back.
    pub finish_action: &'a str,
    /// Where the browser goes once a passkey has been stored.
    pub next_href: &'a str,
    /// The path that works with no script at all: carry on with a password.
    pub password_href: &'a str,
    /// The synchroniser token, sent in the body of both fetches.
    pub csrf: &'a str,
    /// A previous failure, if this is a retry. A fixed string, never echoed.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute — here it is the script's, not only the style's.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// One response parameter, as a hidden input on the `form_post` page.
///
/// A pair rather than a struct with three named fields, because the page is
/// whatever `AuthorizationResponse::query` produced and this type should not
/// be a second opinion about which parameters exist. Both halves are escaped
/// by the template: `state` is a string the client chose, echoed back byte for
/// byte, and it lands in an attribute value.
#[derive(Debug, Clone)]
pub struct ResponseField {
    /// The parameter name — `code`, `state`, `iss` or `error`.
    pub name: String,
    /// Its value.
    pub value: String,
}

/// The `response_mode=form_post` page (`ast-gxh.5`).
///
/// OAuth 2.0 Form Post Response Mode §2: the authorization response is
/// delivered by a form this server renders and the browser POSTs to the
/// client's `redirect_uri`, instead of by a redirect that carries it in a URL.
///
/// # The second scripted page in this tree, and why it is scripted
///
/// A form cannot submit itself. There is no HTML attribute for it and
/// `<noscript>` can only render markup, never act — so "auto-submit" and
/// "works without JavaScript" are only contradictory if the button is the
/// script's creation. Here it is not: the page is a form with a real, visible,
/// always-enabled submit button, and the inline script — under the
/// per-response nonce, interpolating nothing — presses it for the
/// overwhelmingly common case where script runs.
///
/// That is deliberately the mirror image of [`PasskeyPage`], whose button
/// starts `hidden` and is revealed by its script. The rule underneath both is
/// the same: what a browser without script shows must be something that works.
/// There, a WebAuthn button without script cannot; here, the button is the
/// whole mechanism.
///
/// # The policy this page needs
///
/// It is the only page in this server that submits anywhere but back to this
/// server, so it is served with `form-action 'self' <the client's origin>` —
/// [`crate::Document::with_form_post_to`], one origin, taken from the
/// `redirect_uri` this authorization was validated against at push time and
/// never from a parameter of the request that renders it.
#[derive(Debug, Template)]
#[template(path = "form_post.html")]
pub struct FormPostPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// The host the answer is being sent to, so the page says where the
    /// browser is about to go. Registered by the client and validated at push
    /// time, like the one the consent screen shows.
    pub redirect_host: &'a str,
    /// The form's `action`: the client's `redirect_uri`.
    pub action: &'a str,
    /// The response parameters, each rendered as a hidden input.
    pub fields: Vec<ResponseField>,
    /// The CSP nonce attribute — here it is the auto-submit script's.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The code-entry page of the device authorization grant.
///
/// RFC 8628 §3.3: the device shows a `user_code` and a `verification_uri`, and
/// the user types the one at the other on a browser this server can actually
/// talk to. Everything the flow needs from a person happens on this page and
/// the two after it.
///
/// [`Self::user_code`] is `Some` when the user arrived by
/// `verification_uri_complete` (§3.3.1) and the code was in the URI. It is a
/// prefill and nothing more: the field stays editable, because a URI that
/// arrived by mail may have been wrapped or truncated, and it is still
/// compared server-side.
#[derive(Debug, Template)]
#[template(path = "device.html")]
pub struct DevicePage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The code from `verification_uri_complete`, if there was one.
    ///
    /// Attacker-influenced — anybody can construct that URI — so it is
    /// escaped like every other value and never trusted as a *decision*, only
    /// rendered as a prefill.
    pub user_code: Option<&'a str>,
    /// A previous failure, if this is a retry.
    ///
    /// One fixed string for every reason a code can fail (§5.1): "unknown",
    /// "expired" and "already used" would each be an oracle for somebody
    /// working through a short code space.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The "is this the code your device is showing?" page.
///
/// RFC 8628 §3.3.1 asks the authorization server to display the `user_code`
/// and have the user confirm it, and §5.4 says why: a complete verification
/// URI is a link, and a link is something an attacker can send. Confirming the
/// code turns the click into a comparison against a device that has to be in
/// front of the person doing it.
#[derive(Debug, Template)]
#[template(path = "device_confirm.html")]
pub struct DeviceConfirmationPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// The client's registered name. Attacker-chosen at registration time,
    /// like the one on the consent screen.
    pub client_name: &'a str,
    /// The code this server matched, shown for the user to compare.
    pub user_code: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// A previous failure, if this is a retry.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The end of the device flow, in the browser.
///
/// The device itself learns the outcome by polling the token endpoint (RFC
/// 8628 §3.4), so this page exists only to tell the person holding the browser
/// that they are done. It offers no way back into the flow.
#[derive(Debug, Template)]
#[template(path = "device_done.html")]
pub struct DeviceOutcomePage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Whether the device was authorized.
    ///
    /// The unsuccessful rendering names no client and no reason: it is reached
    /// after a cancellation, an expiry, or a code that was never issued, and
    /// distinguishing them would answer a question a guesser is asking.
    pub connected: bool,
    /// The client's registered name, shown only when the device was connected.
    pub client_name: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The account creation page.
///
/// No script: a passkey cannot be enrolled from markup, and enrolment happens
/// on [`PasskeyPage`] once the account exists, which is where that ceremony
/// and its `source_audit` exemption already live.
#[derive(Debug, Template)]
#[template(path = "register.html")]
pub struct RegistrationPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// What the user typed last time, so a rejected submission does not make
    /// them type it all again. Their own text, escaped like anyone else's.
    pub username: Option<&'a str>,
    /// Likewise for the address.
    pub email: Option<&'a str>,
    /// The minimum this tenant accepts, stated in the markup and enforced
    /// again server-side — an attribute is a courtesy to the browser, never a
    /// control.
    pub minimum_password_length: usize,
    /// Where a user who already has an account goes instead.
    pub sign_in_href: &'a str,
    /// A previous failure, if this is a retry.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The email confirmation page, in both of its states.
///
/// Waiting for the link to be followed, and the link having been followed. One
/// template because they are one thing to a user, and because the address is
/// shown on both: a typo in it is the likeliest reason nothing arrives, and a
/// user who cannot see what was recorded cannot spot it.
#[derive(Debug, Template)]
#[template(path = "verify_email.html")]
pub struct EmailVerificationPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// The address a link was sent to. The user's own text, escaped.
    pub email: &'a str,
    /// Whether the link has been followed.
    pub verified: bool,
    /// Where the "send it again" form posts to. A POST because it sends mail,
    /// and a GET that sends mail is a GET any image tag can fire.
    pub resend_action: &'a str,
    /// Where a confirmed user goes next.
    pub continue_href: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// A previous failure — an expired link, a resend that was throttled.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The "email me a reset link" form.
///
/// The page that answers it is [`PasswordResetSentPage`], and it is the same
/// page whether or not the address matched anything.
#[derive(Debug, Template)]
#[template(path = "password_reset.html")]
pub struct PasswordResetRequestPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// Back to the sign-in page.
    pub sign_in_href: &'a str,
    /// A previous failure — a malformed address, a throttled request. Never
    /// "no such account": see [`PasswordResetSentPage`].
    pub message: Option<&'a str>,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The neutral answer to a reset request.
///
/// It carries no field that could differ between an address this server knows
/// and one it does not — not the address, not a name, not a count. An account
/// discovery oracle on a reset form is the textbook one (RFC 9700 §4), and it
/// does not need a message to leak: a different page would do. The absence is
/// structural rather than conditional, and a test renders it for both cases and
/// compares the bytes.
#[derive(Debug, Template)]
#[template(path = "password_reset_sent.html")]
pub struct PasswordResetSentPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Back to the sign-in page.
    pub sign_in_href: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The page a reset link leads to.
///
/// The reset token is a hidden field rather than a path segment of
/// [`Self::action`]: an action is what lands in browser history and in a
/// `Referer` the day this page gains an outbound link. It is not the
/// synchroniser token and does not replace it — one says which account, the
/// other says this submission came from this page.
#[derive(Debug, Template)]
#[template(path = "password_new.html")]
pub struct NewPasswordPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Whose password is being changed, shown so a user with two accounts —
    /// or an old link — can see which. Display only: no field here chooses an
    /// account.
    pub username: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The single-use reset token from the link.
    pub reset_token: &'a str,
    /// The minimum this tenant accepts, checked again server-side.
    pub minimum_password_length: usize,
    /// A previous failure — the two entries not matching, a password too
    /// short, a token that has expired.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// The error page.
///
/// One page for every failure a browser can reach. The message is one of a
/// fixed set and the correlation id points at a log line — see
/// [`crate::interaction::correlation_id`].
#[derive(Debug, Template)]
#[template(path = "error.html")]
pub struct ErrorPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// A generic description of what went wrong.
    pub message: &'a str,
    /// What to quote to support.
    pub correlation_id: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
    /// The tenant's design tokens, as the CSS custom properties
    /// `crate::theme::custom_properties` renders. Escaped like any other
    /// value, and unchanged by escaping by construction; empty for a tenant
    /// that has set no theme.
    pub theme_css: &'a str,
}

/// Renders a page, or an empty document if it somehow cannot.
///
/// A template that fails to render is a bug, not a runtime condition: every
/// value in these types is already a `String`, so there is nothing left to
/// fail on. Returning an empty body beats panicking on a request path, and the
/// caller's status still reaches the browser.
///
/// It lives here rather than in the server so that askama stays an
/// implementation detail of this crate — a handler should not have to name the
/// templating engine to render a page.
pub fn render<T: Template>(page: &T) -> String {
    page.render().unwrap_or_else(|error| {
        tracing::error!(%error, "a template failed to render");
        String::new()
    })
}

/// Builds the `nonce="…"` attribute for a template.
///
/// A free function rather than a method so that the one `|safe` in the
/// templates has an obvious, greppable source.
#[must_use]
pub fn nonce_attribute(nonce: &Nonce) -> String {
    nonce.attribute()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csp::Nonce;

    /// Values a client or a request can choose, each of which breaks out of
    /// HTML if it is not escaped.
    const HOSTILE: &[&str] = &[
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "' onerror='alert(1)",
        "\" onmouseover=\"alert(1)",
        "</title><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "&lt;script&gt;",
        "</textarea><svg onload=alert(1)>",
        "\u{0}<script>",
    ];

    /// A fixed nonce for template tests.
    ///
    /// Not `Nonce::generate()`: `source_audit` requires that a nonce is drawn
    /// only by the document middleware, and that rule is worth more than the
    /// convenience of calling it here. The fixture lives in `csp`, which the
    /// audit exempts as the module that defines the type.
    fn nonce() -> Nonce {
        Nonce::fixed_for_test("test-nonce-value")
    }

    /// Nothing hostile survives into the markup as markup.
    ///
    /// The assertion is deliberately blunt: after rendering, the page must not
    /// contain `<script`, an `onerror=` or an `onmouseover=` that the fixture
    /// put there. askama escapes by default, so this is really a test that no
    /// template gained a `|safe` on a request value.
    #[test]
    fn every_untrusted_value_on_the_login_page_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let page = LoginPage {
                locale: "en",
                tenant_name: hostile,
                action: "/interaction/x/login",
                passkey_options_action: hostile,
                passkey_finish_action: hostile,
                csrf: hostile,
                login_hint: Some(hostile),
                message: Some(hostile),
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            };
            let html = page.render().expect("render");
            // One script: the sign-in bootstrap the template carries. None of
            // the hostile values may have produced a second.
            assert_no_injection_beyond(&html, hostile, 1);
        }
    }

    #[test]
    fn every_untrusted_value_on_the_consent_page_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let page = ConsentPage {
                locale: "en",
                tenant_name: hostile,
                client_name: hostile,
                username: hostile,
                redirect_host: hostile,
                scopes: vec![ScopeLine {
                    name: (*hostile).to_owned(),
                    description: Some((*hostile).to_owned()),
                    required: false,
                }],
                offline_access: true,
                resources: vec![(*hostile).to_owned()],
                // RFC 9396 §2.2's fields are copied from a document the client
                // composed, so every one of them is hostile input on the one
                // page where a person is being asked to agree to something.
                authorization_details: vec![DetailLine {
                    name: (*hostile).to_owned(),
                    description: Some((*hostile).to_owned()),
                    locations: vec![(*hostile).to_owned()],
                    actions: vec![(*hostile).to_owned()],
                    datatypes: vec![(*hostile).to_owned()],
                }],
                action: "/interaction/x/consent",
                csrf: hostile,
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            };
            let html = page.render().expect("render");
            assert_no_injection(&html, hostile);
        }
    }

    #[test]
    fn every_untrusted_value_on_the_error_page_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let page = ErrorPage {
                locale: "en",
                tenant_name: hostile,
                message: hostile,
                correlation_id: hostile,
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            };
            let html = page.render().expect("render");
            assert_no_injection(&html, hostile);
        }
    }

    /// A passkey page with the values a caller would pass.
    fn passkey<'a>(username: &'a str, message: Option<&'a str>) -> PasskeyPage<'a> {
        PasskeyPage {
            locale: "en",
            tenant_name: "Demo",
            username,
            options_action: "/passkeys/options",
            finish_action: "/passkeys/finish",
            next_href: "/account",
            password_href: "/interaction/x/login",
            csrf: "the-token",
            message,
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        }
    }

    /// The scripted page escapes like every other one.
    ///
    /// It matters more here than anywhere: this is the page whose exemption
    /// lets `strict-dynamic` trust an inline block, so an injected second
    /// script would inherit that trust.
    #[test]
    fn every_untrusted_value_on_the_passkey_page_is_escaped() {
        for hostile in HOSTILE {
            let html = passkey(hostile, Some(hostile)).render().expect("render");
            assert_no_injection_beyond(&html, hostile, 1);
        }
    }

    /// One inline block, carrying the nonce the header names.
    ///
    /// A script without the nonce is a page that silently does nothing, and a
    /// second script is one nobody reviewed.
    #[test]
    fn the_passkey_page_carries_exactly_one_nonce_carrying_script() {
        let nonce = nonce();
        let html = PasskeyPage {
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
            ..passkey("ada", None)
        }
        .render()
        .expect("render");

        assert_eq!(html.matches("<script").count(), 1, "{html}");
        assert!(
            html.contains(&format!("<script nonce=\"{}\">", nonce.as_str())),
            "the script did not get the nonce the header will name: {html}"
        );
        assert!(
            !html.contains("<script src"),
            "the bootstrap must be inline, not fetched: {html}"
        );
    }

    /// The ceremony's inputs travel as escaped attributes, never as source.
    ///
    /// This is what makes one `<script>` reviewable: its text is a constant.
    /// A value interpolated into it would be a cross-site scripting bug that
    /// no amount of HTML escaping fixes, because inside a script element the
    /// dangerous characters are different ones.
    #[test]
    fn the_passkey_script_interpolates_nothing() {
        let html = passkey("ada", None).render().expect("render");
        let start = html.find("<script").expect("a script");
        let body = &html[start..];

        for value in [
            "/passkeys/options",
            "/passkeys/finish",
            "/account",
            "the-token",
            "ada",
        ] {
            assert!(
                !body.contains(value),
                "{value:?} was interpolated into the script: {body}"
            );
        }
        // ...and they did reach the page, on the attributes the script reads.
        assert!(
            html.contains(r#"data-options-url="/passkeys/options""#),
            "{html}"
        );
        assert!(html.contains(r#"data-csrf="the-token""#), "{html}");
    }

    /// `ast-kb0`: a 204 is a success, and the script has to say so.
    ///
    /// `/passkeys/finish` answers `204 No Content`, and `Response.json()` on an
    /// empty body rejects — so a script that parsed every answer reported a
    /// registration that had *worked* as having failed, and never navigated.
    /// Nothing in Rust could see it: the endpoint was right and the ceremony
    /// was stored. `e2e/tests/passkey-ceremony.spec.ts` found it the first time
    /// a browser ran the ceremony; this is the cheap guard against its return.
    #[test]
    fn the_passkey_script_treats_an_empty_answer_as_success() {
        let html = passkey("ada", None).render().expect("render");

        assert!(
            html.contains("answer.status === 204"),
            "the enrolment script parses the empty body a 204 has: {html}"
        );
    }

    /// The sign-in page's script, like the enrolment page's, is a constant.
    #[test]
    fn the_sign_in_script_interpolates_nothing() {
        let nonce = nonce();
        let html = LoginPage {
            locale: "en",
            tenant_name: "Demo",
            action: "/interaction/abc",
            passkey_options_action: "/interaction/abc/passkey/options",
            passkey_finish_action: "/interaction/abc/passkey/finish",
            csrf: "the-token",
            login_hint: Some("ada"),
            message: None,
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");
        let start = html.find("<script").expect("a script");
        let body = &html[start..];

        for value in [
            "/interaction/abc",
            "/interaction/abc/passkey/options",
            "the-token",
            "ada",
        ] {
            assert!(
                !body.contains(value),
                "{value:?} was interpolated into the script: {body}"
            );
        }
        // ...and they did reach the page, on the attributes the script reads.
        assert!(
            html.contains(r#"data-options-url="/interaction/abc/passkey/options""#),
            "{html}"
        );
        assert!(html.contains(r#"data-csrf="the-token""#), "{html}");
    }

    /// `ast-2vk.4`: the passkey path is the enhancement and the password form
    /// is the mechanism, so with scripting off the page still signs people in.
    #[test]
    fn without_javascript_the_sign_in_page_still_has_its_password_form() {
        let nonce = nonce();
        let html = LoginPage {
            locale: "en",
            tenant_name: "Demo",
            action: "/interaction/abc",
            passkey_options_action: "/interaction/abc/passkey/options",
            passkey_finish_action: "/interaction/abc/passkey/finish",
            csrf: "the-token",
            login_hint: None,
            message: None,
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");

        // The form, untouched by any of this.
        assert!(
            html.contains(r#"<input type="password" name="password""#),
            "{html}"
        );
        assert!(
            html.contains("<button type=\"submit\">Sign in</button>"),
            "{html}"
        );
        // The passkey block starts hidden, so no browser shows a button that
        // cannot work — including one where the script was blocked, which
        // `<noscript>` would not catch.
        assert!(html.contains(r#"id="passkey-signin""#), "{html}");
        let block = html
            .split(r#"id="passkey-signin""#)
            .nth(1)
            .and_then(|rest| rest.split('>').next())
            .expect("the passkey block");
        assert!(
            block.contains("hidden"),
            "the passkey block is not hidden: {html}"
        );
        assert!(html.contains("<noscript>"), "{html}");
    }

    /// Conditional mediation is asked for in the one place a browser reads it.
    ///
    /// The `webauthn` token in `autocomplete` is what lets a browser offer a
    /// passkey inside its ordinary username dropdown; a browser that has never
    /// heard of it ignores the token and the field is an ordinary username
    /// field, which is exactly the "enhancement, not mechanism" claim.
    #[test]
    fn the_username_field_asks_for_conditional_mediation() {
        let nonce = nonce();
        let html = LoginPage {
            locale: "en",
            tenant_name: "Demo",
            action: "/interaction/abc",
            passkey_options_action: "/interaction/abc/passkey/options",
            passkey_finish_action: "/interaction/abc/passkey/finish",
            csrf: "t",
            login_hint: None,
            message: None,
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");

        assert!(
            html.contains(r#"autocomplete="username webauthn""#),
            "{html}"
        );
    }

    /// The acceptance criterion of `ast-ndk.7`: no dead button, and a reason.
    ///
    /// The button is `hidden` in the markup and revealed by the script, so a
    /// browser that never runs the script never shows a control that cannot
    /// work — including one where scripting is on but the script was blocked,
    /// which `<noscript>` does not cover. That is why the password link is
    /// outside the `<noscript>` and the explanation is inside it.
    #[test]
    fn without_javascript_the_passkey_page_explains_and_offers_the_password_path() {
        let html = passkey("ada", None).render().expect("render");

        assert!(
            html.contains(r#"<button type="button" id="passkey-register" hidden>"#),
            "the button must start hidden, or a no-script browser sees a dead control: {html}"
        );

        let noscript = html
            .split_once("<noscript>")
            .and_then(|(_, rest)| rest.split_once("</noscript>"))
            .map(|(inside, _)| inside.to_owned())
            .expect("a noscript block");
        assert!(
            noscript.contains("JavaScript"),
            "the fallback must say why the button is missing: {noscript}"
        );

        // The way out is in the markup unconditionally, not only inside the
        // `<noscript>`: a blocked script leaves the page with neither.
        let outside = html.replace(&noscript, "");
        assert!(
            outside.contains(r#"<a href="/interaction/x/login">"#),
            "the password path must survive outside the noscript block: {outside}"
        );
    }

    /// The logout pages carry the tenant's name, and nothing else escapes it.
    #[test]
    fn every_untrusted_value_on_the_logout_pages_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let confirmation = LogoutConfirmationPage {
                locale: "en",
                tenant_name: hostile,
                action: "/logout",
                csrf: hostile,
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            }
            .render()
            .expect("render");
            assert_no_injection(&confirmation, hostile);

            for signed_out in [true, false] {
                let html = LoggedOutPage {
                    locale: "en",
                    tenant_name: hostile,
                    signed_out,
                    nonce_attribute: nonce_attribute(&nonce),
                    theme_css: "",
                }
                .render()
                .expect("render");
                assert_no_injection(&html, hostile);
            }
        }
    }

    /// The anti-phishing rule of RP-Initiated Logout 1.0 §2, asserted rather
    /// than trusted: the confirmation page is reached by a request nobody
    /// verified, so the template must have no field a client could fill.
    #[test]
    fn the_confirmation_page_can_render_no_relying_party_text() {
        let nonce = nonce();
        let html = LogoutConfirmationPage {
            locale: "en",
            tenant_name: "Demo",
            action: "/logout",
            csrf: "the-token",
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");

        assert!(html.contains("Log out of Demo?"));
        assert!(
            html.contains(r#"<input type="hidden" name="csrf" value="the-token">"#),
            "a forged logout is a denial of service: {html}"
        );
        assert!(html.contains(r#"value="logout""#) && html.contains(r#"value="stay""#));
        // A source-level check, because the field that would carry a client's
        // name is one somebody could add later without noticing what it is.
        let source = include_str!("../templates/logout_confirm.html");
        for forbidden in ["client_name", "logo", "redirect", "post_logout"] {
            assert!(
                !source.contains(&format!("{{{{ {forbidden}")),
                "the confirmation page renders {forbidden}, which the relying party chooses"
            );
        }
    }

    /// Escaping means the raw value never reaches the markup verbatim.
    ///
    /// The first version of this banned the substrings `onerror=` and
    /// `<script` outright, and was wrong: askama renders `' onerror='alert(1)`
    /// as `&#39; onerror=&#39;alert(1)`, which is inert text in a text node —
    /// the quotes that would have closed the attribute are gone. Banning the
    /// substring tests the wrong thing and fails on correct output.
    ///
    /// What escaping actually guarantees is this: every character that could
    /// change the parse — `< > " ' &` — is replaced, so an input containing
    /// one cannot appear verbatim. That is the property, and it is exact.
    fn assert_no_injection(html: &str, hostile: &str) {
        assert_no_injection_beyond(html, hostile, 0);
    }

    /// The same property for a page that legitimately carries `scripts` script
    /// elements of its own: none of them may have come from the input.
    fn assert_no_injection_beyond(html: &str, hostile: &str, scripts: usize) {
        const DANGEROUS: [char; 5] = ['<', '>', '"', '\'', '&'];

        if hostile.contains(DANGEROUS) {
            assert!(
                !html.contains(hostile),
                "the raw value reached the markup unescaped: {hostile:?}"
            );
        }

        // No tag was opened by the input. Checked separately because it is the
        // outcome everything else exists to prevent, and because a future
        // template that interpolated into a `<script>` block would still fail
        // the verbatim check above only by luck.
        assert_eq!(
            html.to_lowercase().matches("<script").count(),
            scripts,
            "a script element appeared for input {hostile:?}"
        );

        // Escaped rather than dropped: a template that silently discarded the
        // value would satisfy every check above while losing the user's data.
        if hostile.contains('<') {
            assert!(
                html.contains("&#60;") || html.contains("&lt;"),
                "the value vanished rather than being escaped: {hostile:?}"
            );
        }
    }

    /// The nonce reaches the markup, and it is the one that was passed.
    #[test]
    fn the_page_carries_the_nonce_it_was_given() {
        let nonce = nonce();
        let page = ErrorPage {
            locale: "en",
            tenant_name: "Demo",
            message: "Something went wrong.",
            correlation_id: "abc123",
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        };
        let html = page.render().expect("render");
        assert!(
            html.contains(nonce.as_str()),
            "the nonce did not reach the markup"
        );
        assert!(html.contains("<style"), "the style block is gone");
    }

    /// No page runs script it was not deliberately given.
    ///
    /// The three pages here have no reason to carry one at all. The three that
    /// do — login, passkey enrolment and form post — are named in
    /// `source_audit::SCRIPTED_TEMPLATES`, each with the reason, and each has
    /// its own tests below for the nonce, the interpolation and the path that
    /// works without script.
    #[test]
    fn no_page_contains_a_script_element() {
        let nonce = nonce();
        let pages = [
            ConsentPage {
                locale: "en",
                tenant_name: "Demo",
                client_name: "Billing",
                username: "ada",
                redirect_host: "rp.example",
                scopes: vec![ScopeLine {
                    name: "openid".into(),
                    description: Some("Confirm who you are".into()),
                    required: true,
                }],
                offline_access: false,
                resources: Vec::new(),
                authorization_details: Vec::new(),
                action: "/x",
                csrf: "t",
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            }
            .render()
            .expect("render"),
            ErrorPage {
                locale: "en",
                tenant_name: "Demo",
                message: "Something went wrong.",
                correlation_id: "abc",
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            }
            .render()
            .expect("render"),
        ];
        for page in &pages {
            let lowered = page.to_lowercase();
            assert!(!lowered.contains("<script"), "{page}");
            assert!(!lowered.contains("javascript:"), "{page}");
        }
    }

    /// Every form that changes something carries a token.
    #[test]
    fn every_post_form_carries_a_csrf_field() {
        let nonce = nonce();
        for html in [
            LoginPage {
                locale: "en",
                tenant_name: "Demo",
                action: "/x",
                passkey_options_action: "/x/passkey/options",
                passkey_finish_action: "/x/passkey/finish",
                csrf: "the-token",
                login_hint: None,
                message: None,
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            }
            .render()
            .expect("render"),
            ConsentPage {
                locale: "en",
                tenant_name: "Demo",
                client_name: "Billing",
                username: "ada",
                redirect_host: "rp.example",
                scopes: Vec::new(),
                offline_access: false,
                resources: Vec::new(),
                authorization_details: Vec::new(),
                action: "/x",
                csrf: "the-token",
                nonce_attribute: nonce_attribute(&nonce),
                theme_css: "",
            }
            .render()
            .expect("render"),
        ] {
            assert!(html.contains("method=\"post\""), "{html}");
            assert!(
                html.contains(r#"<input type="hidden" name="csrf" value="the-token">"#),
                "a POST form without a synchroniser token: {html}"
            );
        }
    }

    /// A denial is a decision, and needs the same protection as an approval.
    #[test]
    fn the_consent_form_offers_both_decisions_under_one_token() {
        let nonce = nonce();
        let html = ConsentPage {
            locale: "en",
            tenant_name: "Demo",
            client_name: "Billing",
            username: "ada",
            redirect_host: "rp.example",
            scopes: Vec::new(),
            offline_access: false,
            resources: Vec::new(),
            authorization_details: Vec::new(),
            action: "/x",
            csrf: "t",
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");
        assert!(html.contains(r#"value="allow""#), "{html}");
        assert!(html.contains(r#"value="deny""#), "{html}");
        assert_eq!(
            html.matches("name=\"csrf\"").count(),
            1,
            "both decisions must post under one token"
        );
    }

    fn consent(scopes: Vec<ScopeLine>, offline: bool, resources: Vec<String>) -> String {
        let nonce = nonce();
        ConsentPage {
            locale: "en",
            tenant_name: "Demo",
            client_name: "Billing",
            username: "ada",
            redirect_host: "rp.example",
            scopes,
            offline_access: offline,
            resources,
            authorization_details: Vec::new(),
            action: "/interaction/x",
            csrf: "t",
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render")
    }

    /// A required scope travels as a hidden field, not a disabled checkbox.
    ///
    /// A disabled input submits nothing, so the value would never reach the
    /// server and `openid` would silently vanish from the grant. The hidden
    /// field says the same thing to a person and cannot be unticked.
    #[test]
    fn a_required_scope_cannot_be_unticked_and_still_submits() {
        let html = consent(
            vec![ScopeLine {
                name: "openid".into(),
                description: Some("Confirm who you are".into()),
                required: true,
            }],
            false,
            Vec::new(),
        );
        assert!(
            html.contains(r#"<input type="hidden" name="scope" value="openid">"#),
            "{html}"
        );
        assert!(
            !html.contains(r#"type="checkbox" name="scope" value="openid""#),
            "a required scope was rendered as a checkbox: {html}"
        );
        assert!(
            !html.contains("disabled"),
            "a disabled input submits nothing: {html}"
        );
        assert!(html.contains("(required)"), "{html}");
    }

    /// An optional scope is a ticked checkbox: the user may decline it and
    /// still proceed, which is what "inadequate choice" in FAPI 2.0 SP §7
    /// means in practice.
    #[test]
    fn an_optional_scope_is_a_checkbox_the_user_can_untick() {
        let html = consent(
            vec![ScopeLine {
                name: "payments".into(),
                description: Some("See your payment history".into()),
                required: false,
            }],
            false,
            Vec::new(),
        );
        assert!(
            html.contains(r#"<input type="checkbox" name="scope" value="payments" checked>"#),
            "{html}"
        );
    }

    /// An unexplained scope shows its bare token rather than an invented
    /// description.
    #[test]
    fn a_scope_with_no_description_shows_its_name() {
        let html = consent(
            vec![ScopeLine {
                name: "obscure:thing".into(),
                description: None,
                required: false,
            }],
            false,
            Vec::new(),
        );
        assert!(html.contains("obscure:thing"), "{html}");
    }

    /// Acting later, without the user present, is a different thing from
    /// acting now, and is said so.
    #[test]
    fn offline_access_is_spelled_out_when_asked_for() {
        let with = consent(Vec::new(), true, Vec::new());
        assert!(with.contains("without you present"), "{with}");

        let without = consent(Vec::new(), false, Vec::new());
        assert!(!without.contains("without you present"), "{without}");
    }

    #[test]
    fn resources_are_listed_only_when_there_are_some() {
        let with = consent(Vec::new(), false, vec!["https://api.example/".into()]);
        assert!(with.contains("https://api.example/"), "{with}");
        assert!(with.contains("Access applies to"), "{with}");

        let without = consent(Vec::new(), false, Vec::new());
        assert!(!without.contains("Access applies to"), "{without}");
    }

    /// The name is chosen by whoever registered; the host is not.
    #[test]
    fn the_consent_page_names_the_host_the_user_returns_to() {
        let html = consent(Vec::new(), false, Vec::new());
        assert!(html.contains("rp.example"), "{html}");
        assert!(html.contains("returned to"), "{html}");
    }

    /// No remote assets: the acceptance criterion, and the reason
    /// `img-src 'self' data:` is in the policy. A client logo fetched from the
    /// client's own server would tell it exactly when a consent screen was
    /// shown, and to whom by IP.
    #[test]
    fn the_consent_page_loads_nothing_from_anywhere_else() {
        let html = consent(
            vec![ScopeLine {
                name: "openid".into(),
                description: Some("Confirm who you are".into()),
                required: true,
            }],
            true,
            vec!["https://api.example/".into()],
        );
        for remote in ["<img", "<iframe", "<link", "src=\"http", "url(http"] {
            assert!(
                !html.to_lowercase().contains(&remote.to_lowercase()),
                "the page pulls a remote asset ({remote}): {html}"
            );
        }
    }

    fn form_post(action: &str, fields: Vec<(&str, &str)>) -> String {
        let nonce = nonce();
        FormPostPage {
            locale: "en",
            tenant_name: "Demo",
            redirect_host: "rp.example",
            action,
            fields: fields
                .into_iter()
                .map(|(name, value)| ResponseField {
                    name: name.to_owned(),
                    value: value.to_owned(),
                })
                .collect(),
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render")
    }

    /// The acceptance criterion of `ast-gxh.5`, as far as markup can carry it.
    #[test]
    fn the_form_post_page_posts_every_response_parameter_to_the_redirect_uri() {
        // --- Arrange / Act ---
        let html = form_post(
            "https://rp.example/cb",
            vec![
                ("code", "the-code"),
                ("state", "the-state"),
                ("iss", "https://as.example/t/demo"),
            ],
        );

        // --- Assert ---
        assert!(html.contains(r#"method="post""#), "{html}");
        assert!(html.contains(r#"action="https://rp.example/cb""#), "{html}");
        for (name, value) in [
            ("code", "the-code"),
            ("state", "the-state"),
            ("iss", "https://as.example/t/demo"),
        ] {
            assert!(
                html.contains(&format!(
                    r#"<input type="hidden" name="{name}" value="{value}">"#
                )),
                "{name} is not on the form: {html}"
            );
        }
    }

    /// An error response travels the same way, or a client that asked for
    /// `form_post` is left waiting for a POST that went out as a query.
    #[test]
    fn an_error_response_uses_the_same_page() {
        let html = form_post(
            "https://rp.example/cb",
            vec![("error", "access_denied"), ("iss", "https://as.example")],
        );

        assert!(
            html.contains(r#"<input type="hidden" name="error" value="access_denied">"#),
            "{html}"
        );
        assert!(!html.contains(r#"name="code""#), "{html}");
    }

    /// The half of "auto-submit, without JavaScript" that markup owns: the
    /// button is real, visible and not disabled, so a browser that never runs
    /// the script has a control that works.
    #[test]
    fn the_form_post_button_works_without_the_script() {
        let html = form_post("https://rp.example/cb", vec![("code", "c")]);

        assert!(
            html.contains(r#"<button type="submit">Continue</button>"#),
            "{html}"
        );
        assert!(!html.contains("hidden>Continue"), "{html}");
        assert!(!html.contains("disabled"), "{html}");
        // The button is outside `<noscript>`: inside it, the one case it
        // exists for — script blocked rather than disabled — would lose it.
        let noscript = html.find("<noscript>").expect("a noscript block");
        let button = html.find("<button").expect("a button");
        assert!(button < noscript, "the button is inside <noscript>: {html}");
    }

    /// The other half: one inline script, carrying this response's nonce, and
    /// nothing interpolated into it.
    #[test]
    fn the_auto_submit_script_carries_the_nonce_and_interpolates_nothing() {
        let nonce = nonce();
        let html = FormPostPage {
            locale: "en",
            tenant_name: "Demo",
            redirect_host: "rp.example",
            action: "https://rp.example/cb",
            fields: vec![ResponseField {
                name: "code".into(),
                value: "the-code".into(),
            }],
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");

        assert_eq!(html.matches("<script").count(), 1, "{html}");
        assert!(
            html.contains(&format!("<script nonce=\"{}\">", nonce.as_str())),
            "{html}"
        );
        let script = &html[html.find("<script").expect("a script")..];
        let script = &script[..script.find("</script>").expect("a closed script")];
        assert!(
            !script.contains("the-code") && !script.contains("rp.example"),
            "a response value reached the script's source text: {script}"
        );
        assert!(!html.contains("<script src"), "{html}");
    }

    /// Everything on this page is a value from a request or a registration,
    /// and all of it lands in an attribute.
    #[test]
    fn a_hostile_state_or_redirect_uri_cannot_break_out_of_the_form() {
        for hostile in HOSTILE {
            let html = form_post(hostile, vec![("state", hostile), ("code", hostile)]);
            // One script: the page's own, which must still be the only one.
            assert_no_injection_beyond(&html, hostile, 1);
        }
    }

    // -----------------------------------------------------------------------
    // The device authorization grant (RFC 8628 §3.3)
    // -----------------------------------------------------------------------

    fn device(user_code: Option<&str>, message: Option<&str>) -> String {
        render(&DevicePage {
            locale: "en",
            tenant_name: "Demo",
            action: "/device",
            csrf: "token",
            user_code,
            message,
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        })
    }

    fn device_confirmation<'a>(client_name: &'a str, user_code: &'a str) -> String {
        render(&DeviceConfirmationPage {
            locale: "en",
            tenant_name: "Demo",
            client_name,
            user_code,
            action: "/device/confirm",
            csrf: "token",
            message: None,
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        })
    }

    /// The code, the client name and the retry message all land in markup.
    #[test]
    fn every_untrusted_value_on_the_device_pages_is_escaped() {
        for hostile in HOSTILE {
            assert_no_injection(&device(Some(hostile), Some(hostile)), hostile);
            assert_no_injection(&device_confirmation(hostile, hostile), hostile);
        }
    }

    /// RFC 8628 §3.3.1: the user is shown the code and asked whether it
    /// matches, which is what §5.4 turns a mailed `verification_uri_complete`
    /// from a click into.
    #[test]
    fn the_confirmation_page_shows_the_code_for_the_user_to_compare() {
        let html = device_confirmation("Example App", "BDWD-HQPK");
        assert!(html.contains("BDWD-HQPK"), "{html}");
        assert!(html.contains("Example App"), "{html}");
        // Both answers, under one token, as everywhere else in this tree.
        assert!(html.contains(r#"value="confirm""#), "{html}");
        assert!(html.contains(r#"value="cancel""#), "{html}");
        assert_eq!(html.matches(r#"name="csrf""#).count(), 1, "{html}");
    }

    /// The code entry field is prefilled only when a complete URI carried one
    /// (§3.3.1), and is editable either way.
    #[test]
    fn the_code_field_is_prefilled_only_by_a_complete_verification_uri() {
        let plain = device(None, None);
        assert!(!plain.contains("value=\"BDWD"), "{plain}");
        assert!(plain.contains(r#"name="user_code""#), "{plain}");

        let complete = device(Some("BDWD-HQPK"), None);
        assert!(complete.contains(r#"value="BDWD-HQPK""#), "{complete}");
        // Editable: a mail client that wrapped the URI must not strand the user.
        assert!(!complete.contains("readonly"), "{complete}");
        assert!(!complete.contains("disabled"), "{complete}");
    }

    /// A refused or expired device says nothing about which it was.
    ///
    /// §5.1: the code space is small enough to walk, and "expired" versus
    /// "never issued" is the answer that makes walking it worthwhile.
    #[test]
    fn an_unconnected_device_names_no_client_and_no_reason() {
        let refused = render(&DeviceOutcomePage {
            locale: "en",
            tenant_name: "Demo",
            connected: false,
            client_name: "Example App",
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        });
        assert!(!refused.contains("Example App"), "{refused}");
        for oracle in ["expired", "cancelled", "unknown", "already"] {
            assert!(
                !refused.to_lowercase().contains(oracle),
                "the refusal page says {oracle:?}: {refused}"
            );
        }

        let connected = render(&DeviceOutcomePage {
            locale: "en",
            tenant_name: "Demo",
            connected: true,
            client_name: "Example App",
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        });
        assert!(connected.contains("Example App"), "{connected}");
    }

    // -----------------------------------------------------------------------
    // Registration, verification and password reset
    // -----------------------------------------------------------------------

    fn registration<'a>(username: Option<&'a str>, email: Option<&'a str>) -> String {
        render(&RegistrationPage {
            locale: "en",
            tenant_name: "Demo",
            action: "/register",
            csrf: "token",
            username,
            email,
            minimum_password_length: 12,
            sign_in_href: "/login",
            message: None,
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        })
    }

    fn email_verification(email: &str, verified: bool) -> String {
        render(&EmailVerificationPage {
            locale: "en",
            tenant_name: "Demo",
            email,
            verified,
            resend_action: "/register/verify/resend",
            continue_href: "/login",
            csrf: "token",
            message: None,
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        })
    }

    fn new_password<'a>(username: &'a str, reset_token: &'a str) -> String {
        render(&NewPasswordPage {
            locale: "en",
            tenant_name: "Demo",
            username,
            action: "/password/new",
            csrf: "token",
            reset_token,
            minimum_password_length: 12,
            message: None,
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        })
    }

    /// Everything a user types is a value an attacker can type.
    #[test]
    fn every_untrusted_value_on_the_account_pages_is_escaped() {
        for hostile in HOSTILE {
            assert_no_injection(&registration(Some(hostile), Some(hostile)), hostile);
            assert_no_injection(&email_verification(hostile, false), hostile);
            assert_no_injection(&email_verification(hostile, true), hostile);
            assert_no_injection(&new_password(hostile, hostile), hostile);
        }
    }

    /// The reset confirmation cannot say whether the account exists.
    ///
    /// Not "does not": there is no field on [`PasswordResetSentPage`] that
    /// could differ between an address this server knows and one it does not,
    /// so the page is the same bytes for both. This test pins that — the
    /// address, a name, a count, any of them would be the oracle RFC 9700 §4
    /// warns about.
    #[test]
    fn a_reset_confirmation_cannot_reveal_whether_the_account_exists() {
        let html = render(&PasswordResetSentPage {
            locale: "en",
            tenant_name: "Demo",
            sign_in_href: "/login",
            nonce_attribute: nonce_attribute(&nonce()),
            theme_css: "",
        });
        // The body only: the shared stylesheet in the head has an `@media`
        // rule in it, and a check that tripped on it would have to be relaxed
        // into uselessness rather than fixed.
        let body = html
            .split_once("<body>")
            .expect("a rendered page has a body")
            .1;
        assert!(!body.contains('@'), "an address reached the page: {body}");
        for oracle in ["no account", "not found", "unknown", "does not exist"] {
            assert!(
                !html.to_lowercase().contains(oracle),
                "the page says {oracle:?}: {html}"
            );
        }
        // The reassurance a user needs, which is true either way.
        assert!(html.contains("If there is an account"), "{html}");
    }

    /// The reset token travels in the body, not in the URL.
    ///
    /// A token in the action lands in history and in a `Referer`; a hidden
    /// field does neither. It is also not the synchroniser token, and both are
    /// present.
    #[test]
    fn the_reset_token_is_a_hidden_field_and_not_the_form_action() {
        let html = new_password("ada", "reset-token-value");
        assert!(
            html.contains(r#"<input type="hidden" name="token" value="reset-token-value">"#),
            "{html}"
        );
        assert!(
            !html.contains(r#"action="/password/new/reset-token-value""#),
            "{html}"
        );
        assert!(html.contains(r#"name="csrf""#), "{html}");
    }

    // -----------------------------------------------------------------------
    // The shared error summary
    // -----------------------------------------------------------------------

    /// A failure announces itself and takes the focus, with no script.
    ///
    /// WCAG 2.2 SC 3.3.1 and 2.4.3. `autofocus` on a `tabindex="-1"` container
    /// is the whole of the focus management on these pages, which is why none
    /// of them needs a `SCRIPTED_TEMPLATES` entry to satisfy the criterion.
    #[test]
    fn a_failed_submission_announces_itself_and_takes_the_focus() {
        let failed = device(None, Some("That code did not work."));
        assert!(failed.contains(r#"role="alert""#), "{failed}");
        assert!(failed.contains(r#"tabindex="-1""#), "{failed}");
        assert!(failed.contains("That code did not work."), "{failed}");

        // And the summary is not rendered when there is nothing to report —
        // an empty alert would take the focus for no reason on every load.
        let fresh = device(None, None);
        assert!(!fresh.contains(r#"role="alert""#), "{fresh}");
    }

    /// Two things may not both want the focus on the same page.
    ///
    /// The first field of a fresh form is focused for convenience; the error
    /// summary is focused because something went wrong. When both would apply
    /// the summary wins, and the templates express that by dropping the
    /// field's `autofocus` — HTML's own rule is "first one in document order",
    /// which would silently pick the wrong one if the summary ever moved.
    #[test]
    fn only_one_element_on_a_page_asks_for_the_focus() {
        for html in [
            device(None, None),
            device(None, Some("That code did not work.")),
            registration(None, None),
            render(&LoginPage {
                locale: "en",
                tenant_name: "Demo",
                action: "/interaction/abc/login",
                passkey_options_action: "/interaction/abc/passkeys/options",
                passkey_finish_action: "/interaction/abc/passkeys/finish",
                csrf: "token",
                login_hint: None,
                message: Some("That did not match."),
                nonce_attribute: nonce_attribute(&nonce()),
                theme_css: "",
            }),
        ] {
            assert_eq!(
                html.matches("autofocus").count(),
                1,
                "two elements ask for the focus: {html}"
            );
        }
    }

    /// A page saved to disk loses its headers but keeps its meta.
    #[test]
    fn every_page_declares_no_referrer_in_the_markup_too() {
        let nonce = nonce();
        let html = ErrorPage {
            locale: "en",
            tenant_name: "Demo",
            message: "x",
            correlation_id: "y",
            nonce_attribute: nonce_attribute(&nonce),
            theme_css: "",
        }
        .render()
        .expect("render");
        assert!(
            html.contains(r#"<meta name="referrer" content="no-referrer">"#),
            "{html}"
        );
    }
}
