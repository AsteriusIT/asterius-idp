//! The words on the pages, in every language this build renders them in.
//!
//! [`asterius_domain::locale`] decides *which* language a request gets; this
//! module holds what that language actually says, and it is the only place a
//! string a user reads is written down.
//!
//! # A typed catalogue rather than a runtime bundle format
//!
//! `ast-ndk.5` says "Fluent (or ICU) bundles". What is here is neither: it is a
//! `MessageKey` enum with one arm per string and a table per locale, generated
//! by the `catalogue!` macro below. The reasons are the ones this crate keeps
//! making:
//!
//! * **A missing translation is a build failure, not a page.** The macro
//!   demands every locale for every key, so a language cannot be half-added.
//!   With `.ftl` files loaded at startup, a key missing from `fr.ftl` is
//!   discovered by the person it is shown to.
//! * **A key is a type.** Tenant overrides have to be validated against the key
//!   space (`ast-ndk.5`'s second acceptance criterion), and
//!   [`MessageKey::parse`] is that check — total, cheap, and impossible to get
//!   out of step with the templates, because a template that names a key that
//!   does not exist does not compile.
//! * **No new dependency reaches the rendering path.** `crates/web` is checked
//!   by `scripts/check-layering.sh` and by `cargo deny`; a message bundle is
//!   not a good reason to add a parser, a memoiser and a plural-rules crate to
//!   the crate that emits HTML.
//!
//! Fluent's real advantages — plural categories, gendered selection, per-locale
//! ordering of arguments — start to matter when the catalogue has hundreds of
//! entries or a language with a plural system English does not share. There is
//! a note in the ticket's follow-up for the day that is true.
//!
//! # Substitution, and why an argument is still safe
//!
//! A few messages name something: a client, a tenant. Those carry `{0}` and are
//! reached through an accessor that takes the value and returns an owned
//! `String` — so the *whole* sentence, message and substituted value together,
//! is what Askama then escapes. A value cannot escape through the seam between
//! two `{{ }}` because there is no seam: there is one expression.
//!
//! # Tenant overrides
//!
//! [`asterius_domain::MessageOverrides`] has already refused anything that is
//! not text — no `<`, no `>`, no control characters, bounded length. This
//! module adds the half that needs the catalogue: [`validate_overrides`]
//! refuses a key no page has, naming it, and refuses an override that drops the
//! `{0}` a message needs. [`Catalog::with_overrides`] then *ignores* whatever
//! it still does not recognise, deliberately: validation belongs at the moment
//! an administrator writes the setting, and a sign-in page must not fail
//! because a row written by an older build names a key this one renamed.

use asterius_domain::{Locale, MessageOverrides};
use std::collections::BTreeMap;

/// Declares the whole catalogue: keys, tables, and the accessors templates use.
///
/// Two sections, because a message that names something has a different shape
/// of accessor from one that does not:
///
/// * `plain` — `fn accessor(&self) -> &str`;
/// * `filled` — `fn accessor(&self, value: &str) -> String`, with `{0}`
///   replaced by `value` before the caller escapes the lot.
macro_rules! catalogue {
    (
        plain {
            $( $pv:ident => $pa:ident, $pk:literal, en: $pen:literal, fr: $pfr:literal; )*
        }
        filled {
            $( $fv:ident => $fa:ident, $fk:literal, en: $fen:literal, fr: $ffr:literal; )*
        }
    ) => {
        /// One string on one page.
        ///
        /// The key strings are the stable half: they are what a tenant names in
        /// its overrides and what an administrator sees in an error message, so
        /// renaming one is a change to an interface and not to an identifier.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum MessageKey {
            $( #[doc = $pk] $pv, )*
            $( #[doc = $fk] $fv, )*
        }

        impl MessageKey {
            /// Every key this build has, which is the key space an override is
            /// validated against.
            pub const ALL: &'static [Self] = &[ $( Self::$pv, )* $( Self::$fv, )* ];

            /// The dotted name a tenant override uses.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$pv => $pk, )*
                    $( Self::$fv => $fk, )*
                }
            }

            /// The key of that name, if this build has one.
            #[must_use]
            pub fn parse(key: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|known| known.as_str() == key)
            }

            /// Whether the message names something and therefore needs `{0}`.
            #[must_use]
            pub const fn takes_a_value(self) -> bool {
                match self {
                    $( Self::$pv => false, )*
                    $( Self::$fv => true, )*
                }
            }

            /// The wording this build ships, before any tenant override.
            #[must_use]
            pub const fn built_in(self, locale: Locale) -> &'static str {
                match (self, locale) {
                    $(
                        (Self::$pv, Locale::English) => $pen,
                        (Self::$pv, Locale::French) => $pfr,
                    )*
                    $(
                        (Self::$fv, Locale::English) => $fen,
                        (Self::$fv, Locale::French) => $ffr,
                    )*
                }
            }
        }

        impl Catalog {
            $(
                #[doc = concat!("`", $pk, "`")]
                #[must_use]
                pub fn $pa(&self) -> &str {
                    self.get(MessageKey::$pv)
                }
            )*
            $(
                #[doc = concat!("`", $fk, "`, with `{0}` replaced.")]
                #[must_use]
                pub fn $fa(&self, value: &str) -> String {
                    self.fill(MessageKey::$fv, value)
                }
            )*
        }
    };
}

catalogue! {
    plain {
        // ---- shared -------------------------------------------------------
        ErrorSummaryHeading => error_summary_heading, "error-summary.heading",
            en: "There is a problem",
            fr: "Un problème est survenu";

        // ---- login (also the step-up stage, which is the same page) -------
        LoginTitle => login_title, "login.title",
            en: "Sign in",
            fr: "Connexion";
        LoginUsername => login_username, "login.username",
            en: "Username",
            fr: "Identifiant";
        LoginPassword => login_password, "login.password",
            en: "Password",
            fr: "Mot de passe";
        LoginSubmit => login_submit, "login.submit",
            en: "Sign in",
            fr: "Se connecter";
        LoginPasskeyButton => login_passkey_button, "login.passkey-button",
            en: "Sign in with a passkey",
            fr: "Se connecter avec une clé d'accès";
        LoginPasskeyWorking => login_passkey_working, "login.passkey-working",
            en: "Follow your device's prompt to sign in.",
            fr: "Suivez l'invite de votre appareil pour vous connecter.";
        LoginPasskeyFailed => login_passkey_failed, "login.passkey-failed",
            en: "That did not work. Sign in with your password instead.",
            fr: "Cela n'a pas fonctionné. Connectez-vous plutôt avec votre mot de passe.";
        // The word between the passkey button and the password form. One
        // word, in the catalogue rather than in the template, because a
        // template literal is a word a tenant cannot translate.
        LoginOr => login_or, "login.or",
            en: "or",
            fr: "ou";
        // ast-ndk.4, decided with the maquette of ast-9li: the sign-in page
        // carries the link to account recovery. A function nobody can find is
        // a function that gets replaced by a support ticket, and the page it
        // leads to is not an oracle — `/recovery` answers the same page for an
        // address that has an account, an address that has a disabled one and
        // an address nobody has, so a link to it discloses nothing that typing
        // the URL would not. See `docs/threat-model.md`.
        LoginForgotPassword => login_forgot_password, "login.forgot-password",
            en: "Forgot your password?",
            fr: "Mot de passe oublié ?";
        LoginNoScript => login_no_script, "login.no-script",
            en: "Signing in with a passkey needs JavaScript, because it is a browser API that a \
                 page has to call. JavaScript is switched off here, so use your username and \
                 password.",
            fr: "La connexion par clé d'accès nécessite JavaScript, car il s'agit d'une API du \
                 navigateur qu'une page doit appeler. JavaScript est désactivé ici : utilisez \
                 votre identifiant et votre mot de passe.";

        // ---- consent ------------------------------------------------------
        // Prefix rather than a filled sentence, because the host is the part of
        // this page a user checks against where they expected to be (FAPI 2.0
        // SP §7) and it is emphasised in the markup. A filled message would
        // have to carry the `<strong>` to keep that, and a tenant override
        // carrying markup is the one thing these strings may not do.
        ConsentReturnedTo => consent_returned_to, "consent.returned-to",
            en: "You will be returned to",
            fr: "Vous serez redirigé vers";
        // ast-9li: the question, and it names nobody. The heading used to be
        // "{client} would like access", which put a name the client chose for
        // itself at the top of the page in the largest type on it — the
        // misidentification FAPI 2.0 SP §7 warns about, rendered as a title.
        // The name is still here, under the host, as a claim rather than an
        // identity (`consent.calls-itself`).
        ConsentAccessHeading => consent_access_heading, "consent.access-heading",
            en: "Allow access?",
            fr: "Autoriser l'accès ?";
        ConsentAskingFor => consent_asking_for, "consent.asking-for",
            en: "It is asking for:",
            fr: "Voici ce qui est demandé :";
        ConsentRequired => consent_required, "consent.required",
            en: "(required)",
            fr: "(obligatoire)";
        ConsentUndescribedDetail => consent_undescribed_detail, "consent.undescribed-detail",
            en: "Perform an action this server has no description for",
            fr: "Effectuer une action que ce serveur ne sait pas décrire";
        ConsentDetailActions => consent_detail_actions, "consent.detail-actions",
            en: "Operations:",
            fr: "Opérations :";
        ConsentDetailDatatypes => consent_detail_datatypes, "consent.detail-datatypes",
            en: "Data:",
            fr: "Données :";
        ConsentDetailLocations => consent_detail_locations, "consent.detail-locations",
            en: "At:",
            fr: "Auprès de :";
        ConsentResources => consent_resources, "consent.resources",
            en: "Access applies to:",
            fr: "Cet accès s'applique à :";
        ConsentAllow => consent_allow, "consent.allow",
            en: "Allow",
            fr: "Autoriser";
        ConsentDeny => consent_deny, "consent.deny",
            en: "Deny",
            fr: "Refuser";

        // ---- error --------------------------------------------------------
        // A prefix, for `consent.returned-to`'s reason: the correlation id is
        // rendered in a `<code>` element an operator reads back over the
        // telephone.
        ErrorCorrelation => error_correlation, "error.correlation",
            en: "If you contact support, quote",
            fr: "Si vous contactez l'assistance, indiquez";
        ErrorTitle => error_title, "error.title",
            en: "Something went wrong",
            fr: "Une erreur est survenue";

        // ---- logout -------------------------------------------------------
        LogoutTitle => logout_title, "logout.title",
            en: "Log out",
            fr: "Déconnexion";
        LogoutUnverified => logout_unverified, "logout.unverified",
            en: "Somebody asked to end your session. We could not confirm who, so nothing has \
                 changed yet.",
            fr: "Quelqu'un a demandé à mettre fin à votre session. Nous n'avons pas pu vérifier \
                 qui : rien n'a encore changé.";
        LogoutConfirm => logout_confirm, "logout.confirm",
            en: "Log out",
            fr: "Se déconnecter";
        LogoutStay => logout_stay, "logout.stay",
            en: "Stay signed in",
            fr: "Rester connecté";
        LoggedOutTitle => logged_out_title, "logged-out.title",
            en: "Signed out",
            fr: "Déconnecté";
        LoggedOutHeading => logged_out_heading, "logged-out.heading",
            en: "You are signed out",
            fr: "Vous êtes déconnecté";
        StillSignedInTitle => still_signed_in_title, "still-signed-in.title",
            en: "Still signed in",
            fr: "Toujours connecté";
        StillSignedInHeading => still_signed_in_heading, "still-signed-in.heading",
            en: "You are still signed in",
            fr: "Vous êtes toujours connecté";

        // ---- approvals inbox (`ast-lh3.6`) --------------------------------
        //
        // CIBA Core 1.0 §8 has the decision taken on the *authentication
        // device*, which is the person's own phone or laptop: this page is the
        // one in this tree most likely to be read in a hurry, on a small
        // screen, by somebody who did not navigate to it. So it is in the
        // catalogue from the first day rather than in English literals like
        // the device pages beside it.
        ApprovalsTitle => approvals_title, "approvals.title",
            en: "Approvals",
            fr: "Approbations";
        ApprovalsHeading => approvals_heading, "approvals.heading",
            en: "Waiting for your decision",
            fr: "En attente de votre décision";
        ApprovalsEmpty => approvals_empty, "approvals.empty",
            en: "Nothing is waiting for your decision.",
            fr: "Rien n'attend votre décision.";
        // §7.1: the same string is shown by whatever started the flow. The
        // instruction is to *compare*, not to read: a person who is only told
        // a code has been shown a code.
        ApprovalsBindingMessage => approvals_binding_message, "approvals.binding-message",
            en: "Check that this matches what you are seeing where you started:",
            fr: "Vérifiez que ceci correspond à ce qui s'affiche là où vous avez commencé :";
        ApprovalsAskingFor => approvals_asking_for, "approvals.asking-for",
            en: "It is asking for:",
            fr: "Voici ce qui est demandé :";
        ApprovalsAlsoAsking => approvals_also_asking, "approvals.also-asking",
            en: "It is also asking to:",
            fr: "Il est également demandé de :";
        ApprovalsUndescribedDetail => approvals_undescribed_detail,
            "approvals.undescribed-detail",
            en: "Perform an action this server has no description for",
            fr: "Effectuer une action que ce serveur ne sait pas décrire";
        ApprovalsDetailActions => approvals_detail_actions, "approvals.detail-actions",
            en: "Operations:",
            fr: "Opérations :";
        ApprovalsDetailDatatypes => approvals_detail_datatypes, "approvals.detail-datatypes",
            en: "Data:",
            fr: "Données :";
        ApprovalsDetailLocations => approvals_detail_locations, "approvals.detail-locations",
            en: "At:",
            fr: "Auprès de :";
        ApprovalsApprove => approvals_approve, "approvals.approve",
            en: "Approve",
            fr: "Approuver";
        ApprovalsDeny => approvals_deny, "approvals.deny",
            en: "Deny",
            fr: "Refuser";
        // RFC 8628 §5.3's warning, said on this page too: a request nobody
        // started is a request somebody else started.
        ApprovalsWarning => approvals_warning, "approvals.warning",
            en: "If you did not start this yourself, deny it: somebody else is asking to act as \
                 you.",
            fr: "Si vous n'êtes pas à l'origine de cette demande, refusez-la : quelqu'un d'autre \
                 demande à agir en votre nom.";
        // The device flow's code entry, on the same page (`ast-lh3.6`): a
        // person who is told to "approve on your phone" should find both
        // things in one place.
        ApprovalsDeviceHeading => approvals_device_heading, "approvals.device-heading",
            en: "Connecting a device?",
            fr: "Vous connectez un appareil ?";
        ApprovalsDeviceLabel => approvals_device_label, "approvals.device-label",
            en: "Code from the device",
            fr: "Code affiché par l'appareil";
        ApprovalsDeviceSubmit => approvals_device_submit, "approvals.device-submit",
            en: "Continue",
            fr: "Continuer";
        // The two refusals that are about the *approver* rather than about the
        // request. Both are shown on the page rather than logged only: a
        // person whose approval silently did nothing presses the button again.
        ApprovalsStale => approvals_stale, "approvals.stale",
            en: "Sign in again to approve: an approval has to be made within two minutes of \
                 authenticating.",
            fr: "Reconnectez-vous pour approuver : une approbation doit suivre l'authentification \
                 dans les deux minutes.";
        ApprovalsStepUp => approvals_step_up, "approvals.step-up",
            en: "This request needs a stronger sign-in than the one you have. Sign in again with \
                 the method it asks for.",
            fr: "Cette demande exige une authentification plus forte que la vôtre. \
                 Reconnectez-vous avec la méthode demandée.";
        ApprovalsSignInAgain => approvals_sign_in_again, "approvals.sign-in-again",
            en: "Sign in again",
            fr: "Se reconnecter";
        // One sentence for every way a decision can miss: expired, already
        // answered, somebody else's, never existed. Four distinctions nobody
        // on this page can act on, and each of them an answer to a question
        // about a request this person may not hold.
        ApprovalsGone => approvals_gone, "approvals.gone",
            en: "That request is no longer waiting for a decision.",
            fr: "Cette demande n'attend plus de décision.";
        // `ast-5lw`: the decision form has a budget of its own, and a person
        // who hits it is told so rather than shown a page that silently did
        // nothing.
        ApprovalsThrottled => approvals_throttled, "approvals.throttled",
            en: "Too many decisions in a short time. Wait a moment and try again.",
            fr: "Trop de décisions en peu de temps. Patientez un instant et réessayez.";
        ApprovalsApproved => approvals_approved, "approvals.approved",
            en: "Approved.",
            fr: "Approuvé.";
        ApprovalsDenied => approvals_denied, "approvals.denied",
            en: "Denied.",
            fr: "Refusé.";

        // ---- grants dashboard (`ast-uwv.6`) -------------------------------
        //
        // Grant Management ID1 §3 names the dashboard use case: a person has
        // to be able to see what stands open in their name and close it. FAPI
        // 2.0 SP §7 is why the page is written the way it is — it lists the
        // *client's* claims about itself as claims, and it says plainly what
        // withdrawing does, because a revocation somebody did not understand
        // is a support ticket rather than a decision.
        GrantsTitle => grants_title, "grants.title",
            en: "Access you have allowed",
            fr: "Les accès que vous avez autorisés";
        GrantsHeading => grants_heading, "grants.heading",
            en: "Applications and agents with access to your account",
            fr: "Applications et agents ayant accès à votre compte";
        GrantsEmpty => grants_empty, "grants.empty",
            en: "Nothing has standing access to your account.",
            fr: "Aucun accès permanent n'est ouvert sur votre compte.";
        // What the button does, said before it is pressed. The cascade is the
        // one Grant Management ID1 §6.5 describes and this server implements:
        // the authorization, its refresh tokens and its access tokens all go.
        GrantsRevokeExplains => grants_revoke_explains, "grants.revoke-explains",
            en: "Withdrawing access stops the tokens an application already holds from working. \
                 It will have to ask you again.",
            fr: "Retirer un accès rend inutilisables les jetons que l'application détient déjà. \
                 Elle devra vous le redemander.";
        GrantsCovers => grants_covers, "grants.covers",
            en: "This access covers:",
            fr: "Cet accès couvre :";
        GrantsAlsoCovers => grants_also_covers, "grants.also-covers",
            en: "And these operations:",
            fr: "Ainsi que ces opérations :";
        GrantsUndescribedDetail => grants_undescribed_detail, "grants.undescribed-detail",
            en: "An operation this server has no description for",
            fr: "Une opération que ce serveur ne sait pas décrire";
        GrantsDetailActions => grants_detail_actions, "grants.detail-actions",
            en: "Operations:",
            fr: "Opérations :";
        GrantsDetailDatatypes => grants_detail_datatypes, "grants.detail-datatypes",
            en: "Data:",
            fr: "Données :";
        GrantsDetailLocations => grants_detail_locations, "grants.detail-locations",
            en: "At:",
            fr: "Auprès de :";
        GrantsResources => grants_resources, "grants.resources",
            en: "Access applies to:",
            fr: "Cet accès s'applique à :";
        GrantsNeverUsed => grants_never_used, "grants.never-used",
            en: "Never used",
            fr: "Jamais utilisé";
        // RFC 8693 §4.1's `act` chain, as a person reads it: who passed this
        // access on to whom. Listed because a delegation nobody can see is a
        // delegation nobody can withdraw.
        GrantsDelegations => grants_delegations, "grants.delegations",
            en: "Access passed on from this:",
            fr: "Accès transmis à partir de celui-ci :";
        GrantsRevoke => grants_revoke, "grants.revoke",
            en: "Withdraw access",
            fr: "Retirer l'accès";
        GrantsRevoked => grants_revoked, "grants.revoked",
            en: "Access withdrawn.",
            fr: "Accès retiré.";
        // One sentence for every refusal: already withdrawn, somebody else's,
        // never existed, a form this server would not read. The person in
        // front of the page cannot act on the difference, and each distinction
        // answers a question about a grant they may not hold.
        GrantsGone => grants_gone, "grants.gone",
            en: "That access is no longer there.",
            fr: "Cet accès n'existe plus.";
        GrantsStale => grants_stale, "grants.stale",
            en: "Sign in again to withdraw access.",
            fr: "Reconnectez-vous pour retirer un accès.";
        GrantsSignInAgain => grants_sign_in_again, "grants.sign-in-again",
            en: "Sign in again",
            fr: "Se reconnecter";
    }
    filled {
        // ---- consent ------------------------------------------------------
        ConsentTitle => consent_title, "consent.title",
            en: "Authorise {0}",
            fr: "Autoriser {0}";
        ConsentCallsItself => consent_calls_itself, "consent.calls-itself",
            en: "The application calls itself {0}",
            fr: "L'application se présente comme {0}";
        ConsentSignedInAs => consent_signed_in_as, "consent.signed-in-as",
            en: "Signed in as {0}.",
            fr: "Connecté en tant que {0}.";
        ConsentOfflineAccess => consent_offline_access, "consent.offline-access",
            en: "This will let {0} act on your behalf later, without you present.",
            fr: "{0} pourra alors agir en votre nom plus tard, sans que vous soyez présent.";
        ConsentAlsoAsking => consent_also_asking, "consent.also-asking",
            en: "{0} is also asking to:",
            fr: "{0} demande également à :";

        // ---- error --------------------------------------------------------

        // ---- logout -------------------------------------------------------
        LogoutHeading => logout_heading, "logout.heading",
            en: "Log out of {0}?",
            fr: "Se déconnecter de {0} ?";
        LoggedOutBody => logged_out_body, "logged-out.body",
            en: "Your session with {0} has ended. Applications you were signed in to may still \
                 keep sessions of their own.",
            fr: "Votre session avec {0} est terminée. Les applications auxquelles vous étiez \
                 connecté peuvent conserver leurs propres sessions.";
        StillSignedInBody => still_signed_in_body, "still-signed-in.body",
            en: "Nothing was changed. Your session with {0} continues.",
            fr: "Rien n'a été modifié. Votre session avec {0} se poursuit.";

        // ---- approvals inbox (`ast-lh3.6`) --------------------------------
        ApprovalsRequestedBy => approvals_requested_by, "approvals.requested-by",
            en: "{0} is asking to act as you.",
            fr: "{0} demande à agir en votre nom.";
        // §7.3's `expires_in`, rendered server-side and without a script: the
        // value is a duration already formatted as digits and unit symbols, so
        // the sentence around it is the only part that needs a language.
        ApprovalsExpiresIn => approvals_expires_in, "approvals.expires-in",
            en: "Expires in {0}",
            fr: "Expire dans {0}";
        // ---- grants dashboard (`ast-uwv.6`) -------------------------------
        GrantsGrantedTo => grants_granted_to, "grants.granted-to",
            en: "{0} calls itself this, and has access to your account.",
            fr: "{0} se présente ainsi et a accès à votre compte.";
        GrantsAllowedOn => grants_allowed_on, "grants.allowed-on",
            en: "Allowed on {0}",
            fr: "Autorisé le {0}";
        GrantsLastUsed => grants_last_used, "grants.last-used",
            en: "Last used {0}",
            fr: "Dernière utilisation le {0}";
        // The agent's owner is the account the registration named
        // (`asterius_domain::AgentOwner`), which for a grant on this page is
        // this person themselves or somebody who delegated to them.
        GrantsAgentOwner => grants_agent_owner, "grants.agent-owner",
            en: "An agent acting for {0}",
            fr: "Un agent agissant pour {0}";
        GrantsLastExchange => grants_last_exchange, "grants.last-exchange",
            en: "Last delegated token {0}",
            fr: "Dernier jeton délégué le {0}";
        GrantsDelegatedTo => grants_delegated_to, "grants.delegated-to",
            en: "Passed on to {0}",
            fr: "Transmis à {0}";

        ApprovalsDeviceIntro => approvals_device_intro, "approvals.device-intro",
            en: "Enter the code shown on the device you are setting up, and {0} will show you \
                 what it is asking for.",
            fr: "Saisissez le code affiché par l'appareil que vous configurez : {0} vous \
                 indiquera ensuite ce qui est demandé.";
    }
}

/// The words a page is rendered with: one language, plus a tenant's changes.
///
/// Carried by every page struct in [`crate::pages`] in place of the bare locale
/// string those used to hold, so that the `lang` attribute and the words under
/// it cannot disagree: there is one value, and both come out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    locale: Locale,
    overrides: BTreeMap<MessageKey, String>,
}

impl Catalog {
    /// The built-in wording of a language.
    #[must_use]
    pub const fn new(locale: Locale) -> Self {
        Self {
            locale,
            overrides: BTreeMap::new(),
        }
    }

    /// The built-in wording with a tenant's substitutions applied.
    ///
    /// Keys this build does not have are ignored rather than refused; a
    /// substitution that lost the `{0}` a message needs is ignored too, because
    /// a consent page that stopped naming the client would be a worse answer
    /// than one in the wrong words. Both are refused up front by
    /// [`validate_overrides`], which is where an administrator finds out.
    #[must_use]
    pub fn with_overrides(locale: Locale, overrides: &MessageOverrides) -> Self {
        let mut catalog = Self::new(locale);
        for key in overrides.keys() {
            let Some(known) = MessageKey::parse(key) else {
                continue;
            };
            let Some(text) = overrides.get(key) else {
                continue;
            };
            if known.takes_a_value() && !text.contains("{0}") {
                continue;
            }
            catalog.overrides.insert(known, text.to_owned());
        }
        catalog
    }

    /// The language, which is also the `lang` attribute (WCAG 2.2 SC 3.1.1).
    #[must_use]
    pub const fn locale(&self) -> Locale {
        self.locale
    }

    /// The BCP 47 tag, for the `lang` attribute.
    #[must_use]
    pub const fn lang(&self) -> &'static str {
        self.locale.as_tag()
    }

    /// The wording for a key: the tenant's, or this build's.
    #[must_use]
    pub fn get(&self, key: MessageKey) -> &str {
        self.overrides
            .get(&key)
            .map_or_else(|| key.built_in(self.locale), String::as_str)
    }

    /// The wording for a key with `{0}` replaced by `value`.
    ///
    /// One owned `String` handed to the template as a single expression, so
    /// that Askama escapes the sentence and the substituted value together. See
    /// the module documentation.
    #[must_use]
    pub fn fill(&self, key: MessageKey, value: &str) -> String {
        self.get(key).replace("{0}", value)
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new(Locale::default())
    }
}

/// Why a tenant's overrides were refused.
///
/// [`asterius_domain::MessageOverrideError`] covers what a *string* may be;
/// this covers what a *key* may be, which is the half that needs the catalogue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OverrideError {
    /// No page has that key.
    #[error("'{key}' is not a message this server renders")]
    UnknownKey {
        /// The key, as the tenant wrote it.
        key: String,
    },
    /// The replacement dropped the value the message names.
    #[error(
        "the override for '{key}' must contain '{{0}}', which is where {names} appears in the \
         sentence"
    )]
    MissingPlaceholder {
        /// Which key.
        key: String,
        /// What the placeholder stands for, so the message is actionable.
        names: &'static str,
    },
}

/// Checks a tenant's overrides against the catalogue.
///
/// The point where an administrator is told that `consnet.allow` is a typo,
/// rather than the point where a user is shown a page that ignored it. Called
/// by whatever writes the setting; the render path uses
/// [`Catalog::with_overrides`], which cannot fail.
///
/// # Errors
///
/// [`OverrideError`], naming the offending key.
pub fn validate_overrides(overrides: &MessageOverrides) -> Result<(), OverrideError> {
    for key in overrides.keys() {
        let Some(known) = MessageKey::parse(key) else {
            return Err(OverrideError::UnknownKey {
                key: key.to_owned(),
            });
        };
        let text = overrides.get(key).unwrap_or_default();
        if known.takes_a_value() && !text.contains("{0}") {
            return Err(OverrideError::MissingPlaceholder {
                key: key.to_owned(),
                names: "the name of the client, the tenant or the signed-in user",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_spelled_once_and_parses_back() {
        // Arrange
        let mut seen = std::collections::BTreeSet::new();

        // Act & assert
        for key in MessageKey::ALL {
            assert!(
                seen.insert(key.as_str()),
                "the key {} is declared twice",
                key.as_str()
            );
            assert_eq!(MessageKey::parse(key.as_str()), Some(*key));
        }
    }

    /// A key a template names has to say something in every language, and the
    /// macro is what enforces it — this asserts the other half: that nobody
    /// shipped an empty string to satisfy the macro.
    #[test]
    fn every_key_says_something_in_every_language() {
        for key in MessageKey::ALL {
            for locale in Locale::SUPPORTED {
                assert!(
                    !key.built_in(locale).trim().is_empty(),
                    "{} is blank in {locale}",
                    key.as_str()
                );
            }
        }
    }

    /// A message that names something must keep naming it in every language: a
    /// French consent screen that dropped the client's name would be asking a
    /// person to authorise nobody.
    #[test]
    fn a_message_that_names_something_carries_its_placeholder_everywhere() {
        for key in MessageKey::ALL.iter().filter(|key| key.takes_a_value()) {
            for locale in Locale::SUPPORTED {
                assert!(
                    key.built_in(locale).contains("{0}"),
                    "{} has no placeholder in {locale}",
                    key.as_str()
                );
            }
        }
        for key in MessageKey::ALL.iter().filter(|key| !key.takes_a_value()) {
            for locale in Locale::SUPPORTED {
                assert!(
                    !key.built_in(locale).contains("{0}"),
                    "{} has a placeholder nothing fills in {locale}",
                    key.as_str()
                );
            }
        }
    }

    #[test]
    fn the_two_languages_are_actually_different_words() {
        let differences = MessageKey::ALL
            .iter()
            .filter(|key| key.built_in(Locale::English) != key.built_in(Locale::French))
            .count();

        assert_eq!(
            differences,
            MessageKey::ALL.len(),
            "some keys are the same string in both languages; if that is right for a proper \
             noun, say so here"
        );
    }

    #[test]
    fn an_override_replaces_the_built_in_wording() {
        // Arrange
        let overrides =
            MessageOverrides::from_pairs([("consent.allow", "Continuer")]).expect("plain text");

        // Act
        let catalog = Catalog::with_overrides(Locale::French, &overrides);

        // Assert
        assert_eq!(catalog.consent_allow(), "Continuer");
        assert_eq!(catalog.consent_deny(), "Refuser");
    }

    /// The acceptance criterion: an unknown key is refused, and the report says
    /// which key.
    #[test]
    fn an_unknown_key_is_refused_by_path() {
        // Arrange
        let overrides =
            MessageOverrides::from_pairs([("consent.allowed", "Continuer")]).expect("plain text");

        // Act
        let refused = validate_overrides(&overrides).expect_err("no such key");

        // Assert
        assert_eq!(
            refused,
            OverrideError::UnknownKey {
                key: "consent.allowed".to_owned()
            }
        );
        assert!(refused.to_string().contains("consent.allowed"));
    }

    #[test]
    fn an_override_that_drops_the_placeholder_is_refused() {
        // Arrange
        let overrides = MessageOverrides::from_pairs([("consent.calls-itself", "Application")])
            .expect("plain text");

        // Act
        let refused = validate_overrides(&overrides).expect_err("the client is not named");

        // Assert
        assert!(matches!(refused, OverrideError::MissingPlaceholder { .. }));
    }

    /// The render path never fails, however old the row is.
    #[test]
    fn the_render_path_ignores_what_the_validator_would_refuse() {
        // Arrange
        let overrides = MessageOverrides::from_pairs([
            ("consent.allow", "Continuer"),
            ("consent.renamed-away", "x"),
            ("consent.calls-itself", "Application"),
        ])
        .expect("plain text");

        // Act
        let catalog = Catalog::with_overrides(Locale::English, &overrides);

        // Assert
        assert_eq!(catalog.consent_allow(), "Continuer");
        assert_eq!(
            catalog.consent_calls_itself("Example App"),
            "The application calls itself Example App"
        );
    }

    #[test]
    fn a_filled_message_substitutes_once_and_returns_one_string() {
        let catalog = Catalog::new(Locale::French);

        assert_eq!(
            catalog.logout_heading("Example Tenant"),
            "Se déconnecter de Example Tenant ?"
        );
    }

    #[test]
    fn the_lang_attribute_comes_from_the_same_value_as_the_words() {
        let catalog = Catalog::new(Locale::French);

        assert_eq!(catalog.lang(), "fr");
        assert_eq!(catalog.locale(), Locale::French);
    }
}
