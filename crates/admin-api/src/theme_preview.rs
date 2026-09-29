//! An authenticated, inert rendering of the production login template.
use crate::AdminError;
use asterius_domain::{Locale, Tenant, Theme};
use asterius_web::{Brand, Document, Nonce, i18n::Catalog, pages};
use axum::{
    http::header,
    response::{IntoResponse, Response},
};

pub fn render(
    tenant: &Tenant,
    theme: &Theme,
    nonce: &Nonce,
    view: Option<&str>,
) -> Result<Response, AdminError> {
    let view = view.unwrap_or("login");
    if !matches!(view, "login" | "error" | "step-up") {
        return Err(AdminError::Invalid("unknown branding preview".to_owned()));
    }
    let issuer = url::Url::parse(tenant.issuer.as_str()).map_err(|_| AdminError::Unavailable)?;
    let prefix = issuer.path().trim_end_matches('/');
    let font = format!("{prefix}{}", asterius_web::brand::font_path());
    let logo = theme
        .logo()
        .map(|asset| format!("{prefix}/assets/theme/{}", asset.digest()));
    let css = asterius_web::theme::custom_properties(theme);
    let text = Catalog::new(Locale::English);
    let mut brand = Brand::new(&font)
        .with_icon(theme.icon())
        .with_support(theme.support());
    if let Some(logo) = &logo {
        brand = brand.with_logo(logo);
    }
    let document = Document::render(nonce, |nonce| {
        pages::render(&pages::LoginPage {
            preview: true,
            upstream_providers: &[],
            text: &text,
            tenant_name: theme.product_name().unwrap_or(&tenant.display_name),
            step_up: view == "step-up",
            action: "#",
            passkey_options_action: "#",
            passkey_finish_action: "#",
            csrf: "preview-disabled",
            login_hint: None,
            message: (view == "error").then_some("Those details did not match."),
            recovery_href: None,
            nonce_attribute: pages::nonce_attribute(nonce),
            theme_css: &css,
            brand,
        })
    });
    Ok(([(header::CACHE_CONTROL, "no-store")], document).into_response())
}
