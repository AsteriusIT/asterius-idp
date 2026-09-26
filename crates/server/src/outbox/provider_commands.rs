//! Freshly signed Provider Commands from durable account lifecycle intents.
//!
//! A row contains the client ID, typed command and the exact OIDC subject
//! already issued in a grant. It never contains a signed token. Registration
//! is read at delivery time so an endpoint removed by the RP receives nothing.

use crate::outbound::HttpsPoster;
use crate::outbox::{Delivered, Deliverer, Undelivered};
use crate::provider_commands::{AccountCommand, CommandEndpoint, DeliveryError, Sender};
use asterius_domain::audit::AuditSink;
use asterius_domain::keys::Signer;
use asterius_domain::outbox::OutboxEvent;
use asterius_domain::ports::{Clock, TenantRepository};
use asterius_domain::{Capabilities, ClientId};
use asterius_jose::Kek;
use asterius_store_pg::{PgTenantRepository, Store};
use std::sync::Arc;

pub const FAMILY: &str = "provider_command";

pub struct ProviderCommandDeliverer {
    store: Store,
    tenants: PgTenantRepository,
    signer: Arc<dyn Signer>,
    poster: Arc<HttpsPoster>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ProviderCommandDeliverer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderCommandDeliverer")
    }
}

impl ProviderCommandDeliverer {
    #[must_use]
    pub fn new(
        store: Store,
        kek: Arc<dyn Kek>,
        signer: Arc<dyn Signer>,
        poster: Arc<HttpsPoster>,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let tenants = PgTenantRepository::new(store.pool().clone(), kek);
        Self {
            store,
            tenants,
            signer,
            poster,
            audit,
            clock,
        }
    }
}

#[async_trait::async_trait]
impl Deliverer for ProviderCommandDeliverer {
    fn family(&self) -> &'static str {
        FAMILY
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        if event.kind != "provider_command.account" {
            return Err(Undelivered::permanent(
                "unsupported provider command kind".to_owned(),
            ));
        }
        let Some(subject) = event
            .payload
            .get("subject")
            .and_then(serde_json::Value::as_str)
        else {
            return Err(Undelivered::permanent("missing command subject".to_owned()));
        };
        let command = match event
            .payload
            .get("command")
            .and_then(serde_json::Value::as_str)
        {
            Some("invalidate") => AccountCommand::Invalidate,
            Some("delete") => AccountCommand::Delete,
            _ => {
                return Err(Undelivered::permanent(
                    "unsupported account command".to_owned(),
                ));
            }
        };
        let client = ClientId::new(event.destination.clone());
        let raw = self
            .store
            .scope(event.tenant.clone())
            .clients(Capabilities::default())
            .command_endpoint_for_delivery(&client)
            .await
            .map_err(|_| Undelivered::transient("client registration lookup failed".to_owned()))?;
        let Some(raw) = raw else {
            return Err(Undelivered::permanent(
                "client command endpoint is no longer registered".to_owned(),
            ));
        };
        let endpoint = CommandEndpoint::parse_registered(&raw).map_err(|_| {
            Undelivered::permanent("registered command endpoint is unsafe".to_owned())
        })?;
        let tenant = self
            .tenants
            .find_by_id(&event.tenant)
            .await
            .map_err(|_| Undelivered::transient("tenant lookup failed".to_owned()))?
            .ok_or_else(|| Undelivered::permanent("tenant no longer exists".to_owned()))?;
        if !tenant.is_active() {
            return Err(Undelivered::permanent("tenant is disabled".to_owned()));
        }
        Sender {
            tenant: &tenant,
            signer: self.signer.as_ref(),
            poster: self.poster.as_ref(),
            audit: self.audit.as_ref(),
        }
        .deliver(&client, &endpoint, subject, command, self.clock.now())
        .await
        .map_err(|error| {
            let permanent = match &error {
                DeliveryError::Post(post) => post.is_permanent(),
                DeliveryError::UnsupportedStatus(status) => {
                    *status != 429 && !(500..=599).contains(status)
                }
                DeliveryError::Subject
                | DeliveryError::Time
                | DeliveryError::InvalidResponse(_) => true,
                DeliveryError::Signing(_) | DeliveryError::Audit(_) => false,
            };
            // Never surface the token, endpoint, subject or receiver body.
            let detail = match error {
                DeliveryError::Post(_) => "command transport or RP refusal",
                DeliveryError::Subject => "invalid command subject",
                DeliveryError::Time => "invalid command time",
                DeliveryError::Signing(_) => "command signing failed",
                DeliveryError::UnsupportedStatus(_) | DeliveryError::InvalidResponse(_) => {
                    "invalid RP response"
                }
                DeliveryError::Audit(_) => "command outcome audit failed",
            }
            .to_owned();
            if permanent {
                Undelivered::permanent(detail)
            } else {
                Undelivered::transient(detail)
            }
        })?;
        Ok(Delivered::Sent)
    }
}
