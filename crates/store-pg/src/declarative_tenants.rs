//! Conditional tenant settings on the declarative management transaction.
//!
//! Tenant identity/status and signing-key lifecycle remain deployment operations;
//! replacing options uses the same domain parser as ordinary administration.
use asterius_domain::declarative::{Error, Identity, Kind};
use asterius_domain::keys::{KeyPurpose, SigningAlgorithm};
use asterius_domain::{Issuer, RefreshPolicy, ResourceIdentifier, TenantId, TenantSettings};
use asterius_jose::{Kek, KeyBinding, SigningKey, thumbprint};
use serde_json::Value;
use serde_json::json;
use sqlx::{PgConnection, Row as _};
use time::OffsetDateTime;

use crate::error::to_domain_error;

fn tenant_identity(identity: &Identity) -> Result<(), Error> {
    identity.validate()?;
    if identity.kind != Kind::Tenant {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn settings(spec: &Value) -> Result<TenantSettings, Error> {
    let object = spec.as_object().ok_or(Error::Invalid)?;
    let allowed = TenantSettings::default().to_json();
    let fields = allowed.as_object().ok_or(Error::Invalid)?;
    if object.keys().any(|key| !fields.contains_key(key)) {
        return Err(Error::Invalid);
    }
    TenantSettings::from_json(Some(spec)).map_err(|_| Error::Invalid)
}

pub(crate) async fn read(
    connection: &mut PgConnection,
    identity: &Identity,
) -> Result<Value, Error> {
    tenant_identity(identity)?;
    let row = sqlx::query("select issuer, display_name, default_resource, custom_host, settings from tenants where tenant_id = $1")
        .bind(identity.tenant.as_str())
        .fetch_optional(connection)
        .await
        .map_err(|error| Error::Storage(to_domain_error(error)))?
        .ok_or(Error::NotFound)?;
    let document: Value = row
        .try_get("settings")
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    let options = TenantSettings::from_json(document.get("options")).map_err(|_| Error::Invalid)?;
    Ok(json!({
        "tenant_id": identity.tenant.as_str(),
        "issuer": row.try_get::<String, _>("issuer").map_err(|error| Error::Storage(to_domain_error(error)))?,
        "display_name": row.try_get::<String, _>("display_name").map_err(|error| Error::Storage(to_domain_error(error)))?,
        "default_resource": row.try_get::<String, _>("default_resource").map_err(|error| Error::Storage(to_domain_error(error)))?,
        "custom_host": row.try_get::<Option<String>, _>("custom_host").map_err(|error| Error::Storage(to_domain_error(error)))?,
        "options": options.to_json(),
    }))
}

pub(crate) async fn replace(
    connection: &mut PgConnection,
    identity: &Identity,
    spec: &Value,
) -> Result<(), Error> {
    tenant_identity(identity)?;
    let replacement = parse_spec(spec)?;
    let current = read(connection, identity).await?;
    for member in ["tenant_id", "issuer", "default_resource", "custom_host"] {
        if spec.get(member) != current.get(member) {
            return Err(Error::Invalid);
        }
    }
    let options = settings(&replacement.options)?.to_json();
    // Merge only the ordinary settings member. Refresh policy, issuer and
    // deployment status must never be overwritten by an options replacement.
    let changed = sqlx::query(
        "update tenants set settings = settings || jsonb_build_object('options', $2::jsonb), \
         display_name = $3, updated_at = now() where tenant_id = $1",
    )
    .bind(identity.tenant.as_str())
    .bind(options)
    .bind(replacement.display_name)
    .execute(connection)
    .await
    .map_err(|error| Error::Storage(to_domain_error(error)))?;
    if changed.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

struct TenantSpec {
    tenant_id: String,
    issuer: String,
    display_name: String,
    default_resource: String,
    custom_host: Option<String>,
    options: Value,
}

fn default_options() -> Value {
    TenantSettings::default().to_json()
}

fn parse_spec(spec: &Value) -> Result<TenantSpec, Error> {
    let object = spec.as_object().ok_or(Error::Invalid)?;
    if object.keys().any(|key| {
        ![
            "tenant_id",
            "issuer",
            "display_name",
            "default_resource",
            "custom_host",
            "options",
        ]
        .contains(&key.as_str())
    }) {
        return Err(Error::Invalid);
    }
    let string = |member: &str| {
        object
            .get(member)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(Error::Invalid)
    };
    let custom_host = match object.get("custom_host") {
        None | Some(Value::Null) => None,
        Some(Value::String(host)) => Some(host.clone()),
        Some(_) => return Err(Error::Invalid),
    };
    let value = TenantSpec {
        tenant_id: string("tenant_id")?,
        issuer: string("issuer")?,
        display_name: string("display_name")?,
        default_resource: string("default_resource")?,
        custom_host,
        options: object
            .get("options")
            .cloned()
            .unwrap_or_else(default_options),
    };
    TenantId::parse(&value.tenant_id).map_err(|_| Error::Invalid)?;
    let issuer = Issuer::parse(&value.issuer).map_err(|_| Error::Invalid)?;
    if issuer.as_str() != value.issuer {
        return Err(Error::Invalid);
    }
    ResourceIdentifier::parse(&value.default_resource).map_err(|_| Error::Invalid)?;
    if value.display_name.is_empty()
        || value.display_name.len() > 256
        || value.display_name.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    if let Some(host) = &value.custom_host {
        // Match the host form consumed by tenant routing; URL, port and
        // control-character strings cannot become virtual-host identities.
        if host.len() > 253
            || !matches!(url::Host::parse(host), Ok(url::Host::Domain(parsed)) if parsed==*host)
        {
            return Err(Error::Invalid);
        }
    }
    settings(&value.options)?;
    Ok(value)
}

pub(crate) fn normalise(
    _connection: &mut PgConnection,
    tenant: &TenantId,
    spec: &Value,
) -> Result<Value, Error> {
    let value = parse_spec(spec)?;
    if value.tenant_id != tenant.as_str() {
        return Err(Error::Invalid);
    }
    Ok(
        json!({"tenant_id": value.tenant_id, "issuer": value.issuer, "display_name": value.display_name, "default_resource": value.default_resource, "custom_host": value.custom_host, "options": settings(&value.options)?.to_json()}),
    )
}

/// Provisions tenant authority and controller identity within one caller transaction.
pub(crate) async fn create_with_kek(
    connection: &mut PgConnection,
    tenant: &TenantId,
    spec: &Value,
    kek: &dyn Kek,
) -> Result<Identity, Error> {
    let value = parse_spec(spec)?;
    if value.tenant_id != tenant.as_str() || tenant.as_str() == "admin" {
        return Err(Error::Invalid);
    }
    let options = settings(&value.options)?.to_json();
    sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('tenant-upsert'))")
        .bind(tenant.as_str())
        .execute(&mut *connection)
        .await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    sqlx::query(
        "insert into tenants (tenant_id, issuer, display_name, default_resource, custom_host, status, settings) \
         values ($1, $2, $3, $4, $7, 'active', jsonb_build_object('refresh', $5::jsonb, 'options', $6::jsonb))",
    ).bind(tenant.as_str()).bind(&value.issuer).bind(&value.display_name).bind(&value.default_resource)
        .bind(RefreshPolicy::default().to_json()).bind(options).bind(&value.custom_host).execute(&mut *connection).await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    crate::salts::ensure(&mut *connection, tenant, kek)
        .await
        .map_err(Error::Storage)?;
    sqlx::query("insert into resource_servers (tenant_id, identifier, description) values ($1,$2,'the tenant default audience')")
        .bind(tenant.as_str()).bind(&value.default_resource).execute(&mut *connection).await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('key-rotation'))")
        .bind(tenant.as_str())
        .execute(&mut *connection)
        .await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    let now = OffsetDateTime::now_utc();
    for algorithm in SigningAlgorithm::ALL {
        provision_initial_key(connection, tenant, algorithm, kek, now).await?;
    }
    Ok(Identity {
        tenant: tenant.clone(),
        kind: Kind::Tenant,
        keys: vec![tenant.as_str().to_owned()],
    })
}

async fn provision_initial_key(
    connection: &mut PgConnection,
    tenant: &TenantId,
    algorithm: SigningAlgorithm,
    kek: &dyn Kek,
    now: OffsetDateTime,
) -> Result<(), Error> {
    // Initial provisioning has no previous published key or propagation delay.
    // The existing JOSE/KEK primitives bind encrypted private material exactly
    // as the rotation repository does; no plaintext enters PostgreSQL.
    let key = SigningKey::generate(algorithm)
        .map_err(|error| Error::Storage(asterius_domain::DomainError::Storage(Box::new(error))))?;
    let mut public = key
        .public_jwk()
        .map_err(|error| Error::Storage(asterius_domain::DomainError::Storage(Box::new(error))))?;
    let kid = thumbprint(&public)
        .map_err(|error| Error::Storage(asterius_domain::DomainError::Storage(Box::new(error))))?;
    public["kid"] = json!(kid.as_str());
    let purpose = KeyPurpose::Signing;
    let wrapped = kek
        .wrap(
            KeyBinding::new(tenant, &kid, purpose, algorithm),
            key.pkcs8(),
        )
        .await
        .map_err(|error| Error::Storage(asterius_domain::DomainError::Storage(Box::new(error))))?;
    sqlx::query("insert into key_rotation_schedules (tenant_id, purpose, alg, last_rotated_at) values ($1,$2,$3,$4)")
        .bind(tenant.as_str()).bind(purpose.as_str()).bind(algorithm.as_str()).bind(now)
        .execute(&mut *connection).await.map_err(|error| Error::Storage(to_domain_error(error)))?;
    sqlx::query(
        "insert into signing_keys (tenant_id,kid,alg,purpose,public_jwk,private_key_ciphertext,private_key_nonce,kek_id,state,created_at,activated_at) \
         values ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$9)",
    ).bind(tenant.as_str()).bind(kid.as_str()).bind(algorithm.as_str()).bind(purpose.as_str())
        .bind(public).bind(wrapped.ciphertext()).bind(wrapped.nonce()).bind(wrapped.kek_id()).bind(now)
        .execute(connection).await.map_err(|error| Error::Storage(to_domain_error(error)))?;
    Ok(())
}

pub(crate) fn delete(_connection: &mut PgConnection, identity: &Identity) -> Result<(), Error> {
    tenant_identity(identity)?;
    // The accepted v1 contract permits retain/release, never destructive
    // tenant deletion or substituting disable for deletion.
    Err(Error::Protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn settings_cannot_change_identity_or_deployment_status() {
        for document in [
            json!({"status": "disabled"}),
            json!({"issuer": "https://other.example"}),
            json!({"client_secret": "secret"}),
        ] {
            assert!(settings(&document).is_err());
        }
    }

    #[test]
    fn token_lifetimes_use_the_existing_domain_ceiling() {
        assert!(settings(&json!({"access_token_lifetime_seconds": 901})).is_err());
        assert!(settings(&json!({"authorization_code_lifetime_seconds": 61})).is_err());
        assert!(settings(&json!({"access_token_lifetime_seconds": 300})).is_ok());
    }

    #[test]
    fn canonical_options_round_trip() {
        let canonical = TenantSettings::default().to_json();
        assert_eq!(
            settings(&canonical).expect("canonical settings").to_json(),
            canonical
        );
    }
    #[tokio::test]
    #[ignore = "requires migrated DATABASE_URL; CI runs ignored store tests"]
    async fn transactional_provisioning_produces_signable_keys_and_rolls_back_authority() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for ignored store test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("database");
        let tenant = TenantId::new(format!("decl-{}", uuid::Uuid::new_v4().simple()));
        let spec = json!({"tenant_id":tenant.as_str(),"issuer":format!("https://id.example/t/{}",tenant.as_str()),"display_name":"Declarative","default_resource":"https://api.example/","custom_host":null,"options":{}});
        let kek = asterius_jose::LocalKek::from_bytes(&[0x43; 32]).expect("test KEK");
        let mut transaction = pool.begin().await.expect("transaction");
        let identity = create_with_kek(&mut transaction, &tenant, &spec, &kek)
            .await
            .expect("atomic provision");
        assert_eq!(identity.tenant, tenant);
        crate::salts::read(&mut *transaction, &tenant, &kek)
            .await
            .expect("decryptable pairwise salt");
        for algorithm in SigningAlgorithm::ALL {
            let row = sqlx::query("select kid,kek_id,private_key_nonce,private_key_ciphertext from signing_keys where tenant_id=$1 and alg=$2 and state='active'")
                .bind(tenant.as_str()).bind(algorithm.as_str()).fetch_one(&mut *transaction).await.expect("active key");
            let kid =
                asterius_domain::keys::Kid::new(row.try_get::<String, _>("kid").expect("kid"));
            let wrapped = asterius_jose::WrappedKey::from_parts(
                row.try_get::<String, _>("kek_id").expect("KEK ID"),
                row.try_get("private_key_nonce").expect("nonce"),
                row.try_get("private_key_ciphertext").expect("ciphertext"),
            )
            .expect("wrapped key");
            let private = kek
                .unwrap(
                    KeyBinding::new(&tenant, &kid, KeyPurpose::Signing, algorithm),
                    &wrapped,
                )
                .await
                .expect("decrypt key");
            let key = SigningKey::from_pkcs8(algorithm, &private).expect("signable private key");
            assert!(
                !key.sign(b"declarative transactional key")
                    .expect("signature")
                    .is_empty()
            );
        }
        transaction.rollback().await.expect("rollback");
        for table in [
            "tenants",
            "tenant_pairwise_salts",
            "signing_keys",
            "key_rotation_schedules",
            "resource_servers",
        ] {
            let count: i64 =
                sqlx::query_scalar(&format!("select count(*) from {table} where tenant_id=$1"))
                    .bind(tenant.as_str())
                    .fetch_one(&pool)
                    .await
                    .expect("rollback check");
            assert_eq!(count, 0, "{table} authority must roll back");
        }
        pool.close().await;
    }
}
