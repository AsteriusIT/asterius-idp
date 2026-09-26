//! Explicit LDAPS snapshot read for the operator command. Directory data is
//! fully validated before any database write is attempted.

use std::time::Duration;

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions};
use zeroize::Zeroizing;

use crate::config::LdapSourceConfig;
use asterius_store_pg::{LdapGroup, LdapSnapshot, LdapUser};

const MAX_USERS: usize = 500;
const MAX_GROUPS: usize = 500;
const MAX_MEMBERS: usize = 1_000;
const SEARCH_LIMIT_SECS: i32 = 20;

/// Read one complete, bounded snapshot. A server size limit or referral
/// produces an error; a partial directory cannot be interpreted as deletion.
pub async fn read(source: &LdapSourceConfig) -> Result<LdapSnapshot, String> {
    tokio::time::timeout(Duration::from_secs(60), read_inner(source))
        .await
        .map_err(|_| "LDAP synchronization timed out".to_owned())?
}

async fn read_inner(source: &LdapSourceConfig) -> Result<LdapSnapshot, String> {
    if !source.url.starts_with("ldaps://") {
        return Err("LDAP source must use LDAPS".to_owned());
    }
    let metadata = std::fs::metadata(&source.bind_password_file)
        .map_err(|_| "cannot read LDAP bind secret file".to_owned())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 4_096 {
        return Err("LDAP bind secret file must contain 1–4096 bytes".to_owned());
    }
    let mut password = Zeroizing::new(
        std::fs::read_to_string(&source.bind_password_file)
            .map_err(|_| "cannot read LDAP bind secret file".to_owned())?,
    );
    while password.ends_with(['\r', '\n']) {
        password.pop();
    }
    if password.is_empty() {
        return Err("LDAP bind secret file is empty".to_owned());
    }
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10))
        .set_no_tls_verify(false)
        .set_starttls(false);
    let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &source.url)
        .await
        .map_err(|_| "LDAPS connection or certificate validation failed".to_owned())?;
    ldap3::drive!(connection);
    ldap.simple_bind(&source.bind_dn, &password)
        .await
        .map_err(|_| "LDAP bind failed".to_owned())?
        .success()
        .map_err(|_| "LDAP bind rejected".to_owned())?;
    drop(password);

    let user_attrs = vec![
        source.external_id_attribute.as_str(),
        source.username_attribute.as_str(),
        source.email_attribute.as_str(),
        source.display_name_attribute.as_str(),
    ];
    let entries = search_bounded(
        &mut ldap,
        &source.base_dn,
        &source.user_filter,
        user_attrs,
        MAX_USERS,
    )
    .await?;
    let users = entries
        .into_iter()
        .map(|entry| {
            Ok(LdapUser {
                dn: entry.dn.clone(),
                external_id: one(&entry, &source.external_id_attribute)?,
                username: one(&entry, &source.username_attribute)?,
                email: one(&entry, &source.email_attribute)?,
                display_name: one(&entry, &source.display_name_attribute)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut groups = Vec::new();
    if let (Some(base), Some(filter), Some(name_attr), Some(member_attr)) = (
        &source.group_base_dn,
        &source.group_filter,
        &source.group_name_attribute,
        &source.group_member_attribute,
    ) {
        let entries = search_bounded(
            &mut ldap,
            base,
            filter,
            vec![name_attr.as_str(), member_attr.as_str()],
            MAX_GROUPS,
        )
        .await?;
        for entry in entries {
            let display_name = one(&entry, name_attr)?;
            let member_dns = values(&entry, member_attr).unwrap_or_default();
            if member_dns.len() > MAX_MEMBERS {
                return Err("LDAP group has too many members".to_owned());
            }
            groups.push(LdapGroup {
                dn: entry.dn,
                display_name,
                member_dns,
            });
        }
    }
    ldap.unbind()
        .await
        .map_err(|_| "LDAP unbind failed".to_owned())?;
    Ok(LdapSnapshot { users, groups })
}

async fn search_bounded(
    ldap: &mut Ldap,
    base: &str,
    filter: &str,
    attrs: Vec<&str>,
    limit: usize,
) -> Result<Vec<SearchEntry>, String> {
    ldap.with_search_options(
        SearchOptions::new()
            .sizelimit((limit + 1) as i32)
            .timelimit(SEARCH_LIMIT_SECS),
    );
    let mut stream = ldap
        .streaming_search(base, Scope::Subtree, filter, attrs)
        .await
        .map_err(|_| "LDAP search failed".to_owned())?;
    let mut entries = Vec::new();
    while let Some(entry) = stream
        .next()
        .await
        .map_err(|_| "LDAP search stream failed".to_owned())?
    {
        if entries.len() == limit {
            return Err("LDAP search exceeded entry bound".to_owned());
        }
        entries.push(SearchEntry::construct(entry));
    }
    let result = stream
        .finish()
        .await
        .success()
        .map_err(|_| "LDAP search was incomplete".to_owned())?;
    if !result.refs.is_empty() {
        return Err("LDAP search returned a referral".to_owned());
    }
    Ok(entries)
}

fn one(entry: &SearchEntry, attribute: &str) -> Result<String, String> {
    let values = values(entry, attribute)
        .ok_or_else(|| format!("LDAP entry lacks mapped attribute {attribute}"))?;
    if values.len() != 1 || values[0].is_empty() {
        return Err(format!(
            "LDAP mapped attribute {attribute} must have one value"
        ));
    }
    Ok(values.into_iter().next().unwrap_or_default())
}

fn values(entry: &SearchEntry, attribute: &str) -> Option<Vec<String>> {
    entry
        .attrs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
        .map(|(_, values)| values.clone())
}
