/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::oauth::{OAuthResponse, token::TokenHandler};
use common::{
    KV_WEBAUTHN, Server,
    auth::AccessToken,
};
use directory::{
    Permission, PrincipalData, QueryParams, Type,
    backend::internal::{
        PrincipalAction, PrincipalField, PrincipalUpdate, PrincipalValue,
        manage::{ManageDirectory, UpdatePrincipal},
    },
};
use http_proto::*;
use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{future::Future, sync::Arc};
use store::{
    dispatch::lookup::KeyValue,
    rand::{Rng, distr::Alphanumeric, rng},
};
use trc::AddContext;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid,
};

const CHALLENGE_TTL: u64 = 300; // 5 minutes
const CHALLENGE_TOKEN_LEN: usize = 32;

#[derive(Debug, Deserialize)]
pub struct WebauthnRegisterOptionsRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebauthnRegisterOptionsResponse {
    pub challenge_id: String,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct WebauthnRegisterVerifyRequest {
    pub challenge_id: String,
    pub name: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct WebauthnAuthOptionsRequest {
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebauthnAuthOptionsResponse {
    pub challenge_id: String,
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct WebauthnAuthVerifyRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub name: String,
    pub created: u64,
    pub passkey: Passkey,
}

#[derive(Debug, Serialize)]
pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created: u64,
}

#[derive(Serialize, Deserialize)]
struct PendingRegistration {
    account_id: u32,
    state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
struct PendingAuthentication {
    candidate_ids: Vec<u32>,
    state: PasskeyAuthentication,
}

pub trait WebauthnHandler: Sync + Send {
    fn handle_webauthn_account(
        &self,
        method: &Method,
        path: &[&str],
        body: Option<Vec<u8>>,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_webauthn_auth(
        &self,
        path: &[&str],
        body: Option<Vec<u8>>,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

fn webauthn(server: &Server) -> trc::Result<&webauthn_rs::Webauthn> {
    server
        .core
        .webauthn
        .as_ref()
        .map(|w| w.webauthn.as_ref())
        .ok_or_else(|| {
            trc::ResourceEvent::NotFound
                .into_err()
                .details("WebAuthn is not configured on this server")
        })
}

/// Passwordless: collect every enrolled passkey on the server paired with the
/// account it belongs to. Callers use the flat `Vec<Passkey>` for the challenge
/// and the `Vec<u32>` in the same order to resolve the winning account at
/// verify time by matching the returned credential id.
async fn all_enrolled_passkeys(server: &Server) -> trc::Result<(Vec<Passkey>, Vec<u32>)> {
    let ids = server
        .store()
        .principal_ids(Some(Type::Individual), None)
        .await?;

    let mut passkeys = Vec::new();
    let mut account_ids = Vec::new();
    for id in ids {
        let (creds, _) = load_credentials(server, id).await?;
        for cred in creds {
            passkeys.push(cred.passkey);
            account_ids.push(id);
        }
    }
    Ok((passkeys, account_ids))
}

async fn load_credentials(
    server: &Server,
    account_id: u32,
) -> trc::Result<(Vec<StoredCredential>, Vec<PrincipalData>)> {
    let principal = server
        .directory()
        .query(QueryParams::id(account_id).with_return_member_of(false))
        .await?
        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

    let mut creds = Vec::new();
    for data in &principal.data {
        if let PrincipalData::WebauthnCredential(raw) = data
            && let Some(json) = raw.strip_prefix("$webauthn$")
            && let Ok(cred) = serde_json::from_str::<StoredCredential>(json)
        {
            creds.push(cred);
        }
    }

    Ok((creds, principal.data))
}

fn serialize_stored(cred: &StoredCredential) -> trc::Result<String> {
    serde_json::to_string(cred)
        .map(|s| format!("$webauthn${s}"))
        .map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .reason(err)
                .caused_by(trc::location!())
        })
}

impl WebauthnHandler for Server {
    async fn handle_webauthn_account(
        &self,
        method: &Method,
        path: &[&str],
        body: Option<Vec<u8>>,
        access_token: Arc<AccessToken>,
    ) -> trc::Result<HttpResponse> {
        access_token.assert_has_permission(Permission::ManagePasswords)?;

        let wan = webauthn(self)?;
        let account_id = access_token.primary_id();
        if account_id == u32::MAX {
            return Err(trc::ManageEvent::Error
                .into_err()
                .details("WebAuthn is not available for fallback administrator accounts"));
        }

        match (path.first().copied().unwrap_or_default(), method) {
            ("register", &Method::POST) => {
                let sub = path.get(1).copied().unwrap_or_default();
                match sub {
                    "options" => {
                        let principal = self
                            .directory()
                            .query(QueryParams::id(account_id).with_return_member_of(false))
                            .await?
                            .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;
                        let (existing, _) = load_credentials(self, account_id).await?;
                        let exclude = existing
                            .iter()
                            .map(|c| c.passkey.cred_id().clone())
                            .collect::<Vec<_>>();

                        let user_uuid = account_uuid(account_id);
                        let (ccr, state) = wan
                            .start_passkey_registration(
                                user_uuid,
                                principal.name(),
                                principal
                                    .description()
                                    .unwrap_or_else(|| principal.name()),
                                if exclude.is_empty() { None } else { Some(exclude) },
                            )
                            .map_err(webauthn_err)?;

                        let challenge_id = new_challenge_token();
                        store_pending_registration(
                            self,
                            &challenge_id,
                            &PendingRegistration { account_id, state },
                        )
                        .await?;

                        Ok(JsonResponse::new(json!({
                            "data": WebauthnRegisterOptionsResponse {
                                challenge_id,
                                options: ccr,
                            }
                        }))
                        .no_cache()
                        .into_http_response())
                    }
                    "verify" => {
                        let req_body = serde_json::from_slice::<WebauthnRegisterVerifyRequest>(
                            body.as_deref().unwrap_or_default(),
                        )
                        .map_err(|err| {
                            trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                                .from_json_error(err)
                        })?;

                        let pending = take_pending_registration(self, &req_body.challenge_id)
                            .await?
                            .ok_or_else(|| {
                                trc::AuthEvent::Failed
                                    .into_err()
                                    .details("Challenge expired or invalid")
                            })?;

                        if pending.account_id != account_id {
                            return Err(trc::AuthEvent::Failed
                                .into_err()
                                .details("Challenge does not match account"));
                        }

                        let passkey = wan
                            .finish_passkey_registration(&req_body.credential, &pending.state)
                            .map_err(webauthn_err)?;

                        let cred_id_b64 = base64_url(passkey.cred_id().as_ref());
                        let display_name = if req_body.name.trim().is_empty() {
                            "Security key".to_string()
                        } else {
                            req_body.name.trim().to_string()
                        };
                        let stored = StoredCredential {
                            id: cred_id_b64.clone(),
                            name: display_name,
                            created: store::write::now(),
                            passkey,
                        };
                        let secret = serialize_stored(&stored)?;

                        let changed = self
                            .core
                            .storage
                            .data
                            .update_principal(
                                UpdatePrincipal::by_id(account_id)
                                    .with_updates(vec![PrincipalUpdate {
                                        action: PrincipalAction::AddItem,
                                        field: PrincipalField::Secrets,
                                        value: PrincipalValue::String(secret),
                                    }])
                                    .with_tenant(access_token.tenant.map(|t| t.id)),
                            )
                            .await?;
                        self.invalidate_principal_caches(changed).await;

                        trc::event!(
                            Auth(trc::AuthEvent::Success),
                            AccountId = account_id,
                            Details = "webauthn register",
                        );

                        Ok(JsonResponse::new(json!({
                            "data": CredentialInfo {
                                id: stored.id,
                                name: stored.name,
                                created: stored.created,
                            }
                        }))
                        .no_cache()
                        .into_http_response())
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }
            ("", &Method::GET) | ("list", &Method::GET) => {
                let (creds, _) = load_credentials(self, account_id).await?;
                let list = creds
                    .into_iter()
                    .map(|c| CredentialInfo {
                        id: c.id,
                        name: c.name,
                        created: c.created,
                    })
                    .collect::<Vec<_>>();
                Ok(JsonResponse::new(json!({ "data": list })).into_http_response())
            }
            (cred_id, &Method::DELETE) if !cred_id.is_empty() => {
                let (creds, _) = load_credentials(self, account_id).await?;
                let target = creds
                    .into_iter()
                    .find(|c| c.id == cred_id)
                    .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;
                let secret = serialize_stored(&target)?;

                let changed = self
                    .core
                    .storage
                    .data
                    .update_principal(
                        UpdatePrincipal::by_id(account_id)
                            .with_updates(vec![PrincipalUpdate {
                                action: PrincipalAction::RemoveItem,
                                field: PrincipalField::Secrets,
                                value: PrincipalValue::String(secret),
                            }])
                            .with_tenant(access_token.tenant.map(|t| t.id)),
                    )
                    .await?;
                self.invalidate_principal_caches(changed).await;

                Ok(JsonResponse::new(json!({ "data": true })).into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn handle_webauthn_auth(
        &self,
        path: &[&str],
        body: Option<Vec<u8>>,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let wan = webauthn(self)?;

        match (path.first().copied().unwrap_or_default(), body.is_some()) {
            ("options", _) => {
                let req_body = serde_json::from_slice::<WebauthnAuthOptionsRequest>(
                    body.as_deref().unwrap_or_default(),
                )
                .unwrap_or(WebauthnAuthOptionsRequest { username: None });

                // Collect candidate passkeys. If a username was supplied we scope
                // the challenge to that account's keys; otherwise we fall back to
                // a passwordless flow across every account with an enrolled key.
                let (candidates, candidate_ids) = match req_body.username.as_deref() {
                    Some(name) if !name.is_empty() => {
                        match self
                            .directory()
                            .query(QueryParams::name(name).with_return_member_of(false))
                            .await?
                        {
                            Some(principal) if principal.id() != u32::MAX => {
                                let (creds, _) = load_credentials(self, principal.id()).await?;
                                (
                                    creds.into_iter().map(|c| c.passkey).collect::<Vec<_>>(),
                                    vec![principal.id()],
                                )
                            }
                            _ => (Vec::new(), Vec::new()),
                        }
                    }
                    _ => all_enrolled_passkeys(self).await?,
                };

                let (rcr, state) = wan
                    .start_passkey_authentication(&candidates)
                    .map_err(webauthn_err)?;

                let challenge_id = new_challenge_token();
                store_pending_auth(
                    self,
                    &challenge_id,
                    &PendingAuthentication {
                        candidate_ids,
                        state,
                    },
                )
                .await?;

                Ok(JsonResponse::new(json!({
                    "data": WebauthnAuthOptionsResponse {
                        challenge_id,
                        options: rcr,
                    }
                }))
                .no_cache()
                .into_http_response())
            }
            ("verify", _) => {
                let req_body = serde_json::from_slice::<WebauthnAuthVerifyRequest>(
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|err| trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err))?;

                let pending = take_pending_auth(self, &req_body.challenge_id)
                    .await?
                    .ok_or_else(|| {
                        trc::AuthEvent::Failed
                            .into_err()
                            .details("Challenge expired or invalid")
                    })?;

                let result = wan
                    .finish_passkey_authentication(&req_body.credential, &pending.state)
                    .map_err(webauthn_err)?;

                // Locate the account whose credential was used
                let mut account_id = None;
                for candidate in &pending.candidate_ids {
                    let (creds, _) = load_credentials(self, *candidate).await?;
                    if creds.iter().any(|c| c.passkey.cred_id() == result.cred_id()) {
                        account_id = Some(*candidate);
                        break;
                    }
                }
                let account_id = account_id.ok_or_else(|| {
                    trc::AuthEvent::Failed
                        .into_err()
                        .details("No matching credential")
                })?;

                let issuer = format!(
                    "{}://{}",
                    if session.is_tls { "https" } else { "http" },
                    session.instance.id
                );
                let response: OAuthResponse = self
                    .issue_token(
                        account_id,
                        "webauthn",
                        issuer,
                        None,
                        true,
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?;

                trc::event!(
                    Auth(trc::AuthEvent::Success),
                    AccountId = account_id,
                    Details = "webauthn login",
                );

                Ok(JsonResponse::new(json!({ "data": response }))
                    .no_cache()
                    .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

fn new_challenge_token() -> String {
    rng()
        .sample_iter(Alphanumeric)
        .take(CHALLENGE_TOKEN_LEN)
        .map(char::from)
        .collect()
}

fn account_uuid(account_id: u32) -> Uuid {
    // Deterministic per-account UUID (v5 in the URL namespace)
    const NAMESPACE: Uuid = Uuid::from_u128(0x6e9f_2c5f_73f8_4d5a_91b8_5d2a_c1e4_8a7c);
    Uuid::new_v5(&NAMESPACE, &account_id.to_be_bytes())
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn webauthn_err(err: impl std::fmt::Display) -> trc::Error {
    trc::AuthEvent::Error
        .into_err()
        .details(err.to_string())
        .caused_by(trc::location!())
}

async fn store_pending_registration(
    server: &Server,
    challenge_id: &str,
    value: &PendingRegistration,
) -> trc::Result<()> {
    let text = serde_json::to_string(value).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .into_err()
            .reason(err)
            .caused_by(trc::location!())
    })?;
    server
        .core
        .storage
        .lookup
        .key_set(
            KeyValue::with_prefix(KV_WEBAUTHN, challenge_id.as_bytes(), text.into_bytes())
                .expires(CHALLENGE_TTL),
        )
        .await
}

async fn take_pending_registration(
    server: &Server,
    challenge_id: &str,
) -> trc::Result<Option<PendingRegistration>> {
    let key = KeyValue::<()>::build_key(KV_WEBAUTHN, challenge_id.as_bytes());
    let value: Option<String> = server.core.storage.lookup.key_get(key.clone()).await?;
    if let Some(text) = value {
        server.core.storage.lookup.key_delete(key).await?;
        Ok(serde_json::from_str(&text).ok())
    } else {
        Ok(None)
    }
}

async fn store_pending_auth(
    server: &Server,
    challenge_id: &str,
    value: &PendingAuthentication,
) -> trc::Result<()> {
    let text = serde_json::to_string(value).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .into_err()
            .reason(err)
            .caused_by(trc::location!())
    })?;
    server
        .core
        .storage
        .lookup
        .key_set(
            KeyValue::with_prefix(KV_WEBAUTHN, challenge_id.as_bytes(), text.into_bytes())
                .expires(CHALLENGE_TTL),
        )
        .await
}

async fn take_pending_auth(
    server: &Server,
    challenge_id: &str,
) -> trc::Result<Option<PendingAuthentication>> {
    let key = KeyValue::<()>::build_key(KV_WEBAUTHN, challenge_id.as_bytes());
    let value: Option<String> = server.core.storage.lookup.key_get(key.clone()).await?;
    if let Some(text) = value {
        server.core.storage.lookup.key_delete(key).await?;
        Ok(serde_json::from_str(&text).ok())
    } else {
        Ok(None)
    }
}

