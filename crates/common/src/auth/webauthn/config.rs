/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use url::Url;
use utils::config::Config;
use webauthn_rs::WebauthnBuilder;

use super::WebauthnState;

pub fn parse_webauthn(config: &mut Config) -> Option<WebauthnState> {
    let rp_id = config.value("authentication.webauthn.rp-id")?.to_string();
    let rp_name = config
        .value("authentication.webauthn.rp-name")
        .unwrap_or("Stalwart")
        .to_string();
    let origin_str = config.value("authentication.webauthn.origin")?.to_string();

    let origin = match Url::parse(&origin_str) {
        Ok(url) => url,
        Err(err) => {
            config.new_build_error(
                "authentication.webauthn.origin",
                format!("Invalid origin URL: {err}"),
            );
            return None;
        }
    };

    let mut builder = match WebauthnBuilder::new(&rp_id, &origin) {
        Ok(b) => b.rp_name(&rp_name),
        Err(err) => {
            config.new_build_error(
                "authentication.webauthn.rp-id",
                format!("Failed to build WebAuthn config: {err}"),
            );
            return None;
        }
    };

    // Additional allowed origins, comma-separated, e.g. "https://a.example.com,https://m.example.com"
    let extra_origins: Vec<String> = config
        .value("authentication.webauthn.allowed-origins")
        .map(|s| s.to_string())
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for raw in &extra_origins {
        match Url::parse(raw) {
            Ok(url) => builder = builder.append_allowed_origin(&url),
            Err(err) => config.new_build_error(
                "authentication.webauthn.allowed-origins",
                format!("Invalid allowed origin {raw}: {err}"),
            ),
        }
    }

    let webauthn = match builder.build() {
        Ok(w) => Arc::new(w),
        Err(err) => {
            config.new_build_error(
                "authentication.webauthn",
                format!("Failed to build WebAuthn: {err}"),
            );
            return None;
        }
    };

    let require_for_admin = config
        .property_or_default("authentication.webauthn.require-for-admin", "false")
        .unwrap_or(false);

    Some(WebauthnState {
        webauthn,
        require_for_admin,
    })
}
