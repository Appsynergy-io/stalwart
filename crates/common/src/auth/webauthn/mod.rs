/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod config;

use std::sync::Arc;

use webauthn_rs::Webauthn;

#[derive(Clone)]
pub struct WebauthnState {
    pub webauthn: Arc<Webauthn>,
    pub require_for_admin: bool,
}
