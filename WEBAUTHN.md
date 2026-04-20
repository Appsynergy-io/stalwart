# WebAuthn / Passkey Implementation

Add native WebAuthn/passkey support to Stalwart and Bulwark, following project conventions.

## Stalwart (Backend)

### Dependencies
- [x] Add `webauthn-rs` crate to `crates/common/Cargo.toml`

### Data Model
- [x] Add `PrincipalData::WebauthnCredential(String)` variant to `crates/directory/src/lib.rs`
- [x] Add `PrincipalData::WebauthnRequired` variant for passwordless-only accounts
- [x] Extend `SpecialSecrets` trait with `is_webauthn_credential()` / `is_webauthn_required()`
- [x] Wire variants into `internal/manage.rs` (Set/AddItem/RemoveItem on Secrets field)

### Pattern-Match Updates (revealed by build)
- [x] Update `PrincipalData::object_size()` in `crates/directory/src/core/principal.rs`
- [x] Workspace builds with new variants — no other pattern-match sites needed updates

### Configuration
- [ ] Create `crates/common/src/auth/webauthn/config.rs` with `WebauthnConfig` struct
- [ ] Add config keys: `authentication.webauthn.rp-id`, `.rp-name`, `.origin`, `.require-for-admin`
- [ ] Load WebauthnBuilder in `JmapConfig` or core init alongside OAuth config
- [ ] Add config validation (origin must match rp-id)

### Registration Endpoints
- [ ] `POST /api/principal/{id}/webauthn/register/options` — generate challenge
- [ ] `POST /api/principal/{id}/webauthn/register/verify` — verify and store credential
- [ ] `GET /api/principal/{id}/webauthn` — list registered credentials
- [ ] `DELETE /api/principal/{id}/webauthn/{cred_id}` — remove credential

### Authentication Endpoints
- [ ] `POST /api/auth/webauthn/options` — challenge for login
- [ ] `POST /api/auth/webauthn/verify` — verify, issue session token

### Auth Pipeline Integration
- [ ] Hook WebAuthn-issued tokens into existing OAuth token flow in `crates/http/src/auth/mod.rs`
- [ ] Ensure session/cookie behavior matches OAuth path (issue access_token on success)
- [ ] Add `Credentials::WebauthnAssertion` variant in `mail-send` or local credentials enum
- [ ] Reject `Credentials::Plain` if principal has `WebauthnRequired` data
- [ ] Reject `Credentials::Plain` if account has admin role and `require-webauthn-for-admin` is set

### Tracing/Logging
- [ ] Add `AuthEvent::WebauthnRegister` event type in `crates/trc/src/event/`
- [ ] Add `AuthEvent::WebauthnLogin` event type
- [ ] Emit events from registration/login handlers

### Mandatory Passkey Policy
- [ ] Server-wide config: `authentication.require-webauthn-for-admin` (boolean)
- [ ] Per-principal field: `require_webauthn: bool` on Principal struct
- [ ] Auth flow: reject password login if either flag is true and account has admin role / require-webauthn set
- [ ] Lockout protection: refuse to enable server-wide flag if no admin has a passkey enrolled (prevent self-lockout)

### Testing
- [ ] Build succeeds with `cargo build --release`
- [ ] Server starts without errors
- [ ] Existing password auth still works

## Bulwark (Frontend)

### Dependencies
- [ ] Add `@simplewebauthn/browser` to `package.json`

### API Routes
- [ ] `app/api/webauthn/register/options/route.ts` — proxy to Stalwart
- [ ] `app/api/webauthn/register/verify/route.ts` — proxy to Stalwart
- [ ] `app/api/webauthn/auth/options/route.ts` — proxy to Stalwart
- [ ] `app/api/webauthn/auth/verify/route.ts` — proxy to Stalwart

### UI Components
- [ ] "Add passkey" button in account/security settings
- [ ] List of registered passkeys with delete option
- [ ] "Sign in with passkey" button on login page
- [ ] Conditional rendering when WEBAUTHN_ENABLED=true

### Configuration
- [ ] Add `WEBAUTHN_ENABLED=true` to `.env.example`
- [ ] Add `NEXT_PUBLIC_WEBAUTHN_ENABLED=true` for client-side

### Testing
- [ ] Build succeeds with `npm run build`
- [ ] Enroll a passkey end-to-end
- [ ] Sign in with passkey end-to-end
- [ ] Existing password login still works

## Deployment

- [ ] Compile new Stalwart binary
- [ ] Deploy to CT109
- [ ] Build Bulwark
- [ ] Deploy Bulwark
- [ ] Configure `webauthn.rp-id`, `webauthn.rp-name`, `webauthn.origin`
- [ ] Test enrollment and login from a browser
- [ ] Update DNS-changes / OpenMail docs

## Stalwart Web Admin (Yew/WASM SPA)

Bundled into Stalwart at `crates/main/resources/webadmin/`. Same backend endpoints as Bulwark, separate frontend.

### UI Components
- [ ] "Add passkey" button in admin account settings
- [ ] List of registered passkeys with delete option
- [ ] "Sign in with passkey" button on admin login page
- [ ] WebAuthn JS interop via `wasm-bindgen` (Yew can't call browser WebAuthn directly)
- [ ] Settings → Authentication: "Require passkey for admin accounts" toggle
- [ ] Account → Security: "Require passkey for my account" toggle (visible after enrollment)

### Build
- [ ] Recompile webadmin SPA
- [ ] Bundled into Stalwart binary at build time

## Out of Scope

- iOS/IMAP passkey login (IMAP doesn't support WebAuthn — stays on password)
