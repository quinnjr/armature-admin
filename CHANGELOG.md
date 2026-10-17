# Changelog — `armature-admin`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- The admin panel can no longer be mounted unauthenticated. The former `require_auth` check accepted any non-empty `Authorization` header (`Authorization: x` granted full CRUD). Every request now goes through a required `AdminAuthenticator` that must verify a real identity and admin rights (`401` / `403` otherwise).
- CSRF protection on every state-changing route: rendered `POST` forms carry a `_csrf` token (signed double-submit via `armature-security`'s CSRF module, `SameSite=Strict` `__Host-` cookie, bound to the authenticated administrator); requests without a valid token in the form field or `X-CSRF-Token` header get `403`.
- Mass assignment closed: create/edit keep only `ModelDefinition::editable_fields()`; primary key, readonly (`readonly_fields` and field-level), excluded, sensitive and undeclared keys are dropped. Non-object JSON bodies are rejected with `400` (they used to replace the whole row, PK included); `InMemoryDataSource::update` rejects them too.
- `sort` and `filter.*` query keys must name declared fields (sortable / `list_filter` respectively) or the list returns `400`; these names were passed straight to the `DataSource` (SQL identifier injection in a SQL-backed source).
- Sensitive fields (`password*`, `*_hash`, `*token*`, `*secret*`) are never rendered, exported, accepted, searched, filtered or sorted on. Detail pages render only the model's declared fields instead of every column the data source returns.
- CSV export is off by default, capped at `export_max_rows` (default 10 000, `X-Export-Truncated: true` when cut), always quotes fields and prefixes values starting with `= + - @ TAB CR` with `'` (formula injection).
- Every admin response carries `Cache-Control: no-store`.

### Added

- `AdminAuthenticator` trait (implemented for `Fn(&HttpRequest) -> Result<AdminPrincipal, AdminAuthError>`), `AdminPrincipal`, `AdminAuthError`.
- `Admin::authenticator`, `Admin::csrf_secret`, `Admin::csrf_config`, `Admin::enable_export`, `Admin::export_max_rows`; `AdminConfig::export_max_rows`.
- `ModelDefinition::{editable_fields, visible_fields, is_readonly, is_sortable_field, is_filter_field, sanitized}` and `is_sensitive_field`.
- `csrf_token` on `DetailView` / `CreateView` / `EditView` with `with_csrf_token`; `render::render_forbidden`.
- Depends on `armature-security` 0.4 for CSRF tokens.

### Changed

- **Breaking:** `AdminInstance::routes()` returns `Result<Router, AdminError>` and fails without an authenticator or with a missing/short (< 32 bytes) CSRF secret. Migration: `Admin::new().authenticator(Arc::new(my_auth)).csrf_secret(secret)…build().routes()?`.
- **Breaking:** `AdminConfig::require_auth` and `Admin::require_auth` removed (the authenticator replaces them).
- **Breaking:** `AdminConfig::enable_export` defaults to `false`. Migration: `.enable_export(true)`.
- **Breaking:** `DetailView::with_data` takes the `&ModelDefinition` (`with_data(&model, record)`).
- **Breaking:** create/edit forms render `editable_fields()` only; `form_fields()` no longer includes sensitive fields; models are sanitized on registration (sensitive/excluded names removed from `list_display`, `search_fields`, `list_filter`, `ordering`).

## [0.5.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- Dependencies bumped to their latest releases: `tokio` 1.52 → 1.53, `uuid` 1.23 → 1.26, `validator` 0.20 → 0.21.

## [0.4.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.
- Requires `armature-proc-macro` 0.4 (was `0.3`); it moved its minor in the same train for the same reason.

## [0.3.2] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
