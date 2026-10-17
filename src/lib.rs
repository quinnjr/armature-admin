//! Admin Dashboard Generator for Armature Framework
//!
//! Auto-generates a complete CRUD admin interface from your models,
//! similar to Django Admin or Rails Admin.
//!
//! ## Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Admin Dashboard                               │
//! │                                                                  │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │  Navigation    │  Content Area                           │  │
//! │  │  ───────────   │  ─────────────                          │  │
//! │  │  Dashboard     │  ┌────────────────────────────────────┐ │  │
//! │  │  Users         │  │  Users List                        │ │  │
//! │  │  Products      │  │  ─────────────────────────────────  │ │  │
//! │  │  Orders        │  │  [Search] [Filter] [+Add]          │ │  │
//! │  │  Settings      │  │  ┌────┬────────┬────────┬───────┐  │ │  │
//! │  │                │  │  │ ID │ Name   │ Email  │ Actions│  │ │  │
//! │  │                │  │  ├────┼────────┼────────┼───────┤  │ │  │
//! │  │                │  │  │ 1  │ Alice  │ a@...  │ ✏️ 🗑️ │  │ │  │
//! │  │                │  │  │ 2  │ Bob    │ b@...  │ ✏️ 🗑️ │  │ │  │
//! │  │                │  │  └────┴────────┴────────┴───────┘  │ │  │
//! │  │                │  │  [◀ Prev] Page 1 of 10 [Next ▶]   │ │  │
//! │  │                │  └────────────────────────────────────┘ │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use armature_admin::{Admin, AdminModel, Field};
//!
//! #[derive(AdminModel)]
//! #[admin(list_display = ["id", "name", "email"])]
//! #[admin(search_fields = ["name", "email"])]
//! struct User {
//!     #[admin(primary_key)]
//!     id: i64,
//!     #[admin(required)]
//!     name: String,
//!     #[admin(widget = "email")]
//!     email: String,
//!     #[admin(readonly)]
//!     created_at: DateTime<Utc>,
//! }
//!
//! let admin = Admin::new()
//!     .title("My Admin")
//!     // Required: verifies a real identity AND admin rights per request.
//!     .authenticator(Arc::new(|req: &HttpRequest| {
//!         let user = req
//!             .extension::<armature_auth::UserContext>()
//!             .ok_or(AdminAuthError::Unauthenticated)?;
//!         if user.roles.iter().any(|r| r == "admin") {
//!             Ok(AdminPrincipal::new(user.user_id.clone()))
//!         } else {
//!             Err(AdminAuthError::Forbidden)
//!         }
//!     }))
//!     // Required: >= 32 random bytes, used to sign CSRF tokens.
//!     .csrf_secret(std::env::var("ADMIN_CSRF_SECRET")?)
//!     .register::<User>()
//!     .build();
//!
//! // Mount at /admin. Fails if the authenticator or CSRF secret is missing.
//! app.mount("/admin", admin.routes()?);
//! ```
//!
//! ## Security model
//!
//! - **Authentication is mandatory.** [`AdminInstance::routes`] returns an
//!   error unless an [`AdminAuthenticator`] and a CSRF secret are configured,
//!   and the authenticator runs on every request.
//! - **CSRF.** Every rendered `POST` form carries a `_csrf` token bound to the
//!   authenticated administrator; state-changing requests without a valid
//!   token (form field or `X-CSRF-Token` header) are rejected with `403`.
//! - **Field allowlist.** Create/edit accept only
//!   [`ModelDefinition::editable_fields`]; the primary key, readonly,
//!   excluded, sensitive and undeclared keys are dropped. JSON bodies must be
//!   objects. `sort` and `filter.*` keys must name declared fields.
//! - **Sensitive fields** (`password*`, `*_hash`, `*token*`, `*secret*`, see
//!   [`is_sensitive_field`]) are never rendered, exported, searched, filtered
//!   or sorted on, and detail pages render only declared fields.
//! - **Export** is off by default, capped at
//!   [`AdminConfig::export_max_rows`], and neutralizes spreadsheet formulas.
//! - Every response carries `Cache-Control: no-store`.

pub mod auth;
pub mod config;
pub mod dashboard;
pub mod data;
pub mod error;
pub mod field;
pub mod model;
pub mod registry;
pub mod render;
pub mod ui;
pub mod views;

pub use auth::{AdminAuthError, AdminAuthenticator, AdminPrincipal};
pub use config::*;
pub use dashboard::*;
pub use data::{DataPage, DataQuery, DataSource, InMemoryDataSource};
pub use error::*;
pub use field::*;
pub use model::*;
pub use registry::*;
pub use ui::*;
pub use views::*;

use armature_core::{Error, HttpRequest, HttpResponse, Router};
use armature_security::csrf::{CsrfConfig, CsrfError, CsrfProtection, is_safe_method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Admin instance builder
pub struct Admin {
    /// Admin configuration
    config: AdminConfig,
    /// Model registry
    registry: ModelRegistry,
    /// Backing data source
    data_source: Arc<dyn DataSource>,
    /// Verifies identity + admin rights on every request
    authenticator: Option<Arc<dyn AdminAuthenticator>>,
    /// CSRF configuration (secret is validated when set)
    csrf: Option<Result<CsrfConfig, CsrfError>>,
}

impl Admin {
    /// Create a new admin builder
    ///
    /// An [`authenticator`](Self::authenticator) and a
    /// [`csrf_secret`](Self::csrf_secret) are required before
    /// [`AdminInstance::routes`] will build a router.
    pub fn new() -> Self {
        Self {
            config: AdminConfig::default(),
            registry: ModelRegistry::new(),
            data_source: Arc::new(InMemoryDataSource::new()),
            authenticator: None,
            csrf: None,
        }
    }

    /// Set the admin title
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.config.title = title.into();
        self
    }

    /// Set the base URL path
    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.config.base_path = path.into();
        self
    }

    /// Set the theme
    pub fn theme(mut self, theme: Theme) -> Self {
        self.config.theme = theme;
        self
    }

    /// Set items per page
    pub fn items_per_page(mut self, count: usize) -> Self {
        self.config.items_per_page = count;
        self
    }

    /// Set the maximum items-per-page a client may request
    pub fn max_items_per_page(mut self, count: usize) -> Self {
        self.config.max_items_per_page = count;
        self
    }

    /// Enable or disable CSV export (disabled by default)
    pub fn enable_export(mut self, enabled: bool) -> Self {
        self.config.enable_export = enabled;
        self
    }

    /// Cap the number of rows a single CSV export may contain
    pub fn export_max_rows(mut self, rows: usize) -> Self {
        self.config.export_max_rows = rows;
        self
    }

    /// Set the authenticator that verifies every admin request (required).
    ///
    /// It must verify a real credential and admin authorization; see
    /// [`AdminAuthenticator`].
    pub fn authenticator(mut self, authenticator: Arc<dyn AdminAuthenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Set the CSRF secret (required, at least 32 bytes) with the default
    /// cookie settings (`__Host-armature-csrf`, `Secure`, `HttpOnly`,
    /// `SameSite=Strict`). A short secret makes [`AdminInstance::routes`]
    /// fail.
    pub fn csrf_secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.csrf = Some(CsrfConfig::new(secret));
        self
    }

    /// Use a fully custom CSRF configuration (for example a non-`__Host-`
    /// cookie for plain-HTTP development).
    pub fn csrf_config(mut self, config: CsrfConfig) -> Self {
        self.csrf = Some(Ok(config));
        self
    }

    /// Set the backing data source (defaults to an in-memory store)
    pub fn data_source(mut self, source: Arc<dyn DataSource>) -> Self {
        self.data_source = source;
        self
    }

    /// Register a model with the admin
    pub fn register_model(mut self, model: ModelDefinition) -> Self {
        self.registry.register(model);
        self
    }

    /// Build the admin instance
    pub fn build(self) -> AdminInstance {
        AdminInstance {
            config: Arc::new(self.config),
            registry: Arc::new(self.registry),
            data_source: self.data_source,
            authenticator: self.authenticator,
            csrf: self.csrf.map(|r| r.map(CsrfProtection::new)),
        }
    }
}

impl Default for Admin {
    fn default() -> Self {
        Self::new()
    }
}

/// Built admin instance
#[derive(Clone)]
pub struct AdminInstance {
    /// Configuration
    pub config: Arc<AdminConfig>,
    /// Model registry
    pub registry: Arc<ModelRegistry>,
    /// Backing data source
    pub data_source: Arc<dyn DataSource>,
    authenticator: Option<Arc<dyn AdminAuthenticator>>,
    csrf: Option<Result<CsrfProtection, CsrfError>>,
}

/// Everything a request handler needs once the request has been admitted.
struct Secured {
    inst: AdminInstance,
    authenticator: Arc<dyn AdminAuthenticator>,
    csrf: CsrfProtection,
}

/// Per-request context for an admitted request.
struct RequestCtx {
    /// The verified administrator.
    #[allow(dead_code)]
    principal: AdminPrincipal,
    /// CSRF token to render into this page's POST forms.
    csrf_token: String,
}

#[derive(Clone, Copy)]
enum Route {
    Dashboard,
    List,
    Detail,
    CreateForm,
    CreateSubmit,
    EditForm,
    UpdateSubmit,
    Delete,
}

impl AdminInstance {
    /// Get the configuration
    pub fn config(&self) -> &AdminConfig {
        &self.config
    }

    /// Get the model registry
    pub fn registry(&self) -> &ModelRegistry {
        &self.registry
    }

    /// Get the backing data source
    pub fn data_source(&self) -> &Arc<dyn DataSource> {
        &self.data_source
    }

    /// Build a mountable [`armature_core::Router`] for the admin interface.
    ///
    /// Every request is first passed to the configured
    /// [`AdminAuthenticator`] (`401` / `403` on failure). State-changing
    /// requests (`POST`, `DELETE`, ...) must then carry a CSRF token bound to
    /// the authenticated administrator, either in the `_csrf` form field the
    /// rendered forms include or in the `X-CSRF-Token` header (`403`
    /// otherwise). Every response is sent with `Cache-Control: no-store`.
    ///
    /// Registered routes (relative to `base_path`, default `/admin`):
    /// - `GET  {base}` — dashboard
    /// - `GET  {base}/:model` — list
    /// - `GET  {base}/:model/add` + `POST {base}/:model/add` — create
    /// - `GET  {base}/:model/:id` — detail
    /// - `GET  {base}/:model/:id/edit` + `POST {base}/:model/:id/edit` — update
    /// - `POST {base}/:model/:id/delete` (also `DELETE {base}/:model/:id`) — delete
    ///
    /// # Errors
    ///
    /// [`AdminError::Config`] when no authenticator is configured, or the CSRF
    /// secret is missing or shorter than 32 bytes. The admin panel is never
    /// mountable without both.
    pub fn routes(&self) -> Result<Router, AdminError> {
        let authenticator = self.authenticator.clone().ok_or_else(|| {
            AdminError::Config(
                "an AdminAuthenticator is required: the admin router will not serve \
                 unauthenticated requests"
                    .to_string(),
            )
        })?;
        let csrf = match &self.csrf {
            None => {
                return Err(AdminError::Config(
                    "a CSRF secret is required (Admin::csrf_secret)".to_string(),
                ));
            }
            Some(Err(e)) => return Err(AdminError::Config(e.to_string())),
            Some(Ok(csrf)) => csrf.clone(),
        };

        let base = self.config.base_path.trim_end_matches('/').to_string();
        let secured = Arc::new(Secured {
            inst: self.clone(),
            authenticator,
            csrf,
        });
        let mut router = Router::new();

        macro_rules! h {
            ($route:expr) => {{
                let secured = secured.clone();
                move |req: HttpRequest| {
                    let secured = secured.clone();
                    async move { dispatch(secured, req, $route).await }
                }
            }};
        }

        router.get(base.clone(), h!(Route::Dashboard));
        router.get(format!("{base}/:model"), h!(Route::List));
        // Static `/add` and `/:id/edit` must precede the `:id` param routes so
        // they are matched first (the router returns the first matching route).
        router.get(format!("{base}/:model/add"), h!(Route::CreateForm));
        router.post(format!("{base}/:model/add"), h!(Route::CreateSubmit));
        router.get(format!("{base}/:model/:id/edit"), h!(Route::EditForm));
        router.post(format!("{base}/:model/:id/edit"), h!(Route::UpdateSubmit));
        router.post(format!("{base}/:model/:id/delete"), h!(Route::Delete));
        router.delete(format!("{base}/:model/:id"), h!(Route::Delete));
        router.get(format!("{base}/:model/:id"), h!(Route::Detail));

        Ok(router)
    }

    /// Get a model definition by name
    pub fn get_model(&self, name: &str) -> Option<&ModelDefinition> {
        self.registry.get(name)
    }

    /// List all registered models
    pub fn models(&self) -> Vec<&ModelDefinition> {
        self.registry.all()
    }
}

/// Authenticate, enforce CSRF, run the handler, and stamp the response
/// `Cache-Control: no-store` whatever the outcome.
async fn dispatch(
    secured: Arc<Secured>,
    req: HttpRequest,
    route: Route,
) -> Result<HttpResponse, Error> {
    let inst = &secured.inst;
    let mut resp = match secured.authenticator.authenticate(&req).await {
        Err(AdminAuthError::Unauthenticated) => {
            html_response(401, render::render_unauthorized(&inst.config))
        }
        Err(AdminAuthError::Forbidden) => {
            html_response(403, render::render_forbidden(&inst.config))
        }
        Ok(principal) => {
            if !is_safe_method(req.method_str())
                && secured.csrf.verify(&req, &principal.id).is_err()
            {
                html_response(403, render::render_forbidden(&inst.config))
            } else {
                let issued = secured.csrf.issue(&req, &principal.id);
                let ctx = RequestCtx {
                    principal,
                    csrf_token: issued.token,
                };
                let mut resp = match route {
                    Route::Dashboard => handle_dashboard(inst).await,
                    Route::List => handle_list(inst, &req).await,
                    Route::Detail => handle_detail(inst, &ctx, &req).await,
                    Route::CreateForm => handle_create_form(inst, &ctx, &req).await,
                    Route::CreateSubmit => handle_create_submit(inst, &req).await,
                    Route::EditForm => handle_edit_form(inst, &ctx, &req).await,
                    Route::UpdateSubmit => handle_update_submit(inst, &req).await,
                    Route::Delete => handle_delete(inst, &req).await,
                };
                if let Some(cookie) = issued.set_cookie {
                    resp.cookies.push(cookie);
                }
                resp
            }
        }
    };
    resp.headers
        .insert("Cache-Control".to_string(), "no-store".to_string());
    Ok(resp)
}

/// Resolve the `:model` path param to its [`ModelDefinition`], or the 404
/// response to return.
fn resolve_model(inst: &AdminInstance, req: &HttpRequest) -> Result<ModelDefinition, HttpResponse> {
    let model_name = req.param("model").unwrap_or_default();
    inst.get_model(model_name)
        .cloned()
        .ok_or_else(|| html_response(404, render::render_not_found(&inst.config)))
}

/// Build [`ListParams`] from the request's query string.
fn list_params_from_request(req: &HttpRequest) -> ListParams {
    let get = |k: &str| req.query_param(k);
    let mut filters = HashMap::new();
    for (k, v) in req.query().iter() {
        if let Some(field) = k.strip_prefix("filter.") {
            filters.insert(field.to_string(), v.to_owned());
        }
    }
    ListParams {
        page: get("page").and_then(|p| p.parse().ok()),
        per_page: get("per_page").and_then(|p| p.parse().ok()),
        sort: get("sort").map(str::to_owned),
        order: match get("order") {
            Some("desc") | Some("DESC") => Some(SortOrder::Desc),
            Some("asc") | Some("ASC") => Some(SortOrder::Asc),
            _ => None,
        },
        search: get("search").map(str::to_owned),
        filters,
    }
}

/// Reject `sort` / `filter.*` keys that are not declared on the model.
///
/// These names reach the [`DataSource`] (and, in a SQL-backed one, the
/// `ORDER BY` / `WHERE` clauses), so only declared, visible, sortable or
/// filterable fields are allowed.
fn validate_list_params(model: &ModelDefinition, params: &ListParams) -> Result<(), String> {
    if let Some(sort) = &params.sort
        && !model.is_sortable_field(sort)
    {
        return Err(format!("unknown sort field: {sort}"));
    }
    for key in params.filters.keys() {
        if !model.is_filter_field(key) {
            return Err(format!("unknown filter field: {key}"));
        }
    }
    Ok(())
}

/// Parse a submitted form (or JSON body) and keep only the model's
/// [`editable_fields`](ModelDefinition::editable_fields).
///
/// Primary keys, readonly, excluded, sensitive and undeclared keys (including
/// the `_csrf` field) are dropped. A JSON body must be an object.
fn parse_submission(
    model: &ModelDefinition,
    req: &HttpRequest,
) -> Result<serde_json::Value, String> {
    let is_json = req
        .headers
        .get_ignore_case("content-type")
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    let submitted: serde_json::Map<String, serde_json::Value> = if is_json {
        match req.json::<serde_json::Value>() {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => return Err("request body must be a JSON object".to_string()),
            Err(_) => return Err("request body is not valid JSON".to_string()),
        }
    } else {
        req.form_map()
            .map_err(|_| "request body is not a valid form".to_string())?
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect()
    };

    let allowed: Vec<&str> = model
        .editable_fields()
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let filtered: serde_json::Map<String, serde_json::Value> = submitted
        .into_iter()
        .filter(|(k, _)| allowed.contains(&k.as_str()))
        .collect();
    Ok(serde_json::Value::Object(filtered))
}

fn html_response(status: u16, body: String) -> HttpResponse {
    let mut resp = HttpResponse::html(body);
    resp.status = status;
    resp
}

/// Quote a single CSV field and neutralize spreadsheet formulas.
///
/// Every field is wrapped in double quotes (internal quotes doubled), and a
/// value starting with `=`, `+`, `-`, `@`, TAB or CR is prefixed with `'` so
/// spreadsheet applications treat it as text instead of evaluating it
/// (CSV/formula injection).
fn csv_field(value: &str) -> String {
    let neutralized = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", neutralized.replace('"', "\"\""))
}

/// Render the model's `list_display` columns for the given rows as CSV text.
///
/// The header row uses the display fields' labels; each data row emits the
/// plain (unescaped) value of each display field.
fn render_list_csv(model: &ModelDefinition, rows: &[serde_json::Value]) -> String {
    let fields = model.display_fields();
    let mut out = String::new();

    let header: Vec<String> = fields.iter().map(|f| csv_field(&f.label)).collect();
    out.push_str(&header.join(","));
    out.push_str("\r\n");

    for row in rows {
        let cells: Vec<String> = fields
            .iter()
            .map(|f| {
                let raw = row
                    .get(&f.name)
                    .map(data::value_to_plain_string)
                    .unwrap_or_default();
                csv_field(&raw)
            })
            .collect();
        out.push_str(&cells.join(","));
        out.push_str("\r\n");
    }

    out
}

async fn handle_dashboard(inst: &AdminInstance) -> HttpResponse {
    let mut view = DashboardView::new(inst);
    // Populate live counts from the data source.
    let mut total = 0usize;
    for summary in &mut view.model_summaries {
        if let Some(model) = inst.get_model(&summary.name) {
            let count = inst.data_source.count(model).await;
            summary.count = count;
            total += count;
        }
    }
    if let Some(first) = view.stats.first_mut() {
        first.value = total.to_string();
    }
    HttpResponse::html(render::render_dashboard(&view, &inst.config))
}

async fn handle_list(inst: &AdminInstance, req: &HttpRequest) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    let params = list_params_from_request(req);
    if let Err(msg) = validate_list_params(&model, &params) {
        return html_response(400, render::render_error(&inst.config, &msg));
    }
    let per_page = params.resolve_per_page(&inst.config);
    let offset = params.resolve_offset(per_page);

    // Ordering clauses, honoring the (validated) sort param else the model
    // default.
    let order_by = if let Some(sort) = &params.sort {
        vec![format!(
            "{} {}",
            sort,
            params.order.unwrap_or_default().as_sql()
        )]
    } else {
        model.ordering.iter().map(|o| o.as_sql()).collect()
    };

    // CSV export of the current query (honoring search/filters/ordering),
    // capped at `export_max_rows`.
    if req.query_param("export") == Some("csv") {
        if !(inst.config.enable_export && model.can_export) {
            return html_response(403, render::render_forbidden(&inst.config));
        }
        let cap = inst.config.export_max_rows.max(1);
        let query = DataQuery {
            offset: 0,
            limit: cap,
            order_by,
            search: params.search.clone(),
            filters: params.filters.clone(),
        };
        let page = inst.data_source.list(&model, &query).await;
        let rows: Vec<serde_json::Value> = page.rows.into_iter().take(cap).collect();
        let truncated = page.total > rows.len();
        let csv = render_list_csv(&model, &rows);
        let mut resp = HttpResponse::new(200)
            .with_header(
                "Content-Type".to_string(),
                "text/csv; charset=utf-8".to_string(),
            )
            .with_header(
                "Content-Disposition".to_string(),
                format!("attachment; filename=\"{}.csv\"", model.name),
            )
            .with_body(csv.into_bytes());
        if truncated {
            resp.headers
                .insert("X-Export-Truncated".to_string(), "true".to_string());
        }
        return resp;
    }

    let query = DataQuery {
        offset,
        limit: per_page,
        order_by,
        search: params.search.clone(),
        filters: params.filters.clone(),
    };

    let page = inst.data_source.list(&model, &query).await;
    let view = ListView::new(&model, params, per_page).with_json_rows(
        &model,
        &inst.config,
        &page.rows,
        page.total,
    );
    HttpResponse::html(render::render_list(&view, &inst.config))
}

async fn handle_detail(inst: &AdminInstance, ctx: &RequestCtx, req: &HttpRequest) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let id = req.param("id").unwrap_or_default().to_owned();

    match inst.data_source.get(&model, &id).await {
        Some(record) => {
            let view = DetailView::new(&model, id)
                .with_data(&model, record)
                .with_csrf_token(&ctx.csrf_token);
            HttpResponse::html(render::render_detail(&view, &inst.config))
        }
        None => html_response(404, render::render_not_found(&inst.config)),
    }
}

async fn handle_create_form(
    inst: &AdminInstance,
    ctx: &RequestCtx,
    req: &HttpRequest,
) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let view = CreateView::new(&model).with_csrf_token(&ctx.csrf_token);
    HttpResponse::html(render::render_create(&view, &inst.config))
}

async fn handle_create_submit(inst: &AdminInstance, req: &HttpRequest) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    if !model.can_add {
        return html_response(403, render::render_forbidden(&inst.config));
    }
    let data = match parse_submission(&model, req) {
        Ok(data) => data,
        Err(msg) => return html_response(400, render::render_error(&inst.config, &msg)),
    };
    match inst.data_source.create(&model, data).await {
        Ok(id) => {
            HttpResponse::redirect(format!("{}/{}/{}", inst.config.base_path, model.name, id))
        }
        Err(e) => html_response(400, render::render_error(&inst.config, &e.to_string())),
    }
}

async fn handle_edit_form(
    inst: &AdminInstance,
    ctx: &RequestCtx,
    req: &HttpRequest,
) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let id = req.param("id").unwrap_or_default().to_owned();
    match inst.data_source.get(&model, &id).await {
        Some(record) => {
            let view = EditView::new(&model, id)
                .with_data(record)
                .with_csrf_token(&ctx.csrf_token);
            HttpResponse::html(render::render_edit(&view, &inst.config))
        }
        None => html_response(404, render::render_not_found(&inst.config)),
    }
}

async fn handle_update_submit(inst: &AdminInstance, req: &HttpRequest) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let id = req.param("id").unwrap_or_default().to_owned();
    if !model.can_edit {
        return html_response(403, render::render_forbidden(&inst.config));
    }
    let data = match parse_submission(&model, req) {
        Ok(data) => data,
        Err(msg) => return html_response(400, render::render_error(&inst.config, &msg)),
    };
    match inst.data_source.update(&model, &id, data).await {
        Ok(()) => {
            HttpResponse::redirect(format!("{}/{}/{}", inst.config.base_path, model.name, id))
        }
        Err(e) => html_response(400, render::render_error(&inst.config, &e.to_string())),
    }
}

async fn handle_delete(inst: &AdminInstance, req: &HttpRequest) -> HttpResponse {
    let model = match resolve_model(inst, req) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let id = req.param("id").unwrap_or_default().to_owned();
    if !model.can_delete {
        return html_response(403, render::render_forbidden(&inst.config));
    }
    match inst.data_source.delete(&model, &id).await {
        Ok(()) => HttpResponse::redirect(format!("{}/{}", inst.config.base_path, model.name)),
        Err(e) => html_response(404, render::render_error(&inst.config, &e.to_string())),
    }
}

/// Parameters for list view
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListParams {
    /// Current page (1-indexed)
    pub page: Option<usize>,
    /// Items per page
    pub per_page: Option<usize>,
    /// Sort field
    pub sort: Option<String>,
    /// Sort direction
    pub order: Option<SortOrder>,
    /// Search query
    pub search: Option<String>,
    /// Filters
    pub filters: HashMap<String, String>,
}

impl ListParams {
    /// Get effective page number
    pub fn page(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }

    /// Resolve the effective page size, honoring the requested `per_page`, the
    /// config default (`items_per_page`), and the cap (`max_items_per_page`).
    pub fn resolve_per_page(&self, config: &AdminConfig) -> usize {
        let cap = config.max_items_per_page.max(1);
        self.per_page.unwrap_or(config.items_per_page).clamp(1, cap)
    }

    /// Compute the row offset for a resolved page size.
    pub fn resolve_offset(&self, per_page: usize) -> usize {
        (self.page() - 1) * per_page
    }
}

/// Sort order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortOrder {
    #[default]
    Asc,
    Desc,
}

impl SortOrder {
    /// Get SQL representation
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }

    /// Toggle order
    pub fn toggle(&self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_builder() {
        let admin = Admin::new()
            .title("Test Admin")
            .base_path("/admin")
            .items_per_page(25)
            .build();

        assert_eq!(admin.config.title, "Test Admin");
        assert_eq!(admin.config.base_path, "/admin");
        assert_eq!(admin.config.items_per_page, 25);
    }

    #[test]
    fn test_list_params() {
        let params = ListParams {
            page: Some(2),
            per_page: Some(20),
            ..Default::default()
        };

        assert_eq!(params.page(), 2);
        assert_eq!(params.resolve_per_page(&AdminConfig::default()), 20);
        assert_eq!(params.resolve_offset(20), 20);
    }

    #[test]
    fn test_sort_order() {
        assert_eq!(SortOrder::Asc.toggle(), SortOrder::Desc);
        assert_eq!(SortOrder::Desc.toggle(), SortOrder::Asc);
    }

    // ---- Router regression tests ----

    use armature_core::HttpRequest;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const NONCE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn user_model() -> ModelDefinition {
        ModelDefinition::builder("user")
            .id_field()
            .field(FieldDefinition::new("name", FieldType::String).searchable())
            .search_fields(["name"])
            .list_display(["id", "name"])
            .build()
    }

    /// Admits `X-Test-Admin: root`, forbids any other value, rejects absence.
    fn test_auth() -> Arc<dyn AdminAuthenticator> {
        Arc::new(
            |req: &HttpRequest| match req.headers.get("x-test-admin").map(|v| v.to_string()) {
                Some(id) if id == "root" => Ok(AdminPrincipal::new(id)),
                Some(_) => Err(AdminAuthError::Forbidden),
                None => Err(AdminAuthError::Unauthenticated),
            },
        )
    }

    fn secure(admin: Admin) -> Admin {
        admin.authenticator(test_auth()).csrf_secret(SECRET)
    }

    fn anon(method: &str, path: &str) -> HttpRequest {
        HttpRequest::new(method.to_string(), path.to_string())
    }

    /// An authenticated admin request (no CSRF token).
    fn req(method: &str, path: &str) -> HttpRequest {
        let mut r = anon(method, path);
        r.headers.insert("X-Test-Admin", "root");
        r
    }

    fn csrf_token() -> String {
        CsrfProtection::new(CsrfConfig::new(SECRET).unwrap()).token_for(NONCE, "root")
    }

    /// An authenticated admin request carrying a valid CSRF cookie + header.
    fn csrf_req(method: &str, path: &str) -> HttpRequest {
        let mut r = req(method, path);
        r.headers
            .insert("Cookie", format!("__Host-armature-csrf={NONCE}"));
        r.headers.insert("X-CSRF-Token", csrf_token());
        r
    }

    /// A form POST carrying the CSRF token in the `_csrf` field.
    fn form_post(path: &str, body: &str) -> HttpRequest {
        let mut r = req("POST", path);
        r.headers
            .insert("Cookie", format!("__Host-armature-csrf={NONCE}"));
        r.headers
            .insert("Content-Type", "application/x-www-form-urlencoded");
        r.set_body(format!("{body}&_csrf={}", csrf_token()).into_bytes());
        r
    }

    fn body(resp: &HttpResponse) -> String {
        String::from_utf8(resp.body.to_vec()).unwrap()
    }

    #[test]
    fn routes_refuse_to_build_without_authenticator_or_csrf() {
        let no_auth = Admin::new().csrf_secret(SECRET).build();
        assert!(matches!(no_auth.routes(), Err(AdminError::Config(_))));

        let no_csrf = Admin::new().authenticator(test_auth()).build();
        assert!(matches!(no_csrf.routes(), Err(AdminError::Config(_))));

        let weak = Admin::new()
            .authenticator(test_auth())
            .csrf_secret("short")
            .build();
        assert!(matches!(weak.routes(), Err(AdminError::Config(_))));

        assert!(secure(Admin::new()).build().routes().is_ok());
    }

    /// `routes()` must return a real router with registered, responding routes.
    #[tokio::test]
    async fn routes_are_registered_and_respond() {
        let admin = secure(Admin::new()).register_model(user_model()).build();

        let router = admin.routes().unwrap();
        assert!(
            router.routes.len() >= 6,
            "expected multiple registered routes, got {}",
            router.routes.len()
        );

        for path in ["/admin", "/admin/user", "/admin/user/add"] {
            let resp = router.route(req("GET", path)).await.unwrap();
            assert_eq!(resp.status, 200, "route {path} should respond 200");
            assert!(!resp.body.is_empty(), "route {path} should have a body");
        }
    }

    /// The authenticator guards every route; a header's mere presence is not
    /// authentication.
    #[tokio::test]
    async fn authenticator_guards_routes() {
        let admin = secure(Admin::new()).register_model(user_model()).build();
        let router = admin.routes().unwrap();

        let resp = router.route(anon("GET", "/admin/user")).await.unwrap();
        assert_eq!(resp.status, 401, "unauthenticated request must be blocked");

        // Any `Authorization` value used to be accepted.
        let mut forged = anon("GET", "/admin/user");
        forged.headers.insert("Authorization", "x");
        let resp = router.route(forged).await.unwrap();
        assert_eq!(resp.status, 401);

        // Authenticated, but not an administrator.
        let mut user = anon("GET", "/admin/user");
        user.headers.insert("X-Test-Admin", "mallory");
        let resp = router.route(user).await.unwrap();
        assert_eq!(resp.status, 403);

        let resp = router.route(req("GET", "/admin/user")).await.unwrap();
        assert_eq!(resp.status, 200, "authenticated admin must pass");
    }

    #[tokio::test]
    async fn every_response_is_no_store() {
        let admin = secure(Admin::new()).register_model(user_model()).build();
        let router = admin.routes().unwrap();

        for r in [
            req("GET", "/admin"),
            req("GET", "/admin/user"),
            req("GET", "/admin/nope"),
            anon("GET", "/admin/user"),
            req("POST", "/admin/user/add"),
        ] {
            let resp = router.route(r).await.unwrap();
            assert_eq!(
                resp.headers.get("Cache-Control"),
                Some(&"no-store".to_string()),
                "status {} must be no-store",
                resp.status
            );
        }
    }

    #[tokio::test]
    async fn state_changing_requests_require_csrf() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));
        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        // No token at all.
        let mut r = req("POST", "/admin/user/1/delete");
        r.headers
            .insert("Cookie", format!("__Host-armature-csrf={NONCE}"));
        assert_eq!(router.route(r).await.unwrap().status, 403);

        // Token for a different administrator.
        let mut r = req("POST", "/admin/user/1/delete");
        r.headers
            .insert("Cookie", format!("__Host-armature-csrf={NONCE}"));
        r.headers.insert(
            "X-CSRF-Token",
            CsrfProtection::new(CsrfConfig::new(SECRET).unwrap()).token_for(NONCE, "other"),
        );
        assert_eq!(router.route(r).await.unwrap().status, 403);

        // DELETE without a token.
        let resp = router.route(req("DELETE", "/admin/user/1")).await.unwrap();
        assert_eq!(resp.status, 403);

        assert!(
            ds.get(&user_model(), "1").await.is_some(),
            "nothing deleted"
        );

        // Valid token.
        let resp = router
            .route(csrf_req("POST", "/admin/user/1/delete"))
            .await
            .unwrap();
        assert!((300..400).contains(&resp.status));
        assert!(ds.get(&user_model(), "1").await.is_none());
    }

    /// Forms carry a working `_csrf` field and the first visit sets the cookie.
    #[tokio::test]
    async fn forms_embed_csrf_token() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));
        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        for path in ["/admin/user/add", "/admin/user/1/edit", "/admin/user/1"] {
            let resp = router.route(req("GET", path)).await.unwrap();
            assert_eq!(resp.status, 200);
            assert!(
                body(&resp).contains("name=\"_csrf\""),
                "{path} must render a _csrf field"
            );
            assert_eq!(resp.cookies.len(), 1, "{path} must set the CSRF cookie");
            assert!(resp.cookies[0].contains("SameSite=Strict"));
        }

        // With the cookie present the rendered token is the one the server
        // will accept, and no new cookie is minted.
        let mut r = req("GET", "/admin/user/add");
        r.headers
            .insert("Cookie", format!("__Host-armature-csrf={NONCE}"));
        let resp = router.route(r).await.unwrap();
        assert!(resp.cookies.is_empty());
        assert!(body(&resp).contains(&csrf_token()));
    }

    /// A stub data source must populate list rows.
    #[tokio::test]
    async fn stub_data_source_populates_rows() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": 1, "name": "Alice" }));
        ds.seed("user", serde_json::json!({ "id": 2, "name": "Bob" }));

        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();

        let resp = admin
            .routes()
            .unwrap()
            .route(req("GET", "/admin/user"))
            .await
            .unwrap();
        let body = body(&resp);
        assert!(
            body.contains("Alice"),
            "list body should contain seeded rows"
        );
        assert!(body.contains("Bob"));
    }

    /// Pagination must honor `per_page` and cap at `max_items_per_page`.
    #[tokio::test]
    async fn pagination_respects_per_page_and_max() {
        let ds = Arc::new(InMemoryDataSource::new());
        for i in 0..30 {
            ds.seed(
                "user",
                serde_json::json!({ "id": i, "name": format!("u{i}") }),
            );
        }

        let admin = secure(Admin::new())
            .items_per_page(10)
            .max_items_per_page(5)
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        let resp = router
            .route(req("GET", "/admin/user?per_page=3"))
            .await
            .unwrap();
        let row_count = body(&resp).matches("<tr>").count() - 1; // minus header row
        assert_eq!(row_count, 3, "per_page=3 must return 3 rows");

        let resp = router
            .route(req("GET", "/admin/user?per_page=1000"))
            .await
            .unwrap();
        let row_count = body(&resp).matches("<tr>").count() - 1;
        assert_eq!(
            row_count, 5,
            "per_page must be capped at max_items_per_page"
        );
    }

    #[tokio::test]
    async fn sort_and_filter_keys_must_be_declared() {
        let model = ModelDefinition::builder("user")
            .id_field()
            .field(FieldDefinition::new("name", FieldType::String))
            .field(FieldDefinition::new("status", FieldType::String))
            .list_filter(["status"])
            .build();
        let admin = secure(Admin::new()).register_model(model).build();
        let router = admin.routes().unwrap();

        for path in [
            "/admin/user?sort=name",
            "/admin/user?sort=name&order=desc",
            "/admin/user?filter.status=active",
        ] {
            let resp = router.route(req("GET", path)).await.unwrap();
            assert_eq!(resp.status, 200, "{path}");
        }

        for path in [
            "/admin/user?sort=name;DROP%20TABLE%20users",
            "/admin/user?sort=undeclared",
            "/admin/user?filter.name=Alice",
            "/admin/user?filter.1%3D1%20OR%20id=1",
        ] {
            let resp = router.route(req("GET", path)).await.unwrap();
            assert_eq!(resp.status, 400, "{path} must be rejected");
        }
    }

    /// Update and delete handlers must mutate the data source.
    #[tokio::test]
    async fn update_and_delete_handlers_work() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));

        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        let resp = router
            .route(form_post("/admin/user/1/edit", "name=Renamed"))
            .await
            .unwrap();
        assert!(
            (300..400).contains(&resp.status),
            "successful update should redirect, got {}",
            resp.status
        );
        assert_eq!(ds.get(&user_model(), "1").await.unwrap()["name"], "Renamed");

        let resp = router
            .route(csrf_req("POST", "/admin/user/1/delete"))
            .await
            .unwrap();
        assert!((300..400).contains(&resp.status));
        assert!(ds.get(&user_model(), "1").await.is_none());
    }

    fn account_model() -> ModelDefinition {
        ModelDefinition::builder("account")
            .id_field()
            .field(FieldDefinition::new("name", FieldType::String))
            .field(FieldDefinition::new("role", FieldType::String))
            .field(FieldDefinition::new("password_hash", FieldType::String))
            .field(FieldDefinition::new("api_token", FieldType::String))
            .readonly_fields(["role"])
            .list_display(["id", "name", "password_hash"])
            .build()
    }

    #[tokio::test]
    async fn only_editable_fields_are_written() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed(
            "account",
            serde_json::json!({ "id": "1", "name": "A", "role": "user", "password_hash": "h" }),
        );
        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(account_model())
            .build();
        let router = admin.routes().unwrap();

        // Mass assignment through a form: PK, readonly, sensitive and
        // undeclared keys are dropped.
        let resp = router
            .route(form_post(
                "/admin/account/1/edit",
                "name=B&role=admin&password_hash=x&api_token=t&is_superuser=true",
            ))
            .await
            .unwrap();
        assert!((300..400).contains(&resp.status));
        let row = ds.get(&account_model(), "1").await.unwrap();
        assert_eq!(row["name"], "B");
        assert_eq!(row["role"], "user");
        assert_eq!(row["password_hash"], "h");
        assert!(row.get("api_token").is_none());
        assert!(row.get("is_superuser").is_none());
        assert!(row.get("_csrf").is_none());

        // Same through JSON, plus an attempt to choose the PK on create.
        let mut r = csrf_req("POST", "/admin/account/add");
        r.headers.insert("Content-Type", "application/json");
        r.set_body(br#"{"id":"admin","name":"C","role":"admin"}"#.to_vec());
        let resp = router.route(r).await.unwrap();
        assert!((300..400).contains(&resp.status));
        assert!(ds.get(&account_model(), "admin").await.is_none());
        let created = ds
            .list(&account_model(), &DataQuery::default())
            .await
            .rows
            .into_iter()
            .find(|r| r["name"] == "C")
            .unwrap();
        assert!(created.get("role").is_none());
    }

    #[tokio::test]
    async fn non_object_json_is_rejected() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));
        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        for payload in [r#"["x"]"#, r#""x""#, "42", "not json"] {
            let mut r = csrf_req("POST", "/admin/user/1/edit");
            r.headers.insert("Content-Type", "application/json");
            r.set_body(payload.as_bytes().to_vec());
            let resp = router.route(r).await.unwrap();
            assert_eq!(resp.status, 400, "{payload} must be rejected");
        }
        assert_eq!(ds.get(&user_model(), "1").await.unwrap()["name"], "Alice");
    }

    #[tokio::test]
    async fn sensitive_fields_are_never_rendered() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed(
            "account",
            serde_json::json!({
                "id": "1", "name": "A", "role": "user",
                "password_hash": "HASHVALUE", "api_token": "TOKENVALUE",
                "internal_note": "UNDECLARED",
            }),
        );
        let admin = secure(Admin::new())
            .enable_export(true)
            .data_source(ds.clone())
            .register_model(account_model())
            .build();
        let router = admin.routes().unwrap();

        for path in [
            "/admin/account",
            "/admin/account/1",
            "/admin/account/1/edit",
            "/admin/account?export=csv",
        ] {
            let resp = router.route(req("GET", path)).await.unwrap();
            assert_eq!(resp.status, 200, "{path}");
            let b = body(&resp);
            for secret in [
                "HASHVALUE",
                "TOKENVALUE",
                "UNDECLARED",
                "password_hash",
                "Password Hash",
            ] {
                assert!(!b.contains(secret), "{path} leaked {secret}");
            }
        }

        // Sorting / filtering on a sensitive column is not an oracle either.
        let resp = router
            .route(req("GET", "/admin/account?sort=password_hash"))
            .await
            .unwrap();
        assert_eq!(resp.status, 400);
    }

    #[tokio::test]
    async fn export_is_disabled_by_default() {
        let admin = secure(Admin::new()).register_model(user_model()).build();
        let router = admin.routes().unwrap();
        let resp = router
            .route(req("GET", "/admin/user?export=csv"))
            .await
            .unwrap();
        assert_eq!(resp.status, 403);
        let resp = router.route(req("GET", "/admin/user")).await.unwrap();
        assert!(!body(&resp).contains("export=csv"), "no export link");
    }

    /// The Export control must produce real CSV of the current query.
    #[tokio::test]
    async fn export_csv_returns_csv_rows() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));
        ds.seed("user", serde_json::json!({ "id": "2", "name": "Bob" }));

        let admin = secure(Admin::new())
            .enable_export(true)
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        let resp = router
            .route(req("GET", "/admin/user?export=csv"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        let ct = resp
            .headers
            .get("Content-Type")
            .cloned()
            .unwrap_or_default();
        assert!(ct.contains("text/csv"), "export must be served as CSV");
        let b = body(&resp);
        assert!(!b.contains("<table"), "CSV export must not re-render HTML");
        assert!(b.contains("\"Alice\""));
        assert!(b.contains("\"Bob\""));
        assert!(b.lines().count() >= 3, "header + two data rows");

        let resp = router
            .route(req("GET", "/admin/user?export=csv&search=Alice"))
            .await
            .unwrap();
        let b = body(&resp);
        assert!(b.contains("Alice"));
        assert!(!b.contains("Bob"), "CSV export must honor the search query");
    }

    #[tokio::test]
    async fn export_is_capped() {
        let ds = Arc::new(InMemoryDataSource::new());
        for i in 0..10 {
            ds.seed(
                "user",
                serde_json::json!({ "id": i, "name": format!("u{i}") }),
            );
        }
        let admin = secure(Admin::new())
            .enable_export(true)
            .export_max_rows(3)
            .data_source(ds)
            .register_model(user_model())
            .build();
        let resp = admin
            .routes()
            .unwrap()
            .route(req("GET", "/admin/user?export=csv"))
            .await
            .unwrap();
        assert_eq!(body(&resp).lines().count(), 4, "header + 3 capped rows");
        assert_eq!(
            resp.headers.get("X-Export-Truncated"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn csv_fields_are_quoted_and_formulas_neutralized() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        for lead in ["+", "-", "@", "\t", "\r"] {
            let v = format!("{lead}cmd");
            assert_eq!(csv_field(&v), format!("\"'{v}\""));
        }
    }

    /// End-to-end: the search box rendered on the list page must drive filtering.
    #[tokio::test]
    async fn search_form_param_filters_end_to_end() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));
        ds.seed("user", serde_json::json!({ "id": "2", "name": "Bob" }));

        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();
        let router = admin.routes().unwrap();

        let resp = router.route(req("GET", "/admin/user")).await.unwrap();
        let b = body(&resp);
        let form = b
            .split("admin-search")
            .nth(1)
            .expect("search form must be rendered");
        let after = form
            .split("name=\"")
            .nth(1)
            .expect("input must have a name");
        let param = &after[..after.find('"').unwrap()];
        assert_eq!(param, "search");

        let path = format!("/admin/user?{param}=Alice");
        let resp = router.route(req("GET", &path)).await.unwrap();
        let b = body(&resp);
        assert!(b.contains("Alice"), "search must keep the matching row");
        assert!(
            !b.contains("Bob"),
            "search must filter out non-matching rows"
        );
    }

    /// The edit route must render an EditView.
    #[tokio::test]
    async fn edit_form_renders() {
        let ds = Arc::new(InMemoryDataSource::new());
        ds.seed("user", serde_json::json!({ "id": "1", "name": "Alice" }));

        let admin = secure(Admin::new())
            .data_source(ds.clone())
            .register_model(user_model())
            .build();

        let resp = admin
            .routes()
            .unwrap()
            .route(req("GET", "/admin/user/1/edit"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        let b = body(&resp);
        assert!(b.contains("Alice"), "edit form should prefill values");
        assert!(b.contains("<form"), "edit form should render a form");
    }
}
