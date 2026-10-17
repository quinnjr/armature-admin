//! Authentication and authorization for the admin interface.
//!
//! The admin router does not trust anything about a request until an
//! [`AdminAuthenticator`] has verified *who* is calling and that they are an
//! administrator. [`crate::AdminInstance::routes`] refuses to build a router
//! without one, so the panel can never be mounted unauthenticated.

use armature_core::HttpRequest;
use async_trait::async_trait;

/// A verified administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPrincipal {
    /// Stable, unique identifier of the administrator (user id, subject).
    /// CSRF tokens are bound to it.
    pub id: String,
    /// Optional human-readable name.
    pub display_name: Option<String>,
}

impl AdminPrincipal {
    /// Create a principal with the given id.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: None,
        }
    }

    /// Set the display name.
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }
}

/// Why a request was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAuthError {
    /// No valid identity (missing, expired or forged credentials) — `401`.
    Unauthenticated,
    /// A verified identity without admin rights — `403`.
    Forbidden,
}

/// Verifies the caller's identity **and** admin authorization for every admin
/// request.
///
/// Implementations must check a real credential (a verified session, a
/// signature-checked JWT, ...) — the presence of a header proves nothing — and
/// must confirm the identity is allowed to administer the application.
///
/// A plain function or closure `Fn(&HttpRequest) -> Result<AdminPrincipal,
/// AdminAuthError>` implements this trait. A typical implementation reads the
/// verified principal an authentication middleware placed in the request
/// extensions (for example `armature_auth::UserContext`, attached by
/// `JwtAuthMiddleware`) and checks its role:
///
/// ```ignore
/// use armature_admin::{AdminAuthError, AdminPrincipal};
/// use armature_auth::UserContext;
///
/// let authenticator = |req: &armature_core::HttpRequest| {
///     let user = req
///         .extension::<UserContext>()
///         .ok_or(AdminAuthError::Unauthenticated)?;
///     if user.roles.iter().any(|r| r == "admin") {
///         Ok(AdminPrincipal::new(user.user_id.clone()))
///     } else {
///         Err(AdminAuthError::Forbidden)
///     }
/// };
/// ```
#[async_trait]
pub trait AdminAuthenticator: Send + Sync {
    /// Authenticate and authorize `request`.
    async fn authenticate(&self, request: &HttpRequest) -> Result<AdminPrincipal, AdminAuthError>;
}

#[async_trait]
impl<F> AdminAuthenticator for F
where
    F: Fn(&HttpRequest) -> Result<AdminPrincipal, AdminAuthError> + Send + Sync,
{
    async fn authenticate(&self, request: &HttpRequest) -> Result<AdminPrincipal, AdminAuthError> {
        self(request)
    }
}
