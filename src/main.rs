use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::{MatchedPath, Path, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use error::Errors;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{prelude::FromRow, PgPool};
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{debug, error, info, info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuidv4::uuid;

mod error;


#[derive(Clone)]
struct AppState {
    db: Arc<PgPool>,
}

impl AppState {
    async fn new(url: &str) -> Result<AppState, Errors> {
        let pool = sqlx::PgPool::connect(url).await?;

        info!("Database connection success!!!");

        Ok(AppState { db: Arc::new(pool) })
    }
}

#[derive(Serialize, Deserialize, FromRow)]
struct User {
    #[sqlx(rename = "user_name")]
    name: String,

    #[sqlx(rename = "user_email")]
    email: String,

    #[sqlx(rename = "user_password")]
    password: String,

    #[sqlx(rename = "user_phone")]
    phone: String,

    #[sqlx(rename = "user_address")]
    address: String,
}

impl IntoResponse for User {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[derive(Deserialize, Debug)]
struct EditUser {
    name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address: Option<String>,
}

impl EditUser {
    fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.email.is_none()
            && self.phone.is_none()
            && self.address.is_none()
    }
}

#[tokio::main]
async fn main() -> Result<(), Errors> {
    let _ = dotenv::dotenv();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").map_err(|e| Errors::from(e));

    let app_state = AppState::new(&database_url?)
        .await
        .map_err(|e| Errors::from(e));

    let app = Router::new()
        .route("/users", get(get_all).post(create))
        .route("/users/:id", get(get_user).delete(delete).patch(update))
        .route("/health_check", get(health_check))
        .with_state(app_state?)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);
                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        some_other_field = tracing::field::Empty,
                    )
                })
                .on_request(|request: &Request<_>, span: &Span| {
                    let request_id = uuid::v4();
                    span.record("request_id", &request_id.to_string());
                    info!("Received request: {:?}", request);
                })
                .on_response(|response: &Response, latency: Duration, span: &Span| {
                    span.record("status", &response.status().as_u16());
                    info!(
                        "Response sent with status: {} in {:?}",
                        response.status(),
                        latency
                    );
                })
                .on_body_chunk(|chunk: &Bytes, latency: Duration, span: &Span| {
                    span.record("chunk_size", &chunk.len());
                    debug!("Chunk of size {} received in {:?}", chunk.len(), latency);
                })
                .on_eos(
                    |_trailers: Option<&HeaderMap>, stream_duration: Duration, _span: &Span| {
                        info!("End of stream reached after {:?}", stream_duration);
                    },
                )
                .on_failure(
                    |_error: ServerErrorsFailureClass, latency: Duration, _span: &Span| {
                        error!("Request failed after {:?}", latency);
                    },
                ),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listner) => {
            info!("Server start on: {}", listner.local_addr().unwrap());
            if let Err(err) = axum::serve(listner, app).await {
                tracing::error!("{}", Errors::from(err))
            }
        }
        Err(err) => {
            tracing::error!("{}", Errors::from(err))
        }
    }

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    info!("Now it's running");
    StatusCode::OK
}

async fn get_all(
    State(db): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, impl IntoResponse)> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&*db.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Errors::from(e)))?;

    Ok(Json(users))
}

async fn create(
    State(db): State<AppState>,
    Json(new_user): Json<User>,
) -> Result<impl IntoResponse, (StatusCode, impl IntoResponse)> {
    sqlx::query("INSERT INTO users (user_name, user_email, user_password, user_phone, user_address) VALUES ($1,$2,$3,$4,$5)")
    .bind(new_user.name)
    .bind(new_user.email)
    .bind(new_user.password)
    .bind(new_user.phone)
    .bind(new_user.address)
    .execute(&*db.db)
    .await
    .map_err(|e|{
        (
            StatusCode::BAD_REQUEST,
            Errors::from(e)
        )
    })?;

    Ok(StatusCode::CREATED)
}

async fn get_user(
    State(db): State<AppState>,
    Path(id): Path<i32>,
) -> Result<impl IntoResponse, (StatusCode, impl IntoResponse)> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE user_id = $1")
        .bind(id)
        .fetch_one(&*db.db)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Errors::from(e)))?;

    Ok(Json(user))
}

async fn delete(
    State(db): State<AppState>,
    Path(id): Path<i32>,
) -> Result<StatusCode, (StatusCode, impl IntoResponse)> {
    sqlx::query("DELETE FROM users WHERE user_id = $1")
        .bind(id)
        .execute(&*db.db)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Errors::from(e)))?;

    Ok(StatusCode::OK)
}

async fn update(
    Path(id): Path<i32>,
    State(db): State<AppState>,
    Json(update_data): Json<EditUser>, 
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if update_data.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST, 
            Json(json!({"error": "No update fields provided"}))
        ));
    }

    let mut user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE user_id = $1")
        .bind(id)
        .fetch_one(&*db.db)
        .await
        .map_err(|e| {
            error!("{}", Errors::from(e));
            (
                StatusCode::NOT_FOUND, 
                Json(json!({"error": "User not found"}))
            )
        })?;
    
    if let Some(name) = update_data.name {
        user.name = name;
    }

    if let Some(email) = update_data.email {
        user.email = email;
    }

    if let Some(address) = update_data.address {
        user.address = address;
    }

    if let Some(phone) = update_data.phone {
        user.phone = phone;
    }

    sqlx::query("UPDATE users SET user_name = $1, user_email = $2, user_phone = $3, user_address = $4 WHERE user_id = $5")
        .bind(&user.name)
        .bind(&user.email)
        .bind(&user.phone)
        .bind(&user.address)
        .bind(id)
        .execute(&*db.db)
        .await
        .map_err(|e| {
            error!("{}", Errors::from(e));
            (
                StatusCode::INTERNAL_SERVER_ERROR, 
                Json(json!({"error": "Failed to update user"}))
            )
        })?;

    Ok(Json(user))
}
