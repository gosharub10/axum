use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{body::Bytes, extract::{MatchedPath, State}, http::{HeaderMap, Request, StatusCode}, response::{IntoResponse, Response}, routing::get, Json, Router};
use error::Errors;
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, PgPool};
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{debug, error, info, info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuidv4::uuid;

mod error;


#[derive(Clone)]
struct AppState{
    db: Arc<PgPool>
}

impl AppState {
    async  fn new(url: &str) -> Result<AppState, Errors> {
        let pool = sqlx::PgPool::connect(url).await?;

        info!("Database connection success!!!");

        Ok(AppState{
            db: Arc::new(pool)
        })
    }
}

#[derive(Serialize, Deserialize, FromRow)]
struct User{
    name : String,
    email: String,
    password: String,
    phone: String,
    address: String
}


#[tokio::main]
async fn main() -> Result<(), Errors>{
    let _ = dotenv::dotenv();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| { format!("{}=debug,tower_http=debug,axum::rejection=trace",
        env!("CARGO_CRATE_NAME"))
        .into()}),)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").map_err(|e| Errors::from(e));

    let app_state = AppState::new(&database_url?).await.map_err(|e| Errors::from(e));

    let app = Router::new()
        .route("/users", get(get_all))
        .route("/health_check", get(health_check))
        .with_state(app_state?)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let matched_path = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);
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
                    info!("Response sent with status: {} in {:?}", response.status(), latency);
                })
                .on_body_chunk(|chunk: &Bytes, latency: Duration, span: &Span| {
                    span.record("chunk_size", &chunk.len());
                    debug!("Chunk of size {} received in {:?}", chunk.len(), latency);
                })
                .on_eos(|_trailers: Option<&HeaderMap>, stream_duration: Duration, _span: &Span| {
                    info!("End of stream reached after {:?}", stream_duration);
                })
                .on_failure(|_error: ServerErrorsFailureClass, latency: Duration, _span: &Span| {
                    error!("Request failed after {:?}", latency);
                }),
        );

    let addr = SocketAddr::from(([0,0,0,0], 3000));

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

async fn health_check() -> impl IntoResponse{
    info!("Now it's running");
    StatusCode::OK
}

async fn get_all(State(db): State<AppState>) -> Result<impl IntoResponse ,(StatusCode, impl IntoResponse)>{
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
    .fetch_all(&*db.db)
    .await
    .map_err(|e|{
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{}", Errors::from(e))
        )
    })?;

    Ok(Json(users))
}

//TODO сделать простейшие CRUD для работы с базой данных