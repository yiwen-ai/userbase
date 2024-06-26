use axum::{
    middleware,
    response::{IntoResponse, Response},
    routing, Router,
};
use std::{fs, sync::Arc, time::Duration};
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{predicate::SizeAbove, CompressionLayer},
    // cors::CorsLayer,
    timeout::TimeoutLayer,
};

use axum_web::context;
use axum_web::encoding;
use axum_web::erring;

use crate::api;
use crate::conf;
use crate::crypto;
use crate::db;

pub async fn todo() -> Response {
    (erring::HTTPError::new(501, "TODO".to_string())).into_response()
}

pub async fn new(cfg: conf::Conf) -> anyhow::Result<(Arc<api::AppState>, Router)> {
    let app_state = Arc::new(new_app_state(cfg).await?);

    let app = Router::new()
        .route("/", routing::get(api::version))
        .route("/healthz", routing::get(api::healthz))
        .nest(
            "/v1/session",
            Router::new()
                .route(
                    "/",
                    routing::get(api::session::get).delete(api::session::delete),
                )
                .route("/min_verify", routing::post(api::session::min_verify))
                .route("/verify", routing::post(api::session::verify))
                .route("/renew_token", routing::post(api::session::renew_token))
                .route(
                    "/min_verify_token",
                    routing::get(api::session::min_verify_token),
                )
                .route("/verify_token", routing::get(api::session::verify_token))
                .route("/forward_auth", routing::get(api::session::forward_auth))
                .route("/list", routing::get(api::session::list)),
        )
        .nest(
            "/v1/authn",
            Router::new()
                .route(
                    "/",
                    routing::get(api::authn::get).delete(api::authn::delete),
                )
                .route("/login_or_new", routing::post(api::authn::login_or_new))
                .route("/list", routing::get(api::authn::list)),
        )
        .nest(
            "/v1/passkey",
            Router::new()
                .route("/get_challenge", routing::get(api::passkey::get_challenge))
                .route(
                    "/verify_registration",
                    routing::post(api::passkey::verify_registration),
                )
                .route(
                    "/verify_authentication",
                    routing::post(api::passkey::verify_authentication),
                ),
        )
        .nest(
            "/v1/oauth",
            Router::new()
                .route("/authorize", routing::get(todo))
                .route("/access_token", routing::get(todo)),
        )
        .nest(
            "/v1/user",
            Router::new()
                .route("/", routing::get(api::user::get).patch(api::user::update))
                .route("/batch_get_info", routing::post(api::user::batch_get_info))
                .route("/update_email", routing::patch(api::user::update_email))
                .route("/update_phone", routing::patch(api::user::update_phone))
                .route("/derive_key", routing::post(api::user::derive_key)),
        )
        .nest(
            "/v1/group",
            Router::new()
                .route(
                    "/",
                    routing::post(api::group::create)
                        .get(api::group::get)
                        .patch(api::group::update),
                )
                .route("/batch_get_info", routing::post(api::group::batch_get_info))
                .route("/update_status", routing::patch(api::group::update_status))
                .route("/update_kind", routing::patch(api::group::update_kind))
                .route("/update_email", routing::patch(api::group::update_email))
                .route("/follow", routing::patch(api::group::follow))
                .route("/unfollow", routing::patch(api::group::unfollow))
                .route("/get_by_user", routing::get(api::group::get_by_user))
                .route("/list_users", routing::post(api::group::list_users))
                .route("/list_members", routing::post(api::group::list_members))
                .route("/list_by_user", routing::post(api::group::list_by_user))
                .route("/list_following", routing::post(api::group::list_following))
                .route("/following_ids", routing::get(api::group::following_ids))
                .nest(
                    "/member",
                    Router::new()
                        .route(
                            "/",
                            routing::post(api::member::create).delete(api::member::delete),
                        )
                        .route("/update_role", routing::patch(api::member::update_role))
                        .route(
                            "/update_priority",
                            routing::patch(api::member::update_priority),
                        ),
                ),
        )
        .nest(
            "/v1/sys",
            Router::new()
                .route("/user", routing::post(api::user::create))
                .route("/user/update_kind", routing::patch(api::user::update_kind))
                .route(
                    "/user/update_status",
                    routing::patch(api::user::update_status),
                )
                .route(
                    "/user/update_rating",
                    routing::patch(api::user::update_rating),
                )
                .route(
                    "/group/update_status",
                    routing::patch(api::group::update_status),
                )
                .route(
                    "/group/update_kind",
                    routing::patch(api::group::update_kind),
                ),
        )
        .layer((
            CatchPanicLayer::new(),
            TimeoutLayer::new(Duration::from_secs(10)),
            // CorsLayer::very_permissive(),
            middleware::from_fn(context::middleware),
            CompressionLayer::new().compress_when(SizeAbove::new(encoding::MIN_ENCODING_SIZE)),
        ))
        .with_state(app_state.clone());

    Ok((app_state, app))
}

async fn new_app_state(cfg: conf::Conf) -> anyhow::Result<api::AppState> {
    let aad = cfg.keys.aad.as_bytes();
    let decryptor = {
        // Should use KMS on production.
        let mkek = std::env::var("YIWEN_MKEK")
            .unwrap_or("YiWenAI-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-LLc".to_string()); // default to test key
        let mkek = crypto::base64url_decode(&mkek)?;
        let decryptor = crypto::Encrypt0::new(mkek.try_into().unwrap(), b"");

        let kek = read_key(&decryptor, aad, &cfg.keys.kek)?;
        crypto::Encrypt0::new(kek.get_private()?, b"")
    };

    let (mac_id, mac_state) = {
        let id_key = read_key(&decryptor, aad, &fs::read_to_string(cfg.keys.id_key_file)?)?;
        let secret = id_key.get_private()?;
        (crypto::MacId::new(secret), crypto::MacState::new(secret))
    };

    let session = {
        let session_key = read_key(
            &decryptor,
            aad,
            &fs::read_to_string(cfg.keys.session_key_file)?,
        )?;
        crypto::Session::new(session_key.get_private()?)
    };

    let cwt = {
        let token_key = read_key(
            &decryptor,
            aad,
            &fs::read_to_string(cfg.keys.token_key_file)?,
        )?;
        crypto::Cwt::new(
            token_key.get_private()?,
            cfg.keys.issuer.as_str(),
            &token_key.key_id(),
            aad,
        )
    };

    let scylla = { db::scylladb::ScyllaDB::new(cfg.scylla).await? };

    Ok(api::AppState {
        start_at: context::unix_ms(),
        session_name_prefix: cfg.session_name_prefix,
        passkey: cfg.passkey,
        mac_id: Arc::new(mac_id),
        mac_state: Arc::new(mac_state),
        session: Arc::new(session),
        cwt: Arc::new(cwt),
        scylla: Arc::new(scylla),
    })
}

fn read_key(
    decryptor: &crypto::Encrypt0,
    aad: &[u8],
    ciphertext: &str,
) -> anyhow::Result<crypto::Key> {
    let key = crypto::base64url_decode(ciphertext.trim())?;
    let key = decryptor.decrypt(crypto::unwrap_cbor_tag(&key), aad)?;
    crypto::Key::from_slice(&key)
}
