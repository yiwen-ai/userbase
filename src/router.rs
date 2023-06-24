use axum::{
    middleware,
    response::{IntoResponse, Response},
    routing, Router,
};
use std::{fs, sync::Arc};
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{predicate::SizeAbove, CompressionLayer},
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

    let mds = ServiceBuilder::new()
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn(context::middleware))
        .layer(CompressionLayer::new().compress_when(SizeAbove::new(encoding::MIN_ENCODING_SIZE)));

    let app = Router::new()
        .route("/", routing::get(api::version))
        .route("/healthz", routing::get(api::healthz))
        .nest(
            "/v1/user",
            Router::new()
                .route("/", routing::get(api::user::get).patch(api::user::update))
                .route("/update_email", routing::patch(api::user::update_email))
                .route("/update_phone", routing::patch(api::user::update_phone))
                .route("/list_groups", routing::patch(api::user::list_groups)),
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
                .route("/update_status", routing::patch(api::group::update_status))
                .route("/update_kind", routing::patch(api::group::update_kind))
                .route("/update_email", routing::patch(api::group::update_email))
                .route("/list_users", routing::post(api::group::list_users))
                .route("/list_members", routing::post(api::group::list_members))
                .nest(
                    "/member",
                    Router::new()
                        .route(
                            "/",
                            routing::post(api::member::create).delete(api::member::create),
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
        .route_layer(mds)
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

    let mac_id = {
        let id_key = read_key(&decryptor, aad, &fs::read_to_string(cfg.keys.id_key_file)?)?;
        crypto::MacId::new(id_key.get_private()?)
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
        crypto::Cwt::new(token_key.get_private()?, &token_key.key_id())
    };

    let scylla = {
        let keyspace = if cfg.env == "test" {
            "userbase_test"
        } else {
            "userbase"
        };
        db::scylladb::ScyllaDB::new(cfg.scylla, keyspace).await?
    };

    Ok(api::AppState {
        start_at: context::unix_ms(),
        mac_id: Arc::new(mac_id),
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
