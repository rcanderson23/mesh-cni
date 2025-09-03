// use axum::http::{Response, StatusCode};
// use axum::response::IntoResponse;
// use tracing::error;
//
// use crate::Error;
// use mesh_cni_api::Reply;
//
// impl IntoResponse for Error {
//     fn into_response(self) -> axum::response::Response {
//         let (message, code) = match self {
//             Error::EbpfError(e) => (e, StatusCode::INTERNAL_SERVER_ERROR),
//             Error::EbpfProgramError(e) => (e, StatusCode::INTERNAL_SERVER_ERROR),
//             Error::IoError(error) => (error.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
//             Error::JsonConversion(error) => (error.to_string(), StatusCode::BAD_REQUEST),
//             Error::ConversionError(_)
//             | Error::CryptoError(_)
//             | Error::StoreCreation(_)
//             | Error::ConvertPodIpIdentity
//             | Error::KubeError(_)
//             | Error::AddrParseError(_)
//             | Error::KubeStreamFailed
//             | Error::ChannelError
//             | Error::Other(_)
//             | Error::MapNotFound { name: _ }
//             | Error::MapError(_) => ("unexepcted error".into(), StatusCode::INTERNAL_SERVER_ERROR),
//             Error::InvalidSandbox => ("invalid sandbox".into(), StatusCode::BAD_REQUEST),
//             Error::NetNs(error) => (error.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
//         };
//         let reply = Reply {
//             status: "fail".into(),
//             message: Some(message),
//         };
//         match serde_json::to_string(&reply) {
//             Ok(r) => Response::builder()
//                 .status(code)
//                 .header("Content-Type", "application/json")
//                 .body(r.into())
//                 .unwrap(),
//             Err(e) => {
//                 error!(%e, "failed to serialize reply");
//                 Response::builder()
//                     .status(StatusCode::INTERNAL_SERVER_ERROR)
//                     .header("Content-Type", "application/json")
//                     .body(().into())
//                     .unwrap()
//             }
//         }
//     }
// }
