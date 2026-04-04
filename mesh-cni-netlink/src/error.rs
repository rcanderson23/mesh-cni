use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),
}
