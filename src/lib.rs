#![doc = include_str!("../README.md")]

mod client;
// The extracted crypto includes additional primitives used by its upstream tests.
#[allow(dead_code)]
mod create_order;
#[allow(dead_code, unused_imports)]
mod crypto;
mod signing;
#[cfg(feature = "websocket")]
mod ws_send;

pub use client::{Client, Receipt, Route};
pub use signing::{LimitOrder, Side, SignedTransaction, Signer, TimeInForce};
use thiserror::Error;

/// Lighter deployments and their L2 signing domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Main,
    Robinhood,
}

impl Network {
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Main => 304,
            Self::Robinhood => 466324,
        }
    }

    pub const fn rest_url(self) -> &'static str {
        match self {
            Self::Main => "https://mainnet.zklighter.elliot.ai",
            Self::Robinhood => "https://api.rh.lighter.xyz",
        }
    }

    pub const fn websocket_url(self) -> &'static str {
        match self {
            Self::Main => "wss://mainnet.zklighter.elliot.ai/stream",
            Self::Robinhood => "wss://api.rh.lighter.xyz/stream",
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("failed to sign the transaction")]
    Signing,
    #[error("nonce lookup failed: {0}")]
    NonceLookup(String),
    #[error("Lighter rejected the transaction ({code}): {message}")]
    Rejected { code: i64, message: String },
    #[error("Lighter may have accepted {tx_hash} (nonce {nonce}): {detail}")]
    Unknown {
        nonce: i64,
        tx_hash: String,
        detail: String,
    },
    #[error("reconcile {tx_hash} (nonce {nonce}) before submitting again")]
    UnresolvedNonce { nonce: i64, tx_hash: String },
    #[error("could not initialize HTTP client: {0}")]
    HttpClient(#[source] reqwest::Error),
}
