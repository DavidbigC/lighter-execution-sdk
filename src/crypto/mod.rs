//! Vendored crypto from Bvvvp009/lighter-rust (https://github.com/Bvvvp009/lighter-rust)
//! ECgFp5 elliptic curve, Schnorr signatures, Poseidon2 hash over the Goldilocks field.
//!
//! ⚠️ NOT security audited. Use at own risk.

pub mod batch_verify;
pub mod poseidon2;
pub mod scalar_field;
pub mod schnorr;

pub use batch_verify::batch_verify;
pub use poseidon2::{hash_to_quintic_extension, Fp5Element, Goldilocks};
pub use scalar_field::ScalarField;
pub use schnorr::{sign, sign_hashed_message, validate_public_key, verify_signature, Point};
pub type WeierstrassPoint = Point;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid private key length: expected 40 bytes, got {0}")]
    InvalidPrivateKeyLength(usize),
    #[error("Invalid signature format")]
    InvalidSignature,
    #[error("Invalid signature length: expected 80 bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("Invalid message length: expected 40 bytes, got {0}")]
    InvalidMessageLength(usize),
    #[error("Invalid public key: cannot decode as encoded point")]
    InvalidPublicKey,
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
