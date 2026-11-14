//! createOrder (tx type 14): places a new order on Lighter.
//!
//! ## Pre-image (16 Goldilocks elements)
//! ```text
//! [chain_id, 14, nonce, expired_at, account_index, api_key_index,
//!  market_index, client_order_index, base_amount, price,
//!  is_ask, order_type, time_in_force, reduce_only,
//!  trigger_price, order_expiry]
//! ```
//!
//! ## Attribute hash aggregation
//! When integrator fees / account index are non-zero:
//!   `msgHash = Poseidon2([txHash[0..4] || attrHash[0..4]])`
//! Otherwise (our default case):
//!   `msgHash = txHash`
//!
//! ## JSON (from Go SDK reference)
//! ```json
//! {
//!   "AccountIndex": int64,
//!   "ApiKeyIndex": uint8,
//!   "BaseAmount": int64,
//!   "ClientOrderIndex": int64,       // 0 = let server assign (NilClientOrderIndex)
//!   "ExpiredAt": int64,
//!   "IsAsk": uint8,                  // 0 = bid, 1 = ask
//!   "L2TxAttributes": {"1":int,"2":int,"3":int},
//!   "MarketIndex": int16,            // 0 = ETH-USD, 1 = BTC-USD perps
//!   "Nonce": int64,
//!   "OrderExpiry": int64,            // 0 for IOC/market; required for GTT limit orders
//!   "Price": uint32,                 // price in market ticks
//!   "ReduceOnly": uint8,             // 0 or 1
//!   "Sig": "<base64>",
//!   "TimeInForce": uint8,            // 0=IOC, 1=GTT, 2=PostOnly
//!   "TriggerPrice": uint32,          // 0 for limit/market orders (NilOrderTriggerPrice)
//!   "Type": uint8                    // 0=Limit, 1=Market, 2=StopLoss, ...
//! }
//! ```

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use super::crypto::{
    poseidon2::{hash_to_quintic_extension, Fp5Element, Goldilocks},
    schnorr::sign_hashed_message,
    ScalarField,
};

// ── Order type constants ──────────────────────────────────────────────────────
pub const ORDER_TYPE_LIMIT: u8 = 0;
pub const ORDER_TYPE_MARKET: u8 = 1;
pub const ORDER_TYPE_STOP_LOSS: u8 = 2;
pub const ORDER_TYPE_STOP_LOSS_LIMIT: u8 = 3;
pub const ORDER_TYPE_TAKE_PROFIT: u8 = 4;
pub const ORDER_TYPE_TAKE_PROFIT_LIMIT: u8 = 5;
pub const ORDER_TYPE_TWAP: u8 = 6;

// ── Time-in-force constants ───────────────────────────────────────────────────
pub const TIF_IOC: u8 = 0; // ImmediateOrCancel
pub const TIF_GTT: u8 = 1; // GoodTillTime
pub const TIF_POST_ONLY: u8 = 2; // PostOnly

// ── Sentinel values (nil) ─────────────────────────────────────────────────────
pub const NIL_CLIENT_ORDER_INDEX: i64 = 0;
pub const NIL_ORDER_EXPIRY: i64 = 0;
pub const NIL_TRIGGER_PRICE: u32 = 0;

// ── Attribute type indices (from Lighter SDK) ─────────────────────────────────
const ATTR_INTEGRATOR_ACCOUNT: u8 = 1;
const ATTR_INTEGRATOR_TAKER_FEE: u8 = 2;
const ATTR_INTEGRATOR_MAKER_FEE: u8 = 3;
const NB_ATTRIBUTES: usize = 4;

/// Parameters for L2TxAttributes (integrator fee routing).
/// All zero = no integrator; the attribute hash is skipped.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrderAttributes {
    pub integrator_account_index: i64,
    pub integrator_taker_fee: i64,
    pub integrator_maker_fee: i64,
}

impl OrderAttributes {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.integrator_account_index == 0
            && self.integrator_taker_fee == 0
            && self.integrator_maker_fee == 0
    }

    /// Produces 8 Goldilocks elements matching Go's `getNormalizedTypes()` + interleaved values.
    /// Format: [type0, val0, type1, val1, type2, val2, type3, val3]
    /// Only non-zero attributes are included; remainder is zero-padded to 4 pairs.
    fn to_hash_elements(&self) -> [Goldilocks; 8] {
        // Collect (type, value) pairs for non-zero entries, sorted by type
        let mut pairs: Vec<(u8, i64)> = Vec::new();
        if self.integrator_account_index != 0 {
            pairs.push((ATTR_INTEGRATOR_ACCOUNT, self.integrator_account_index));
        }
        if self.integrator_taker_fee != 0 {
            pairs.push((ATTR_INTEGRATOR_TAKER_FEE, self.integrator_taker_fee));
        }
        if self.integrator_maker_fee != 0 {
            pairs.push((ATTR_INTEGRATOR_MAKER_FEE, self.integrator_maker_fee));
        }
        pairs.sort_by_key(|&(t, _)| t);

        // Pad to NB_ATTRIBUTES pairs with (0, 0)
        let mut out = [Goldilocks::from_canonical_u64(0); 8];
        for (i, &(typ, val)) in pairs.iter().enumerate().take(NB_ATTRIBUTES) {
            out[i * 2] = Goldilocks::from_canonical_u64(typ as u64);
            out[i * 2 + 1] = Goldilocks::from_i64(val);
        }
        out
    }

    /// Compute the attribute hash (Poseidon2 over 8 elements).
    fn hash(&self) -> Fp5Element {
        let elems = self.to_hash_elements();
        hash_to_quintic_extension(&elems)
    }
}

/// Hash the createOrder pre-image and (if attributes non-empty) aggregate with attr hash.
/// Returns the 40-byte final msgHash ready for Schnorr signing.
pub fn hash_create_order(
    chain_id: u64,
    nonce: i64,
    expired_at: i64,
    account_index: i64,
    api_key_index: u8,
    market_index: i64,
    client_order_index: i64,
    base_amount: i64,
    price: u32,
    is_ask: u8,
    order_type: u8,
    time_in_force: u8,
    reduce_only: u8,
    trigger_price: u32,
    order_expiry: i64,
    attrs: &OrderAttributes,
) -> [u8; 40] {
    let elems = [
        Goldilocks::from_canonical_u64(chain_id),
        Goldilocks::from_canonical_u64(14), // TxTypeL2CreateOrder
        Goldilocks::from_i64(nonce),
        Goldilocks::from_i64(expired_at),
        Goldilocks::from_i64(account_index),
        Goldilocks::from_canonical_u64(api_key_index as u64),
        Goldilocks::from_i64(market_index),
        Goldilocks::from_i64(client_order_index),
        Goldilocks::from_i64(base_amount),
        Goldilocks::from_canonical_u64(price as u64),
        Goldilocks::from_canonical_u64(is_ask as u64),
        Goldilocks::from_canonical_u64(order_type as u64),
        Goldilocks::from_canonical_u64(time_in_force as u64),
        Goldilocks::from_canonical_u64(reduce_only as u64),
        Goldilocks::from_canonical_u64(trigger_price as u64),
        Goldilocks::from_i64(order_expiry),
    ];

    let tx_hash: Fp5Element = hash_to_quintic_extension(&elems);

    if attrs.is_empty() {
        tx_hash.to_bytes_le()
    } else {
        // AggregateTxHash: Poseidon2([txHash[0..4] || attrHash[0..4]])
        let attr_hash = attrs.hash();
        let combined: Vec<Goldilocks> = tx_hash
            .0
            .iter()
            .chain(attr_hash.0.iter())
            .cloned()
            .collect();
        hash_to_quintic_extension(&combined).to_bytes_le()
    }
}

/// Sign a createOrder transaction. Returns base64-encoded 80-byte Schnorr signature.
pub fn sign_create_order(
    private_key: &[u8; 40],
    chain_id: u64,
    nonce: i64,
    expired_at: i64,
    account_index: i64,
    api_key_index: u8,
    market_index: i64,
    client_order_index: i64,
    base_amount: i64,
    price: u32,
    is_ask: u8,
    order_type: u8,
    time_in_force: u8,
    reduce_only: u8,
    trigger_price: u32,
    order_expiry: i64,
    attrs: &OrderAttributes,
) -> String {
    let nonce_bytes = ScalarField::sample_crypto().to_bytes_le();
    let hash = hash_create_order(
        chain_id,
        nonce,
        expired_at,
        account_index,
        api_key_index,
        market_index,
        client_order_index,
        base_amount,
        price,
        is_ask,
        order_type,
        time_in_force,
        reduce_only,
        trigger_price,
        order_expiry,
        attrs,
    );
    let sig =
        sign_hashed_message(private_key, &hash, &nonce_bytes).expect("sign_hashed_message failed");
    BASE64.encode(&sig)
}

/// Build the tx_info JSON for createOrder (ready to POST to /api/v1/sendTx as tx_type=14).
///
/// `L2TxAttributes` is always included in the JSON (even when all-zero) matching Go SDK output.
pub fn build_tx_info(
    account_index: i64,
    api_key_index: u8,
    market_index: i64,
    client_order_index: i64,
    base_amount: i64,
    price: u32,
    is_ask: u8,
    order_type: u8,
    time_in_force: u8,
    reduce_only: u8,
    trigger_price: u32,
    order_expiry: i64,
    expired_at: i64,
    nonce: i64,
    sig_b64: &str,
    attrs: &OrderAttributes,
) -> serde_json::Value {
    serde_json::json!({
        "AccountIndex": account_index,
        "ApiKeyIndex": api_key_index,
        "BaseAmount": base_amount,
        "ClientOrderIndex": client_order_index,
        "ExpiredAt": expired_at,
        "IsAsk": is_ask,
        "L2TxAttributes": {
            "1": attrs.integrator_account_index,
            "2": attrs.integrator_taker_fee,
            "3": attrs.integrator_maker_fee,
        },
        "MarketIndex": market_index,
        "Nonce": nonce,
        "OrderExpiry": order_expiry,
        "Price": price,
        "ReduceOnly": reduce_only,
        "Sig": sig_b64,
        "TimeInForce": time_in_force,
        "TriggerPrice": trigger_price,
        "Type": order_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── hash_create_order determinism ─────────────────────────────────────────

    #[test]
    fn hash_create_order_is_deterministic() {
        let attrs = OrderAttributes::none();
        let h1 = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_POST_ONLY,
            0,
            0,
            0,
            &attrs,
        );
        let h2 = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_POST_ONLY,
            0,
            0,
            0,
            &attrs,
        );
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    #[test]
    fn hash_create_order_changes_with_different_price() {
        let attrs = OrderAttributes::none();
        let h1 = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            0,
            &attrs,
        );
        let h2 = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            310_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            0,
            &attrs,
        ); // different price
        assert_ne!(h1, h2, "different price must produce different hash");
    }

    #[test]
    fn hash_create_order_changes_with_different_side() {
        let attrs = OrderAttributes::none();
        let h_bid = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            0,
            &attrs,
        );
        let h_ask = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            1,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            0,
            &attrs,
        );
        assert_ne!(h_bid, h_ask, "bid vs ask must produce different hash");
    }

    #[test]
    fn hash_create_order_with_attrs_differs_from_without() {
        let no_attrs = OrderAttributes::none();
        let with_attrs = OrderAttributes {
            integrator_account_index: 12345,
            integrator_taker_fee: 100,
            integrator_maker_fee: 50,
        };
        let h_plain = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            0,
            &no_attrs,
        );
        let h_attrs = hash_create_order(
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            0,
            &with_attrs,
        );
        assert_ne!(h_plain, h_attrs, "integrator attrs must change the hash");
    }

    // ── OrderAttributes ───────────────────────────────────────────────────────

    #[test]
    fn order_attributes_none_is_empty() {
        let a = OrderAttributes::none();
        assert!(a.is_empty());
    }

    #[test]
    fn order_attributes_with_nonzero_is_not_empty() {
        let a = OrderAttributes {
            integrator_account_index: 1,
            ..Default::default()
        };
        assert!(!a.is_empty());
    }

    // ── build_tx_info JSON shape ───────────────────────────────────────────────

    #[test]
    fn build_tx_info_contains_all_required_fields() {
        let attrs = OrderAttributes::none();
        let tx = build_tx_info(
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_POST_ONLY,
            0,
            0,
            1774012600000,
            1774009000000,
            5,
            "sig==",
            &attrs,
        );
        // All Go SDK required fields must be present
        assert!(tx["AccountIndex"].is_number());
        assert!(tx["ApiKeyIndex"].is_number());
        assert!(tx["BaseAmount"].is_number());
        assert!(tx["ClientOrderIndex"].is_number());
        assert!(tx["ExpiredAt"].is_number());
        assert!(tx["IsAsk"].is_number());
        assert!(
            tx["L2TxAttributes"].is_object(),
            "L2TxAttributes must always be present"
        );
        assert!(tx["MarketIndex"].is_number());
        assert!(tx["Nonce"].is_number());
        assert!(tx["Price"].is_number());
        assert!(tx["Sig"].is_string());
        assert!(tx["TimeInForce"].is_number());
        assert!(tx["Type"].is_number());
        assert_eq!(tx["Sig"].as_str().unwrap(), "sig==");
    }

    #[test]
    fn build_tx_info_l2_tx_attributes_always_present_even_when_zero() {
        let attrs = OrderAttributes::none();
        let tx = build_tx_info(
            1,
            88,
            0,
            0,
            10,
            100_000,
            1,
            ORDER_TYPE_LIMIT,
            TIF_IOC,
            0,
            0,
            0,
            1774009000000,
            1,
            "s",
            &attrs,
        );
        let l2 = &tx["L2TxAttributes"];
        assert!(l2.is_object());
        assert_eq!(l2["1"].as_i64(), Some(0));
        assert_eq!(l2["2"].as_i64(), Some(0));
        assert_eq!(l2["3"].as_i64(), Some(0));
    }

    // ── sign_create_order returns valid base64 ────────────────────────────────

    #[test]
    fn sign_create_order_returns_80_byte_base64() {
        let mut privkey = [0u8; 40];
        privkey[0] = 7; // non-trivial key
        let attrs = OrderAttributes::none();
        let sig = sign_create_order(
            &privkey,
            304,
            1,
            1774009000000,
            281474976620611,
            88,
            0,
            0,
            100,
            300_000,
            0,
            ORDER_TYPE_LIMIT,
            TIF_GTT,
            0,
            0,
            1774012600000,
            &attrs,
        );
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .expect("must be valid base64");
        assert_eq!(decoded.len(), 80, "Schnorr sig must be 80 bytes");
    }
}
