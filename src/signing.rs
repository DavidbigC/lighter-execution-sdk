use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{
    create_order::{
        build_tx_info, hash_create_order, OrderAttributes, NIL_ORDER_EXPIRY, NIL_TRIGGER_PRICE,
        ORDER_TYPE_LIMIT, TIF_GTT, TIF_IOC, TIF_POST_ONLY,
    },
    crypto::{hash_to_quintic_extension, sign_hashed_message, Goldilocks, ScalarField},
    Error, Network,
};

const CREATE_ORDER: u8 = 14;
const CANCEL_ORDER: u8 = 15;
const CANCEL_ALL: u8 = 16;
const MAX_48_BIT: i64 = (1 << 48) - 1;
const MAX_ORDER_INDEX: i64 = (1 << 60) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeInForce {
    Ioc,
    /// An absolute Unix timestamp in milliseconds.
    GoodTillTime {
        order_expiry_ms: i64,
    },
    /// An absolute Unix timestamp in milliseconds.
    PostOnly {
        order_expiry_ms: i64,
    },
}

/// Prices and sizes use the selected market's integer tick units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitOrder {
    pub market_id: i64,
    pub side: Side,
    pub size_ticks: i64,
    pub price_ticks: u32,
    pub time_in_force: TimeInForce,
    pub reduce_only: bool,
    /// An application-supplied ID. Zero asks the venue to assign an ID.
    pub client_order_index: i64,
}

/// A payload for Lighter's sendTx API. The nonce and expiration are already signed.
pub struct SignedTransaction {
    tx_type: u8,
    tx_info: Value,
    nonce: i64,
    tx_hash: String,
}

impl SignedTransaction {
    pub fn tx_type(&self) -> u8 {
        self.tx_type
    }

    pub fn tx_info(&self) -> &Value {
        &self.tx_info
    }

    /// The transaction's signing hash, usable to look up its status at Lighter.
    pub fn tx_hash(&self) -> &str {
        &self.tx_hash
    }

    pub fn nonce(&self) -> i64 {
        self.nonce
    }
}

/// Offline signing for one network, account, and API key.
pub struct Signer {
    pub(crate) network: Network,
    pub(crate) account_index: i64,
    pub(crate) api_key_index: u8,
    key: Zeroizing<[u8; 40]>,
}

impl Signer {
    pub fn new(
        network: Network,
        account_index: i64,
        api_key_index: u8,
        private_key: &str,
    ) -> Result<Self, Error> {
        if !(0..MAX_48_BIT).contains(&account_index) || api_key_index == u8::MAX {
            return Err(Error::Invalid(
                "account index or API key index is out of range",
            ));
        }
        let mut key = Zeroizing::new([0; 40]);
        let private_key = private_key
            .strip_prefix("0x")
            .or_else(|| private_key.strip_prefix("0X"))
            .unwrap_or(private_key);
        hex::decode_to_slice(private_key, &mut *key)
            .map_err(|_| Error::Invalid("API private key must be 40 bytes of hex"))?;
        let scalar = ScalarField::from_bytes_le(&*key).map_err(|_| Error::Signing)?;
        let below_modulus = scalar
            .0
            .iter()
            .rev()
            .cmp(ScalarField::N.0.iter().rev())
            .is_lt();
        if scalar.is_zero() || !below_modulus {
            return Err(Error::Invalid(
                "API private key is outside the scalar field",
            ));
        }
        Ok(Self {
            network,
            account_index,
            api_key_index,
            key,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Build and sign a limit order. The caller supplies the transaction nonce and expiry.
    pub fn sign_order(
        &self,
        order: &LimitOrder,
        nonce: i64,
        tx_expiry_ms: i64,
    ) -> Result<SignedTransaction, Error> {
        check_tx(nonce, tx_expiry_ms)?;
        if !is_market_id(order.market_id)
            || (order.size_ticks == 0 && !order.reduce_only)
            || !(0..=MAX_48_BIT).contains(&order.size_ticks)
            || order.price_ticks == 0
            || !(0..=MAX_48_BIT).contains(&order.client_order_index)
        {
            return Err(Error::Invalid("invalid market, order index, size or price"));
        }
        let (tif, order_expiry) = match order.time_in_force {
            TimeInForce::Ioc => (TIF_IOC, NIL_ORDER_EXPIRY),
            TimeInForce::GoodTillTime { order_expiry_ms } if order_expiry_ms > 0 => {
                (TIF_GTT, order_expiry_ms)
            }
            TimeInForce::PostOnly { order_expiry_ms } if order_expiry_ms > 0 => {
                (TIF_POST_ONLY, order_expiry_ms)
            }
            _ => {
                return Err(Error::Invalid(
                    "order expiry must be a positive Unix timestamp",
                ))
            }
        };
        let is_ask = u8::from(order.side == Side::Sell);
        let reduce_only = u8::from(order.reduce_only);
        let attrs = OrderAttributes::none();
        let hash = hash_create_order(
            self.network.chain_id(),
            nonce,
            tx_expiry_ms,
            self.account_index,
            self.api_key_index,
            order.market_id,
            order.client_order_index,
            order.size_ticks,
            order.price_ticks,
            is_ask,
            ORDER_TYPE_LIMIT,
            tif,
            reduce_only,
            NIL_TRIGGER_PRICE,
            order_expiry,
            &attrs,
        );
        let signature = self.sign_hash(&hash)?;
        let tx_info = build_tx_info(
            self.account_index,
            self.api_key_index,
            order.market_id,
            order.client_order_index,
            order.size_ticks,
            order.price_ticks,
            is_ask,
            ORDER_TYPE_LIMIT,
            tif,
            reduce_only,
            NIL_TRIGGER_PRICE,
            order_expiry,
            tx_expiry_ms,
            nonce,
            &signature,
            &attrs,
        );
        Ok(SignedTransaction {
            tx_type: CREATE_ORDER,
            tx_info,
            nonce,
            tx_hash: hex::encode(hash),
        })
    }

    pub fn sign_cancel(
        &self,
        market_id: i64,
        order_index: i64,
        nonce: i64,
        tx_expiry_ms: i64,
    ) -> Result<SignedTransaction, Error> {
        if !is_market_id(market_id) || !(1..=MAX_ORDER_INDEX).contains(&order_index) {
            return Err(Error::Invalid("market or order index is out of range"));
        }
        self.sign_cancellation(
            CANCEL_ORDER,
            [market_id, order_index],
            nonce,
            tx_expiry_ms,
            json!({ "MarketIndex": market_id, "Index": order_index }),
        )
    }

    /// Sign an immediate cancellation of all open orders in this Lighter account.
    pub fn sign_cancel_all(
        &self,
        nonce: i64,
        tx_expiry_ms: i64,
    ) -> Result<SignedTransaction, Error> {
        self.sign_cancellation(
            CANCEL_ALL,
            [0, 0],
            nonce,
            tx_expiry_ms,
            json!({ "TimeInForce": 0, "Time": 0 }),
        )
    }

    fn sign_cancellation(
        &self,
        tx_type: u8,
        [first, second]: [i64; 2],
        nonce: i64,
        tx_expiry_ms: i64,
        mut tx_info: Value,
    ) -> Result<SignedTransaction, Error> {
        check_tx(nonce, tx_expiry_ms)?;
        // Common header and operation fields match Lighter's Go reference signer.
        let preimage = [
            self.network.chain_id() as i64,
            i64::from(tx_type),
            nonce,
            tx_expiry_ms,
            self.account_index,
            i64::from(self.api_key_index),
            first,
            second,
        ]
        .map(Goldilocks::from_i64);
        let hash = hash_to_quintic_extension(&preimage).to_bytes_le();
        tx_info["AccountIndex"] = json!(self.account_index);
        tx_info["ApiKeyIndex"] = json!(self.api_key_index);
        tx_info["ExpiredAt"] = json!(tx_expiry_ms);
        tx_info["Nonce"] = json!(nonce);
        tx_info["Sig"] = json!(self.sign_hash(&hash)?);
        Ok(SignedTransaction {
            tx_type,
            tx_info,
            nonce,
            tx_hash: hex::encode(hash),
        })
    }

    fn sign_hash(&self, hash: &[u8]) -> Result<String, Error> {
        let random_scalar = Zeroizing::new(ScalarField::sample_crypto().to_bytes_le());
        let sig =
            sign_hashed_message(&*self.key, hash, &*random_scalar).map_err(|_| Error::Signing)?;
        Ok(STANDARD.encode(sig))
    }
}

fn is_market_id(id: i64) -> bool {
    id != 255 && (0..=MAX_48_BIT).contains(&id)
}

fn check_tx(nonce: i64, tx_expiry_ms: i64) -> Result<(), Error> {
    if nonce < 0 || !(1..=MAX_48_BIT).contains(&tx_expiry_ms) {
        return Err(Error::Invalid(
            "nonce or transaction expiry is out of range",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{verify_signature, Point};

    #[test]
    fn each_signature_binds_the_expected_l2_domain() {
        let key = ScalarField::ONE.to_bytes_le();
        let public_key = Point::generator().encode().to_bytes_le();
        let order = LimitOrder {
            market_id: 1,
            side: Side::Sell,
            size_ticks: 1000,
            price_ticks: 750_000,
            time_in_force: TimeInForce::Ioc,
            reduce_only: true,
            client_order_index: 123,
        };
        // These hashes come from lighter-go v1.0.2's Hash(chainID) on the same fields.
        let main_hashes = [
            "abfec0679277db8b097dca4900a4843402326dd781937dc060d40ac0c938b343887d9deae83bf65c",
            "44a1e4afecc22d15fa9ea97d40f2a6ffc45e3438a102303b08e2a100d46f291d79787d9268f240f8",
            "0d0b7d022b2c7d476f19341855cbaf21064f2e2c6968b34260201b5a5528ec50e5ca427dbc30eab5",
        ];
        let rh_hashes = [
            "4234ca687617a6c70204464786088aaa0936cbd0a62d3655ae57eb96c8b3d4fd9c895cffd1b0c746",
            "8bd3ca0691ecca02a911390f11bc62d7b8a478d8d1c6376398111d4294c59eef9fbda6f0c52d885c",
            "bf1604af8c5ea2fca75f0b55f33ed1eb57a135aa972cceb54d2a332dae6831f1eaae5bebe02c749b",
        ];
        for (network, expected, other) in [
            (Network::Main, main_hashes, rh_hashes),
            (Network::Robinhood, rh_hashes, main_hashes),
        ] {
            let signer = Signer::new(network, 41, 3, &hex::encode(key)).unwrap();
            let txs = [
                signer.sign_order(&order, 17, 1_800_000_000_000).unwrap(),
                signer.sign_cancel(1, 998, 18, 1_800_000_000_000).unwrap(),
                signer.sign_cancel_all(19, 1_800_000_000_000).unwrap(),
            ];
            for ((tx, hash), wrong_domain_hash) in txs.into_iter().zip(expected).zip(other) {
                let sig = STANDARD
                    .decode(tx.tx_info()["Sig"].as_str().unwrap())
                    .unwrap();
                assert_eq!(tx.tx_hash(), hash);
                let hash = hex::decode(hash).unwrap();
                let wrong_domain_hash = hex::decode(wrong_domain_hash).unwrap();
                assert!(verify_signature(&sig, &hash, &public_key).unwrap());
                assert!(!verify_signature(&sig, &wrong_domain_hash, &public_key).unwrap());
            }
        }
    }
}
