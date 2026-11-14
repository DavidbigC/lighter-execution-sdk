use lighter_execution_sdk::{LimitOrder, Network, Side, Signer, TimeInForce};

const TEST_KEY: &str =
    "01000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn sign_limit_order_and_cancel() {
    let order = LimitOrder {
        market_id: 1,
        side: Side::Sell,
        size_ticks: 1000,
        price_ticks: 750_000,
        time_in_force: TimeInForce::Ioc,
        reduce_only: true,
        client_order_index: 123,
    };
    for network in [Network::Main, Network::Robinhood] {
        let signer = Signer::new(network, 41, 3, TEST_KEY).unwrap();
        let tx = signer.sign_order(&order, 17, 1_800_000_000_000).unwrap();
        assert_eq!(tx.tx_type(), 14);
        assert_eq!(tx.nonce(), 17);
        assert_eq!(tx.tx_info()["AccountIndex"], 41);
        assert_eq!(tx.tx_info()["ApiKeyIndex"], 3);
        assert_eq!(tx.tx_info()["MarketIndex"], 1);
        assert_eq!(tx.tx_info()["ClientOrderIndex"], 123);
        assert_eq!(tx.tx_info()["Price"], 750_000);
        assert_eq!(tx.tx_info()["BaseAmount"], 1000);
        assert_eq!(tx.tx_info()["IsAsk"], 1);
        assert_eq!(tx.tx_info()["TimeInForce"], 0);
        assert_eq!(tx.tx_info()["ReduceOnly"], 1);
        let cancel = signer.sign_cancel(1, 998, 18, 1_800_000_000_000).unwrap();
        assert_eq!(cancel.tx_type(), 15);
        assert_eq!(cancel.tx_info()["Index"], 998);
        let cancel_all = signer.sign_cancel_all(19, 1_800_000_000_000).unwrap();
        assert_eq!(cancel_all.tx_type(), 16);
        assert_eq!(cancel_all.tx_info()["Time"], 0);
        assert!(signer
            .sign_order(
                &LimitOrder {
                    size_ticks: 0,
                    reduce_only: false,
                    ..order
                },
                17,
                1
            )
            .is_err());
    }
}

#[test]
fn market_id_above_32_bits_is_kept_in_signed_payload() {
    let signer = Signer::new(Network::Robinhood, 41, 3, TEST_KEY).unwrap();
    let market_id = (1_i64 << 40) + 73;
    let order = LimitOrder {
        market_id,
        side: Side::Buy,
        size_ticks: 1,
        price_ticks: 5,
        time_in_force: TimeInForce::Ioc,
        reduce_only: false,
        client_order_index: 12,
    };
    let tx = signer.sign_order(&order, 21, 1_800_000_000_000).unwrap();
    let truncated = signer
        .sign_order(
            &LimitOrder {
                market_id: 73,
                ..order
            },
            21,
            1_800_000_000_000,
        )
        .unwrap();
    assert_eq!(tx.tx_info()["MarketIndex"], market_id);
    assert_ne!(tx.tx_hash(), truncated.tx_hash());
    let cancel = signer
        .sign_cancel(market_id, 12, 22, 1_800_000_000_000)
        .unwrap();
    assert_eq!(cancel.tx_info()["MarketIndex"], market_id);
    assert!(signer.sign_cancel(255, 12, 22, 1_800_000_000_000).is_err());
}
