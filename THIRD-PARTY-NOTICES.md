# Third-party notices

The signing code derives from the `lighter-execd` daemon in Variational. Its `src/crypto/` modules retain their original attribution to [Bvvvp009/lighter-rust](https://github.com/Bvvvp009/lighter-rust). The upstream crypto and Poseidon-hash portions are included here under their [crypto MIT license](licenses/Bvvvp009-crypto-MIT.txt) and [Poseidon-hash MIT license](licenses/Bvvvp009-poseidon-hash-MIT.txt).

Order and cancellation transaction layouts follow the [Elliot Technologies Go SDK](https://github.com/elliottech/lighter-go), which uses the [Apache License 2.0](licenses/elliottech-lighter-go-Apache-2.0.txt). The SDK tests use transaction hashes computed with Go SDK version `v1.0.12`.
