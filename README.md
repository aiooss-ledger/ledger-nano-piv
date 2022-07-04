# Ledger Nano PIV Application

TODO

## Building

  * Clone [ledger-nanos-sdk on branch unified_build](https://github.com/LedgerHQ/ledger-nanos-sdk/tree/unified_build) next to this repository.

  * Clone [ledger-nanos-ui](https://github.com/LedgerHQ/ledger-nanos-ui) next to this repository and edit `nanos_sdk = { path = "../ledger-nanos-sdk" }` in `Cargo.toml`.

  * Then you should be able to compile:
    ```
    cargo build --release -Z build-std=core
    ```

## Loading

You can use [cargo-ledger](https://github.com/LedgerHQ/cargo-ledger.git) which
builds, outputs a `hex` file and a manifest file for `ledgerctl`, and loads it
on a device in a single `cargo ledger load` command in your app directory.

## Testing

One can for example use [speculos](https://github.com/LedgerHQ/speculos).

There is a small test script that sends some of the available commands in
`test/test_cmds.py`, or raw APDUs that can be used with `ledgerctl`.

## References

  * JavaCard PIV Applet under Mozilla Public License 2.0:
    https://github.com/arekinath/PivApplet
  * https://csrc.nist.gov/publications/detail/sp/800-73/4/final
  * https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
  * https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html
