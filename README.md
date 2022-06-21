# Ledger Nano PIV Application

TODO

## Building

```
cargo build --release -Z build-std=core --target=../ledger-nanos-sdk/nanosplus.json
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
