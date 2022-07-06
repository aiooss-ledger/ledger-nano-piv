# Ledger Nano PIV Application

This is a Ledger Hackathon project targetted on building a PIV compatible
Ledger Nano X/S+ application.

The focus of this application is to be compatible with AGE Yubikey plugin.

During the Hackathon we made some choices:

  * The application is stateless.
    Retired slots value are derived from the seed.
  * No PIN or PUK as the Ledger Nano operating system already prompt a PIN.

## Building

The code has been tested using Rust Nighly (2022-06-19).

```
cargo build --release
```

## Loading

You can use [cargo-ledger](https://github.com/LedgerHQ/cargo-ledger.git) which
builds, outputs a `hex` file and a manifest file for `ledgerctl`, and loads it
on a device in a single `cargo ledger load` command in your app directory.

## Testing

One can for example use [speculos](https://github.com/LedgerHQ/speculos).

In a first console:
```
cargo run
```
In a second one:
```
pytest test/ -v -s
```

## References

  * JavaCard PIV Applet under Mozilla Public License 2.0:
    https://github.com/arekinath/PivApplet
  * https://csrc.nist.gov/publications/detail/sp/800-73/4/final
  * https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
  * https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html
