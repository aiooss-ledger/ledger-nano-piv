# Ledger Nano PIV Application

This is a Ledger Hackathon project targeted on building a PIV compatible
Ledger Nano X/S+ application.

The focus of this application is to be compatible with AGE Yubikey plugin.

During the Hackathon we made some choices:

  * The application is stateless.
    Retired slots value are derived from the seed.
  * No PIN or PUK as the Ledger Nano operating system already prompt a PIN.

## Building

If you have never used Rust on your machine, you might start by
[installing rustup](https://www.rust-lang.org/tools/install).

This application requires Rust Nightly and some C headers,
```bash
rustup default nightly
rustup component add rust-src

# On Ubuntu
sudo apt install clang gcc-arm-none-eabi gcc-multilib

# On Fedora
sudo dnf install clang arm-none-eabi-gcc arm-none-eabi-newlib

# On ArchLinux
sudo pacman -S clang arm-none-eabi-gcc arm-none-eabi-newlib
```

Then you should be able to build this application using
[cargo-ledger](https://github.com/LedgerHQ/cargo-ledger),
```bash
cargo install --git https://github.com/LedgerHQ/cargo-ledger
cd /path/to/ledger-nano-piv/
cargo ledger
```

## Loading

[cargo-ledger](https://github.com/LedgerHQ/cargo-ledger.git) is able to
generate a `hex` file and a manifest for `ledgerctl`. To directly load the
application on the connected device, you may run:
```
cargo ledger load
```

## Usage

### On GNU/Linux distributions

You need the `pcscd` smart card service to manage connections to CCID smart
card devices.
`ccid` package is not yet aware of the Ledger Nano S/X/S Plus CCID USB device
identifiers. To add support for these devices, you need to edit
`/etc/libccid_Info.plist` and then reload `pcscd`:
```diff
--- a/libccid_Info.plist
+++ b/libccid_Info.plist
@@ -102,6 +102,9 @@

        <key>ifdVendorID</key>
        <array>
+               <string>0x2C97</string>
+               <string>0x2C97</string>
+               <string>0x2C97</string>
                <string>0x072F</string>
                <string>0x09C3</string>
                <string>0x09C3</string>
@@ -550,6 +553,9 @@

        <key>ifdProductID</key>
        <array>
+               <string>0x1009</string>
+               <string>0x4009</string>
+               <string>0x5009</string>
                <string>0x90CC</string>
                <string>0x0013</string>
                <string>0x0014</string>
@@ -998,6 +1004,9 @@

        <key>ifdFriendlyName</key>
        <array>
+               <string>Ledger Nano S CCID</string>
+               <string>Ledger Nano X CCID</string>
+               <string>Ledger Nano S Plus CCID</string>
                <string>ACS ACR 38U-CCID</string>
                <string>ActivIdentity USB Reader V3</string>
                <string>ActivIdentity Activkey_Sim</string>
```

Now you should see the Ledger device in `pkcs11-tool -L` output.

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
