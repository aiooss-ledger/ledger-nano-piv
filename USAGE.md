# Usage

## On GNU/Linux distributions

You need the `pcscd` smart card service to manage connections to CCID smart
card devices and `opensc` for software integrations.

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

### OpenSSH

```
ssh-keygen -D /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

## On Windows

Windows should detect the Ledger device as a `Microsoft Usbccid (WUDF)` smart
card reader containing a `NIST SP 800-73 [PIV]` smart card.
You can query information on this smart card using `certutil -scinfo` from
command line.

To use open-source software such as VeryCrypt, Putty-CAC and OpenVPN, you will
need to install OpenSC. More information is available on
[OpenSC wiki](https://github.com/OpenSC/OpenSC/wiki/Windows-Quick-Start).

### OpenSSH

Using built-in OpenSSH (since build 1809) and OpenSC,

```
ssh-keygen -D "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll
```

### VeraCrypt

Configure VeraCrypt to use OpenSC PKCS11 library:
go to `Settings > Security Tokens...` then press `Select Library...` and
choose `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll`.

Then you should be able to manage the security token in
`Tools > Manage Security Token Keyfiles...`.
