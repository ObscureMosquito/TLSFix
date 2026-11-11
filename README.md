<div align="center">
<h1>TLSFix</h1>
<br>
Modern SSL and TLS for iPhones, iPads, and iPod touches running iPhoneOS 2 to iOS 9.
<br>
<br>
</div>

<div style="white-space: nowrap; width: 100%" align="center">
  <img src="./Images/screenshot-1.png" style="width: 32%">
  <img src="./Images/screenshot-2.png" style="width: 32%">
  <img src="./Images/screenshot-3.png" style="width: 32%">
</div>

</br>

TLSFix reroutes the device's TLS/SSL traffic and operations through OpenSSL 1.1.1, so an old device understands modern cryptography again, TLS 1.0 through 1.3, current ciphers (ChaCha20-Poly1305, AES-GCM), and certificates. The chain is verified by the device's **own system trust store**, additionally, it **does not** disrupt SSL pinning in any way, it handles the initial crypto talk, but the final decision wherther to accept the server cert is still up to the process.

## How it works

TLSFix works by keeping the real `SSLContextRef` valid (so any call it doesn't intercept still operates on a live object) and attaches an OpenSSL shadow keyed by that context. The shadow runs the real handshake and crypto, whjile CFNetwork keeps driving the socket through the `SSLReadFunc`/`SSLWriteFunc` it already installed, which TLSFix bridges into OpenSSL as a custom BIO.

Verification is the OS's job, as the chain received is rebuilt into a `SecTrustRef` and evaluated with `SecTrustEvaluate` against the live system/user trust store. **This eliminates the need to bundle external certificates, and any new added profiles/certificates via the settings app are reflected inmediately, without needing to restart anything**.

## ECC certificates on iOS 3 and 4

iOS 3 and 4 cannot verify elliptic-curve (ECC) keys or ECDSA signatures. Installing an ECC root through a profile only stores it as a plain certificate, and every site whose chain uses ECC stays untrusted :(.

On those versions TLSFix verifies those chains itself, against the CA certificates of the installed profiles:

- Only when the system has already rejected the chain, and only when the chain contains an ECC key or signature. An all-RSA chain is always the system's decision.
- The same checks as the system's SSL policy, every signature and date up to an installed root, a server certificate, etc.
- An app that sets its own anchors or policies on a trust (SSL pinning) still the system's decition.

iOS 5 and later, which verifes ECC themselves, none of this occurs.

## Install

1. **Install the package**:
   - Install TLSFix from Cydia repo http://cydia.skyglow.es/ or https://nfzerox.github.io/cydia/
   - Or install the DEB file from [releases](https://github.com/nfzerox/TLSFix/releases) in your preferred manner

2. **Install modern roots**:
   - Go to [tlsroot.litten.ca](https://tlsroot.litten.ca/) in the device you're installing, and install the certificate bundle, TLSFix still needs a modern trust store to verify against.

Restart all userspace processes, or reboot.

## Building from source

**Prerequisites**: Theos with the legacy SDKs, Xcode command-line
tools (`xcrun`, `clang`, `lipo`, `ld`), and `ldid`. The prebuilt OpenSSL (`src/openssl/`:
`lib/libssl.a`, `lib/libcrypto.a`, `include/`) is vendored.

Run `./build-legacy.sh`. It compiles the files in `src/` and links each arch
against its SDK so `LC_VERSION_MIN`: armv6 and armv7 on the 5.1 SDK (min 2.0 / 3.0), arm64 on the 7.0 SDK (min 7.0).

Source stuff:

- `src/tlsfix.h` — shared result codes, the per-connection `Shadow` struct, and the engine API.
- `src/tlsfix_engine.c` — the OpenSSL core: shadow table, the CFNetwork↔BIO bridge, system-trust
  verification, client-identity signing, and one-time setup.
- `src/tlsfix_hooks.c` — the Secure Transport hooks and the injection constructor.
- `src/tlsfix_status.c`which Secure Transport status and session state a failure is reported as.
- `src/tlsfix.plist` — the MobileSubstrate filter (which processes get injected).

### Note on Pinning and mutual TLS

- As stated before, when an app drives its own trust
  (SSL Pinning), TLSFix defers the decision completely, the app sees the real peer certificate via `SSLCopyPeerTrust` and runs its logic. But the **connection itself is still handled by TLSFix**, it runs the modern handshake and crypto the legacy stack cant. So an app that both validates and pins still gets a connection that was impossible before, TLSFix only hands back the trust result but not the cypher.

- **Mutual TLS works** the same way (APNs, iMessage, and other client-certificate services). The client identity is signed through iOS `SecKeyRawSign` so the private key is never extracted, but the handshake carrying that identity is again TLSFix's modern one, so these services work with servers that now require a cipher the old stack dosent have.

## Credits

[nfzerox](https://github.com/nfzerox): Made the original tweak, and idea!

[ObscureMosquito](https://github.com/ObscureMosquito): Rewrote for OpenSSL, system trust store, SSL pinning, better legacy and system support!
