# Release owner signatures

The owner explicitly selected a dedicated self-signed certificate for this project.
This proves possession of the pinned owner key, not public certificate-authority
trust. Windows SmartScreen/Gatekeeper warnings may remain. macOS releases are not
Apple-notarized. No command here installs a trusted root or disables an OS policy.

Public certificate SHA-256:

```text
f3347ef7108b0024c794aa6b01da997264846a27bbf8df726c954444d5f89575
```

Compare that fingerprint through an independently trusted copy of this page before
accepting a release. Certificate rotation requires an explicit published transition;
a certificate supplied beside an archive is not sufficient trust on its own.

## Verify before extraction

Download the target `.tar.gz`, its `.sha256`, `.tar.gz.p7s`,
`OWNER-CERTIFICATE.cer` and `Verify-Release.ps1` from the same release. Review the
verifier from this repository before running it. PowerShell 7 is required by the
verifier, not by the application. Replace the archive name with the actual target.

```bash
pwsh -NoProfile -File Verify-Release.ps1 -Archive megabasterd-cli-2.0.0-x86_64-pc-windows-msvc.tar.gz -Certificate OWNER-CERTIFICATE.cer
```

The verifier checks the pinned certificate fingerprint, validity, detached CMS
signature, exact signer and archive digest. It fails on a changed archive, different
certificate, missing signature or checksum mismatch. It does not extract or execute
the archive, import a root certificate or change your security settings.

After verification, extract into a new empty directory and inspect `SIGNING.json`
for the exact source commit. Check `SHA256SUMS` for every installed file. The native
commands are `mb`, `mbcli` and `megabasterd-cli`. Windows binaries carry Authenticode
and macOS binaries carry native code signatures. Linux archives use detached CMS.

## Build and custody boundary

The manual release workflow forwards only two dedicated protected inputs to the
packaging step. Ordinary tests and source packages never contain private signing
material. Windows PE resources carry the publisher, product, version and exact source commit;
the native CI checks all three aliases before signing. On every platform,
`mb --no-log-file -v config get max_workers` reports the embedded publisher and
source commit on stderr; stdout remains the setting value. Cargo refuses dirty
source-package inputs; the corresponding source archive must carry a clean
`.cargo_vcs_info.json` for that exact commit. Native signing occurs before
member checksums; detached signing occurs
after archive creation. A final archive cannot be relabeled from unsigned bytes.
Windows verification checks the native payload signature and pinned owner certificate
without modifying a trusted-root store. Only success or the exact untrusted-root
chain result is eligible; other errors fail. A changed PE payload or different owner
must be rejected. Neither the hosted runner nor the user's machine gains root trust.
The macOS runner uses an isolated temporary keychain, temporarily adds it to the
runner's keychain search list, restores the previous list and removes it in cleanup.
This does not install a trusted root or change certificate trust policy.
Its mode-700 scratch directory contains a mode-600 PKCS#12 transport with a
nonsecret, fixed transport password. Unlike an empty password, this produces an
encrypted key bag that Apple's importer accepts; the password is not a security
boundary. The protected directory and deletion are mandatory. Private key material
and the real custody password never appear in process arguments. The transport
is never published or cached and is deleted with the keychain; protected recovery
custody and native SHA-256 signatures are unchanged.

The release process verifies tamper rejection and native signatures. The owner
retains an exportable protected recovery key outside published artifacts. No public
CA, timestamp authority, Apple Developer ID or notarization is asserted.
