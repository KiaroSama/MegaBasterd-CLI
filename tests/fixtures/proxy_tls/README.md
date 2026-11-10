# Public offline TLS fixtures

These are PUBLIC, NON-SECRET TEST-ONLY credentials and certificates copied without modification
from rustls 0.23.46, commit `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`.
Never use this public test key for an account, production TLS, artifact signing, or an installation.
Tests trust this CA in an isolated client configuration only; they never install a machine root.
Production proxy clients use the platform verifier, not this CA.

Upstream: https://github.com/rustls/rustls/tree/f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb/test-ca/rsa-2048
License: MIT; the complete upstream notice is in `LICENSE-MIT.txt`.
The Rustls Test CA README identifies these as integration-test fixtures.

| Local file | Upstream file | SHA-256 |
| --- | --- | --- |
| `root.der` | `ca.der` | `316376e1a51676e89092ef268141926e375d2a3da21796b50be42e988463b807` |
| `server.der` | `end.der` | `a317c8ff73014e9dc2b199f19c05aa20b5aab15b5d137948a86fdcbc8a772473` |
| `intermediate.der` | `inter.der` | `07fd827dbcf16beb9b7657e9bea824edd4aa67c38af30de6e0ea8e19e60a9f43` |
| `public-test-key.txt` | `end.key` | `b8bc05c6b34043701ee34a21c92eb3299408499edaffafb6fcd60ccc8a7dc81b` |

The server certificate covers `testserver.com`, `second.testserver.com`, and `localhost`;
validity is 1975-01-01 through 4096-01-01 UTC. Tests use its original DNS name, never replace
hostname verification with an IP certificate or permissive verifier. Fixture Git blob hashes were
checked against the exact upstream content API before saving. No upstream generator was executed.
