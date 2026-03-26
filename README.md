# CRYpT — Free Edition

**COS TRINITY** · [costrinity.xyz](https://costrinity.xyz)

Desktop file encryption built on the **Costrinity Cipher Language (CCL)** — a novel protocol where the cipher pipeline structure is derived from your key. The algorithm itself is secret.

## Free Tier

| Mode | KDF Memory | Use Case |
|------|-----------|----------|
| Standard | ~384MB | General use |
| Military | ~768MB | Sensitive files |

## CRYpT Pro ($14.99 — lifetime)

| Mode | KDF Memory | Use Case |
|------|-----------|----------|
| Paranoid | ~1.5GB | High-value targets |
| FORTRESS | ~3GB | Maximum security |

Upgrade at **[costrinity.xyz/crypt](https://costrinity.xyz/crypt)**

---

## Architecture

22-layer encryption pipeline:

```
L0   Triple KDF: Argon2id → scrypt → HKDF-SHA3
L1   zlib compression
L2   Dual canary (head + tail)
L3   Random padding (512–8192B)
L4   SHAKE-256 pre-whitening (Keccak XOF)
L5   CCL S-Box ×4–8 (key-derived pass count)
L6   Cascade diffusion (SHAKE-256 keystream)
L7   Block permutation (transposition)
L8   CCL Feistel ×3–6 (BLAKE2b PRF, 64–127 rounds each)
L9   SHAKE-256 post-whitening (Keccak XOF)
L10  AES-256-GCM #1
L11  XChaCha20-Poly1305 #1
L12  AES-256-GCM #2
L13  XChaCha20-Poly1305 #2
L14  AES-256-GCM #3
L15  XChaCha20-Poly1305 #3
L16  Quintuple integrity: 2×HMAC-SHA3 + BLAKE2b + HMAC-SHA512 + full-file HMAC
```

**CCL Innovation:** S-Box passes (4–8), Feistel passes (3–6), and rounds per Feistel (64–127) are all derived from the master key. An attacker observing the ciphertext has no idea what operations were performed.

**Triple KDF:** An attacker must defeat Argon2id *then* scrypt *then* HKDF-SHA3 sequentially. Parallelizing them produces wrong keys.

## Build

```bash
go build -o CRYpT.exe .    # Windows
go build -o CRYpT .        # macOS / Linux
```

Requires Go 1.21+ and system OpenGL/X11 libraries.

## License

Source available for inspection. Compiled binaries available at [costrinity.xyz/crypt](https://costrinity.xyz/crypt).

---

Built by [Collin Obey](https://x.com/COSTRINITY) · COS TRINITY 🔱
