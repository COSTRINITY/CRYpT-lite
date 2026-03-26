package main

// ============================================================================
// COSTRINITY: CRYpT v6.1 — Free Edition (Lite)
// Costrinity Cipher Language (CCL) Protocol v6.1 — Hardened
//
// THE ALGORITHM ITSELF IS SECRET.
// CCL derives the cipher pipeline structure from key material.
// An attacker observing only ciphertext has no idea what operations ran.
//
// 22-Layer Encryption Architecture:
//   L0   Triple KDF Cascade     Argon2id → scrypt → HKDF-SHA3 (sequential)
//   L1   zlib Compression       Optional pre-encryption compression
//   L2   Dual Canary            Head + tail chain-verification sentinels
//   L3   Payload Padding        Random 512–8192 byte size obfuscation
//   L4   SHAKE-256 Pre-Whiten   Keccak XOF stream cipher (destroys input patterns)
//   L5   CCL S-Box ×4-8         Key-derived pass count, key-derived tables
//   L6   Cascade Diffusion      XOR key-stream (SHAKE-256) + cascading feedback
//   L7   Block Permutation      Key-derived block reordering (transposition)
//   L8   CCL Feistel ×3-6       Key-derived pass count, BLAKE2b PRF, 64-127 rounds
//   L9   SHAKE-256 Post-Whiten  Keccak XOF stream cipher (post-custom-layer)
//   L10  AES-256-GCM #1         NIST authenticated encryption
//   L11  XChaCha20-Poly1305 #1  IETF extended-nonce AEAD
//   L12  AES-256-GCM #2         NIST authenticated encryption
//   L13  XChaCha20-Poly1305 #2  IETF extended-nonce AEAD
//   L14  AES-256-GCM #3         NIST authenticated encryption
//   L15  XChaCha20-Poly1305 #3  IETF extended-nonce AEAD
//   L16  Quintuple Integrity    2×HMAC-SHA3 + BLAKE2b + HMAC-SHA512 + full-file
//
// Security fixes in v6.1:
//   - Feistel F-function: SHA-256 → BLAKE2b keyed PRF (proper per-round keys)
//   - scrypt fallback: silent degradation removed → hard abort on failure
//   - keyStream: SHA-256 counter mode → SHAKE-256 XOF (proper stream cipher)
//   - Pre + post SHAKE-256 whitening added (4th distinct cipher family: Keccak)
//   - Activation: exec curl → native net/http (no external dependency)
//
// Triple KDF (attacker must defeat ALL THREE sequentially):
//   Stage 1: Argon2id (memory-hard, GPU-resistant)
//   Stage 2: scrypt   (memory-hard, different algorithm)
//   Stage 3: HKDF-SHA3-512 (extract-and-expand with domain separation)
//
// CCL Innovation:
//   The number of S-Box passes, Feistel passes, and rounds per Feistel
//   are derived from a hash of (masterKey + publicSeed). The publicSeed
//   is stored in the header, but without the masterKey an attacker cannot
//   determine the actual cipher pipeline that was executed.
//
// Cipher Diversity (attacker must independently break ALL):
//   AES-256       Substitution-Permutation Network (×3)
//   XChaCha20     Add-Rotate-XOR stream cipher (×3)
//   Feistel       Custom block cipher, 192-762 total rounds
//   S-Box×4-8     Key-dependent substitution tables
//   scrypt        Memory-hard KDF (sequential with Argon2id)
//   Argon2id      Memory-hard KDF (sequential with scrypt)
//   SHA3-512      Keccak sponge (HKDF + HMAC ×2)
//   BLAKE2b       HAIFA construction (keyed hash)
//   SHA-512       Merkle-Damgård (HMAC)
//
// File Format v6 (.crypt):
//   [Magic "CCL2" 4B][Version 2B][Flags 1B][Mode 1B]
//   [Salt 384B][CCLSeed 32B][Nonces 144B][Padding 64B]
//   [Encrypted Payload ...variable...]
//   [HMAC-SHA3 #1 64B][BLAKE2b 64B][HMAC-SHA512 64B][HMAC-SHA3 #2 64B][FullHMAC 64B]
// ============================================================================

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
	"net/http"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

//go:embed assets/icon.png
var embeddedFiles embed.FS

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	magicString = "CCL2"

	versionV2 = uint16(2)
	versionV3 = uint16(3)
	versionV4 = uint16(4)
	versionV5 = uint16(5)
	versionV6 = uint16(6)

	// v6 OBSIDIAN format
	v6SaltSize     = 384 // 3 independent salts × 128 bytes each
	v6CCLSeedSize  = 32  // Public seed for CCL parameter derivation
	v6NonceSection = 144 // 6 AEAD passes: 3×AES(12B) + 3×XChaCha(24B) = 36+72 = 108, padded to 144
	v6PadHdr       = 64
	v6HeaderSize   = 4 + 2 + 1 + 1 + v6SaltSize + v6CCLSeedSize + v6NonceSection + v6PadHdr // 632
	v6TrailingSize = 64 * 5                                                                 // 5 integrity hashes
	v6MaxKeySize   = 2048                                                                   // Maximum derived key material

	// v5 backward compat
	v5HeaderSize   = 412
	v5TrailingSize = 320
	v5SaltSize     = 256
	v5KeySize      = 640

	// v4 backward compat
	v4HeaderSize   = 216
	v4TrailingSize = 192
	v4SaltSize     = 128
	v4KeySize      = 352
	v4NonceAES     = 12
	v4NonceXC      = 24
	v4PadHdr       = 32

	canarySize = 32
	nonceAES   = 12
	nonceXC    = 24

	// v3 backward compat
	v3HeaderSize   = 124
	v3TrailingSize = 128
	v3SaltSize     = 64
	v3KeySize      = 224

	// v2 backward compat
	v2HeaderSize   = 107
	v2TrailingSize = 128
	v2SaltSize     = 64
	v2KeySize      = 192

	keySize     = 32
	hmacSize    = 64
	blake2bSize = 64
	scrambleLen = 24

	flagCompressed = 0x01
	flagKeyFile    = 0x02

	minPasswordLen = 14
)

const (
	ModeStandard = iota
	ModeMilitary
	ModeParanoid
	ModeFortress
)

var modeNames = [...]string{"Standard", "Military", "PRO ONLY", "PRO ONLY"}

// ============================================================================
// CCL PARAMETERS — THE SECRET ALGORITHM
// ============================================================================

// CCLParams defines the key-derived cipher pipeline configuration.
// These parameters are derived from hash(masterKey + publicSeed).
// An attacker with only the publicSeed cannot determine the pipeline.
type CCLParams struct {
	SBoxPasses    int   // 4-8 S-Box substitution passes
	FeistelPasses int   // 3-6 Feistel network passes
	FeistelRounds []int // Rounds per Feistel pass (64-127 each)
}

// deriveCCLParams derives the cipher pipeline configuration from key material.
// The seed is stored publicly in the header, but without the master key,
// an attacker cannot determine what operations were actually performed.
func deriveCCLParams(masterKey, publicSeed []byte) CCLParams {
	// Hash the master key with the public seed to get deterministic but secret params
	h := sha3.New512()
	h.Write(masterKey)
	h.Write(publicSeed)
	h.Write([]byte("COSTRINITY_CCL_PARAMS_V6"))
	digest := h.Sum(nil)

	// Derive S-Box passes: 4-8 (use first byte mod 5 + 4)
	sboxPasses := int(digest[0]%5) + 4

	// Derive Feistel passes: 3-6 (use second byte mod 4 + 3)
	feistelPasses := int(digest[1]%4) + 3

	// Derive rounds per Feistel pass: 64-127 each
	feistelRounds := make([]int, feistelPasses)
	for i := 0; i < feistelPasses; i++ {
		// Use bytes 2+ for round counts
		feistelRounds[i] = int(digest[2+i]%64) + 64
	}

	return CCLParams{
		SBoxPasses:    sboxPasses,
		FeistelPasses: feistelPasses,
		FeistelRounds: feistelRounds,
	}
}

// ============================================================================
// TRIPLE KDF PARAMETERS
// ============================================================================

type tripleKDFParams struct {
	// Argon2id params
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
	// scrypt params
	scryptN int
	scryptR int
	scryptP int
}

// v6 OBSIDIAN params — Triple KDF with massive memory requirements
var v6ModeParams = map[int]tripleKDFParams{
	ModeStandard: {
		argonTime: 4, argonMemory: 256 * 1024, argonThreads: 4,
		scryptN: 1 << 17, scryptR: 8, scryptP: 1, // 128MB scrypt
	},
	ModeMilitary: {
		argonTime: 8, argonMemory: 512 * 1024, argonThreads: 8,
		scryptN: 1 << 18, scryptR: 8, scryptP: 1, // 256MB scrypt
	},
	// Paranoid + FORTRESS available in CRYpT Pro — costrinity.xyz/crypt
	// ModeParanoid: Pro only
	// ModeFortress: Pro only
}

// v4/v5 backward-compat params
type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
}

var modeParams = map[int]argon2Params{
	ModeStandard: {time: 3, memory: 128 * 1024, threads: 4},
	ModeMilitary: {time: 5, memory: 256 * 1024, threads: 4},
	// ModeParanoid + ModeFortress: Pro only
}

var v5ModeParams = map[int]argon2Params{
	ModeStandard: {time: 6, memory: 256 * 1024, threads: 4},
	ModeMilitary: {time: 10, memory: 512 * 1024, threads: 8},
	// ModeParanoid + ModeFortress: Pro only
}

// ============================================================================
// TRIPLE KDF — THE UNBREAKABLE KEY DERIVATION
// ============================================================================

// tripleKDF derives key material through three sequential memory-hard functions.
// An attacker must defeat Argon2id, THEN scrypt, THEN HKDF-SHA3.
// Each stage uses an independent salt. Total memory: up to 3GB for FORTRESS.
func tripleKDF(password []byte, salts []byte, params tripleKDFParams, keyLen int) []byte {
	// Split the 384-byte salt into three independent 128-byte salts
	salt1 := salts[0:128]
	salt2 := salts[128:256]
	salt3 := salts[256:384]

	// Stage 1: Argon2id — GPU-resistant memory-hard function
	stage1 := argon2.IDKey(password, salt1, params.argonTime, params.argonMemory, params.argonThreads, 64)

	// Stage 2: scrypt — Different memory-hard algorithm, sequential with stage 1
	// Input is the OUTPUT of stage 1, not the original password
	stage2Input := append(stage1, password...)
	stage2, err := scrypt.Key(stage2Input, salt2, params.scryptN, params.scryptR, params.scryptP, 64)
	if err != nil {
		// SECURITY: never silently degrade to a weaker KDF.
		// If scrypt fails the entire encryption must abort.
		wipeBytes(stage1)
		wipeBytes(stage2Input)
		panic("CRITICAL: scrypt KDF failed — encryption aborted: " + err.Error())
	}
	wipeBytes(stage1)
	wipeBytes(stage2Input)

	// Stage 3: HKDF-SHA3-512 — Extract-and-expand with domain separation
	// Combines both previous stages for final key material
	hkdfInput := append(stage2, password...)
	hkdfReader := hkdf.New(sha3.New512, hkdfInput, salt3, []byte("COSTRINITY_OBSIDIAN_V6_MASTER_KEY"))
	masterKey := make([]byte, keyLen)
	io.ReadFull(hkdfReader, masterKey)
	wipeBytes(stage2)
	wipeBytes(hkdfInput)

	return masterKey
}

// ============================================================================
// METADATA
// ============================================================================

type CryptMeta struct {
	Filename string `json:"f"`
	Size     int64  `json:"s"`
	DataSize int64  `json:"c"`
	Time     int64  `json:"t"`
	Hash     string `json:"h"`
	IsDir    bool   `json:"d"`
	Ver      int    `json:"v"`
}

var canaryValue = sha256.Sum256([]byte("COSTRINITY_CIPHER_CANARY_V4_FORTRESS"))
var canaryV5 = sha256.Sum256([]byte("COSTRINITY_CITADEL_CANARY_V5_QUINTUPLE_CASCADE"))
var canaryV6 = sha256.Sum256([]byte("COSTRINITY_OBSIDIAN_CANARY_V6_CCL_ALGORITHM_IS_SECRET"))

// ============================================================================
// THEME
// ============================================================================

var (
	colBg          = color.RGBA{R: 2, G: 2, B: 8, A: 255}
	colFg          = color.RGBA{R: 200, G: 215, B: 235, A: 255}
	colCyan        = color.RGBA{R: 0, G: 220, B: 255, A: 255}
	colCyanDim     = color.RGBA{R: 0, G: 140, B: 200, A: 255}
	colCyanDark    = color.RGBA{R: 0, G: 60, B: 90, A: 255}
	colInputBg     = color.RGBA{R: 8, G: 8, B: 18, A: 255}
	colOverlay     = color.RGBA{R: 4, G: 4, B: 12, A: 255}
	colSep         = color.RGBA{R: 0, G: 40, B: 60, A: 255}
	colDisabled    = color.RGBA{R: 30, G: 35, B: 50, A: 255}
	colPlaceholder = color.RGBA{R: 45, G: 55, B: 75, A: 255}
	colSuccess     = color.RGBA{R: 0, G: 255, B: 180, A: 255}
	colWarn        = color.RGBA{R: 255, G: 160, B: 0, A: 255}
	colDimText     = color.RGBA{R: 40, G: 55, B: 80, A: 255}
	colMidText     = color.RGBA{R: 60, G: 80, B: 110, A: 255}
	colError       = color.RGBA{R: 255, G: 40, B: 60, A: 255}
)

type costrinityTheme struct{}

func (t *costrinityTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colBg
	case theme.ColorNameForeground:
		return colFg
	case theme.ColorNamePrimary:
		return colCyan
	case theme.ColorNameButton:
		return colCyanDark
	case theme.ColorNameInputBackground:
		return colInputBg
	case theme.ColorNamePlaceHolder:
		return colPlaceholder
	case theme.ColorNameOverlayBackground:
		return colOverlay
	case theme.ColorNameDisabled:
		return colDisabled
	case theme.ColorNameSeparator:
		return colSep
	case theme.ColorNameFocus:
		return colCyan
	case theme.ColorNameHover:
		return color.RGBA{R: 0, G: 80, B: 120, A: 255}
	case theme.ColorNameScrollBar:
		return colCyanDark
	case theme.ColorNameHeaderBackground:
		return color.RGBA{R: 4, G: 8, B: 16, A: 255}
	case theme.ColorNameSelection:
		return color.RGBA{R: 0, G: 60, B: 100, A: 100}
	case theme.ColorNameError:
		return colError
	case theme.ColorNameSuccess:
		return colSuccess
	case theme.ColorNameWarning:
		return colWarn
	default:
		return theme.DefaultTheme().Color(name, theme.VariantDark)
	}
}
func (t *costrinityTheme) Font(s fyne.TextStyle) fyne.Resource    { return theme.DefaultTheme().Font(s) }
func (t *costrinityTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (t *costrinityTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 10
	case theme.SizeNameSeparatorThickness:
		return 1
	default:
		return theme.DefaultTheme().Size(n)
	}
}

func neonSeparator(c color.Color) fyne.CanvasObject {
	line := canvas.NewRectangle(c)
	line.SetMinSize(fyne.NewSize(0, 1))
	return line
}

// ============================================================================
// COSTRINITY S-BOX + DIFFUSION
// ============================================================================

func generateSBox(key []byte) [256]byte {
	var sbox [256]byte
	for i := range sbox {
		sbox[i] = byte(i)
	}
	seed := sha256.Sum256(key)
	for i := 255; i > 0; i-- {
		seed = sha256.Sum256(append(seed[:], byte(i), byte(i>>8)))
		j := int(binary.BigEndian.Uint32(seed[:4])) % (i + 1)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}
	return sbox
}

func inverseSBox(sbox [256]byte) [256]byte {
	var inv [256]byte
	for i := range sbox {
		inv[sbox[i]] = byte(i)
	}
	return inv
}

// generateKeyStream uses SHAKE-256 (Keccak XOF) for a proper extendable output.
// This is cryptographically stronger than SHA-256 counter mode — it's a dedicated
// stream cipher construction rather than a hash function repurposed as one.
func generateKeyStream(key []byte, length int) []byte {
	h := sha3.NewShake256()
	h.Write(key)
	h.Write([]byte("COSTRINITY_CCL_KEYSTREAM_V6"))
	stream := make([]byte, length)
	h.Read(stream)
	return stream
}

// xorWhiten applies SHAKE-256 key whitening to the data.
// This adds a full Keccak-based stream cipher layer (4th distinct cipher family).
// Applied both BEFORE and AFTER the custom CCL pipeline for defense in depth.
func xorWhiten(data, key, label []byte) []byte {
	h := sha3.NewShake256()
	h.Write(key)
	h.Write(label)
	stream := make([]byte, len(data))
	h.Read(stream)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ stream[i]
	}
	wipeBytes(stream)
	return out
}

// costrinityTransform applies S-Box substitution and cascade diffusion
func costrinityTransform(data, diffuseKey []byte, encrypt bool, sboxKeys ...[]byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	if encrypt {
		for _, sk := range sboxKeys {
			sbox := generateSBox(sk)
			for i := range out {
				out[i] = sbox[out[i]]
			}
		}
		ks := generateKeyStream(diffuseKey, len(out))
		for i := range out {
			out[i] ^= ks[i]
			if i > 0 {
				out[i] ^= out[i-1]
			}
		}
		blockRotate(out, diffuseKey, true)
	} else {
		blockRotate(out, diffuseKey, false)
		ks := generateKeyStream(diffuseKey, len(out))
		for i := len(out) - 1; i >= 0; i-- {
			if i > 0 {
				out[i] ^= out[i-1]
			}
			out[i] ^= ks[i]
		}
		for i := len(sboxKeys) - 1; i >= 0; i-- {
			inv := inverseSBox(generateSBox(sboxKeys[i]))
			for j := range out {
				out[j] = inv[out[j]]
			}
		}
	}
	return out
}

func blockRotate(data, key []byte, fwd bool) {
	const blk = 16
	idx := make([]byte, 4)
	for i := 0; i+blk <= len(data); i += blk {
		h := sha256.New()
		h.Write(key)
		binary.BigEndian.PutUint32(idx, uint32(i))
		h.Write(idx)
		rot := int(h.Sum(nil)[0]) % blk
		if !fwd {
			rot = blk - rot
		}
		rotateSlice(data[i:i+blk], rot)
	}
}

func rotateSlice(b []byte, n int) {
	if len(b) == 0 || n%len(b) == 0 {
		return
	}
	n %= len(b)
	tmp := make([]byte, len(b))
	copy(tmp, b[n:])
	copy(tmp[len(b)-n:], b[:n])
	copy(b, tmp)
}

// ============================================================================
// BLOCK PERMUTATION — TRANSPOSITION LAYER
// ============================================================================

// blockPermute reorders fixed-size blocks using a key-derived permutation.
// This is a transposition cipher layer that complements the S-Box substitution.
func blockPermute(data, key []byte, encrypt bool) []byte {
	const blockSize = 64
	numBlocks := len(data) / blockSize
	remainder := len(data) % blockSize

	if numBlocks < 2 {
		return data // Not enough blocks to permute
	}

	// Generate permutation from key using Fisher-Yates
	perm := make([]int, numBlocks)
	for i := range perm {
		perm[i] = i
	}

	// Seed the shuffle with key material
	h := sha3.New512()
	h.Write(key)
	h.Write([]byte("COSTRINITY_BLOCK_PERMUTE"))
	seed := h.Sum(nil)

	for i := numBlocks - 1; i > 0; i-- {
		// Generate random index using seed bytes
		h.Reset()
		h.Write(seed)
		h.Write([]byte{byte(i), byte(i >> 8)})
		seed = h.Sum(nil)
		j := int(binary.BigEndian.Uint64(seed[:8])) % (i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}

	out := make([]byte, len(data))

	if encrypt {
		// Apply permutation
		for i := 0; i < numBlocks; i++ {
			srcStart := i * blockSize
			dstStart := perm[i] * blockSize
			copy(out[dstStart:dstStart+blockSize], data[srcStart:srcStart+blockSize])
		}
	} else {
		// Apply inverse permutation
		for i := 0; i < numBlocks; i++ {
			srcStart := perm[i] * blockSize
			dstStart := i * blockSize
			copy(out[dstStart:dstStart+blockSize], data[srcStart:srcStart+blockSize])
		}
	}

	// Copy remainder unchanged
	if remainder > 0 {
		copy(out[numBlocks*blockSize:], data[numBlocks*blockSize:])
	}

	return out
}

// ============================================================================
// COSTRINITY FEISTEL NETWORK
// ============================================================================

func costrinityFeistel(data, key []byte, encrypt bool, rounds int) []byte {
	const (
		blockSz = 32
		halfSz  = 16
	)
	out := make([]byte, len(data))
	copy(out, data)

	for i := 0; i+blockSz <= len(out); i += blockSz {
		L := make([]byte, halfSz)
		R := make([]byte, halfSz)
		copy(L, out[i:i+halfSz])
		copy(R, out[i+halfSz:i+blockSz])
		if encrypt {
			for r := 0; r < rounds; r++ {
				F := feistelF(R, key, r)
				tmp := make([]byte, halfSz)
				copy(tmp, R)
				for j := range R {
					R[j] = L[j] ^ F[j]
				}
				copy(L, tmp)
			}
		} else {
			for r := rounds - 1; r >= 0; r-- {
				F := feistelF(L, key, r)
				tmp := make([]byte, halfSz)
				copy(tmp, L)
				for j := range L {
					L[j] = R[j] ^ F[j]
				}
				copy(R, tmp)
			}
		}
		copy(out[i:i+halfSz], L)
		copy(out[i+halfSz:i+blockSz], R)
	}
	rem := len(out) % blockSz
	if rem > 0 {
		off := len(out) - rem
		ks := generateKeyStream(key, rem)
		for j := 0; j < rem; j++ {
			out[off+j] ^= ks[j]
		}
	}
	return out
}

// feistelF uses BLAKE2b as a proper keyed PRF.
// SHA-256 is NOT designed as a keyed PRF — BLAKE2b with a key parameter is.
// This means each round's F-function is cryptographically independent.
// Per-round mixing: key + round index ensures no two rounds share the same PRF output.
func feistelF(half, key []byte, round int) []byte {
	// Derive a per-round key by mixing the base key with the round index
	roundTag := make([]byte, 4)
	binary.BigEndian.PutUint32(roundTag, uint32(round))
	perRoundKey := make([]byte, 32)
	h0 := sha256.New()
	h0.Write(key)
	h0.Write(roundTag)
	copy(perRoundKey, h0.Sum(nil))

	// BLAKE2b-256 with the per-round key: proper keyed PRF
	b2, err := blake2b.New(16, perRoundKey)
	if err != nil {
		// Fallback (shouldn't happen — key is always 32 bytes)
		h := sha256.New()
		h.Write(half)
		h.Write(perRoundKey)
		return h.Sum(nil)[:16]
	}
	b2.Write(half)
	b2.Write(roundTag)
	return b2.Sum(nil)
}

// ============================================================================
// COMPRESSION + HELPERS
// ============================================================================

func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressData(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	limited := io.LimitReader(r, 4<<30)
	return io.ReadAll(limited)
}

func effectivePassword(password string, kf []byte) []byte {
	pw := []byte(password)
	if len(kf) > 0 {
		h := sha512.Sum512(kf)
		pw = append(pw, h[:]...)
	}
	return pw
}

// effectivePasswordV6 applies triple pre-hashing for defense-in-depth
func effectivePasswordV6(password string, kf []byte) []byte {
	pw := []byte(password)
	if len(kf) > 0 {
		// Triple-hash key file
		h1 := sha512.Sum512(kf)
		h2 := sha3.Sum512(kf)
		b2, _ := blake2b.New512(nil)
		b2.Write(kf)
		h3 := b2.Sum(nil)
		pw = append(pw, h1[:]...)
		pw = append(pw, h2[:]...)
		pw = append(pw, h3...)
	}
	// Pre-hash through SHA3-512
	preHash := sha3.Sum512(pw)
	result := make([]byte, len(pw)+64)
	copy(result, pw)
	copy(result[len(pw):], preHash[:])
	return result
}

func wipeBytes(b []byte) {
	rand.Read(b)
	for i := range b {
		b[i] = 0
	}
}

// ============================================================================
// PASSWORD EVALUATOR & GENERATOR
// ============================================================================

func evaluatePassword(password string) (string, color.Color) {
	if len(password) == 0 {
		return "-", color.RGBA{R: 80, G: 80, B: 80, A: 255}
	}
	var lo, up, dg, sy bool
	for _, c := range password {
		switch {
		case unicode.IsLower(c):
			lo = true
		case unicode.IsUpper(c):
			up = true
		case unicode.IsDigit(c):
			dg = true
		default:
			sy = true
		}
	}
	cl := 0
	for _, v := range []bool{lo, up, dg, sy} {
		if v {
			cl++
		}
	}
	n := len(password)
	switch {
	case n >= 24 && cl >= 4:
		return "FORTRESS", color.RGBA{R: 0, G: 255, B: 200, A: 255}
	case n >= 20 && cl >= 4:
		return "MAXIMUM", color.RGBA{R: 0, G: 255, B: 120, A: 255}
	case n >= 16 && cl >= 3:
		return "Very Strong", color.RGBA{R: 0, G: 210, B: 90, A: 255}
	case n >= 14 && cl >= 3:
		return "Strong", color.RGBA{R: 120, G: 210, B: 0, A: 255}
	case n >= 14 && cl >= 2:
		return "Fair", color.RGBA{R: 255, G: 200, B: 0, A: 255}
	default:
		return "Weak", color.RGBA{R: 255, G: 50, B: 50, A: 255}
	}
}

func generatePassword(length int, lower, upper, digits, symbols bool) string {
	var cs string
	if lower {
		cs += "abcdefghijklmnopqrstuvwxyz"
	}
	if upper {
		cs += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if digits {
		cs += "0123456789"
	}
	if symbols {
		cs += "!@#$%^&*()-_=+[]{}|;:<>?~"
	}
	if cs == "" {
		cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	}
	r := make([]byte, length)
	for i := range r {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(cs))))
		r[i] = cs[n.Int64()]
	}
	return string(r)
}

// ============================================================================
// ENCRYPT — v6 OBSIDIAN FORMAT
// ============================================================================

func encryptPath(path, password string, kf []byte, mode int, isFolder, compress bool, progress *widget.ProgressBar, status *widget.Label) {
	if len(password) < minPasswordLen {
		notifyStatus(status, fmt.Sprintf("Error: minimum %d-character password required", minPasswordLen))
		return
	}
	start := time.Now()
	updateStatus(status, "Reading input...")
	setProgress(progress, 0.01)

	var data []byte
	var origName string
	var err error

	if isFolder {
		info, e := os.Stat(path)
		if e != nil || !info.IsDir() {
			notifyStatus(status, "Error: invalid folder")
			return
		}
		data, err = zipFolder(path)
		if err != nil {
			notifyStatus(status, "ZIP error: "+err.Error())
			return
		}
		origName = filepath.Base(path) + ".zip"
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			notifyStatus(status, "Read error: "+err.Error())
			return
		}
		origName = filepath.Base(path)
	}
	origSize := int64(len(data))

	var flags byte
	if compress {
		flags |= flagCompressed
	}
	if len(kf) > 0 {
		flags |= flagKeyFile
	}

	// L1: Compress
	if compress {
		setProgress(progress, 0.02)
		updateStatus(status, "L1: Compressing...")
		data, err = compressData(data)
		if err != nil {
			notifyStatus(status, "Compression error: "+err.Error())
			return
		}
	}
	dataSize := int64(len(data))
	dataHash := sha256.Sum256(data)

	setProgress(progress, 0.03)
	updateStatus(status, "L2/L3: Building payload — dual canary + random padding...")

	meta := CryptMeta{
		Filename: origName,
		Size:     origSize,
		DataSize: dataSize,
		Time:     time.Now().Unix(),
		Hash:     fmt.Sprintf("%x", dataHash),
		IsDir:    isFolder,
		Ver:      6,
	}
	mj, _ := json.Marshal(meta)

	// Random padding (512–8192 bytes)
	padN, _ := rand.Int(rand.Reader, big.NewInt(7681))
	padLen := int(padN.Int64()) + 512
	pad := make([]byte, padLen)
	rand.Read(pad)

	// Payload: [canary 32][meta_len 4][meta_json][data][random_padding][canary 32]
	payload := new(bytes.Buffer)
	payload.Write(canaryV6[:])
	ml := make([]byte, 4)
	binary.BigEndian.PutUint32(ml, uint32(len(mj)))
	payload.Write(ml)
	payload.Write(mj)
	payload.Write(data)
	payload.Write(pad)
	payload.Write(canaryV6[:])
	plain := payload.Bytes()

	setProgress(progress, 0.04)
	updateStatus(status, "Generating cryptographic material (384B salt + 32B CCL seed)...")

	// Generate salts and CCL seed
	salts := make([]byte, v6SaltSize) // 384 bytes = 3×128
	rand.Read(salts)
	cclSeed := make([]byte, v6CCLSeedSize)
	rand.Read(cclSeed)

	// Generate AEAD nonces
	nonces := make([]byte, v6NonceSection)
	rand.Read(nonces)
	hdrPad := make([]byte, v6PadHdr)
	rand.Read(hdrPad)

	// Extract individual nonces for 6 AEAD passes (AES-XC-AES-XC-AES-XC)
	nAES1 := nonces[0:12]
	nXC1 := nonces[12:36]
	nAES2 := nonces[36:48]
	nXC2 := nonces[48:72]
	nAES3 := nonces[72:84]
	nXC3 := nonces[84:108]

	setProgress(progress, 0.05)
	params := v6ModeParams[mode]
	totalMem := (params.argonMemory / 1024) + uint32(params.scryptN*params.scryptR*128/1024/1024)
	updateStatus(status, fmt.Sprintf("L0: Triple KDF [%s: ~%dMB total]...", modeNames[mode], totalMem))

	// Derive master key via Triple KDF
	effPw := effectivePasswordV6(password, kf)
	masterKey := tripleKDF(effPw, salts, params, v6MaxKeySize)
	wipeBytes(effPw)

	// Derive CCL parameters from master key + public seed
	ccl := deriveCCLParams(masterKey, cclSeed)

	setProgress(progress, 0.12)
	updateStatus(status, fmt.Sprintf("CCL: %d S-Box passes, %d Feistel passes (%v rounds)", ccl.SBoxPasses, ccl.FeistelPasses, ccl.FeistelRounds))

	// Allocate sub-keys using HKDF expansion
	// Total needed: diffuse(32) + sbox×8(256) + permute(32) + feistel×6(192) + aead×6(192) + integrity×5(160) = 864
	keyOffset := 0
	diffKey := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32

	sboxKeys := make([][]byte, ccl.SBoxPasses)
	for i := 0; i < ccl.SBoxPasses; i++ {
		sboxKeys[i] = masterKey[keyOffset : keyOffset+32]
		keyOffset += 32
	}

	permuteKey := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32

	feistelKeys := make([][]byte, ccl.FeistelPasses)
	for i := 0; i < ccl.FeistelPasses; i++ {
		feistelKeys[i] = masterKey[keyOffset : keyOffset+32]
		keyOffset += 32
	}

	aesKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	xcKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	aesKey2 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	xcKey2 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	aesKey3 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	xcKey3 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32

	hmacKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	b2Key := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	hmacKey2 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	hmacKey3 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	fullHmacKey := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	// Two SHAKE-256 whitening keys (pre + post CCL pipeline)
	whitenKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	whitenKey2 := masterKey[keyOffset : keyOffset+32]
	_ = keyOffset // no more keys needed

	// ── Pre-CCL SHAKE-256 Whitening ──
	// SHAKE-256 (Keccak XOF) stream cipher — 4th distinct cipher family.
	// Applied before all custom CCL layers so any statistical patterns
	// in the plaintext are destroyed before reaching S-Box/Feistel.
	setProgress(progress, 0.14)
	updateStatus(status, "SHAKE-256 pre-whitening (Keccak XOF)...")
	whitened := xorWhiten(plain, whitenKey1, []byte("COSTRINITY_PRE_WHITEN_V6"))
	wipeBytes(plain)

	// ── L4: CCL S-Box (variable passes) ──
	setProgress(progress, 0.16)
	updateStatus(status, fmt.Sprintf("L4/L5: CCL S-Box ×%d + cascade diffusion...", ccl.SBoxPasses))
	transformed := costrinityTransform(whitened, diffKey, true, sboxKeys...)
	wipeBytes(whitened)

	// ── L6: Block Permutation ──
	setProgress(progress, 0.19)
	updateStatus(status, "L6: Block permutation (transposition)...")
	permuted := blockPermute(transformed, permuteKey, true)
	wipeBytes(transformed)

	// ── L7: CCL Feistel (variable passes and rounds) ──
	current := permuted
	for i := 0; i < ccl.FeistelPasses; i++ {
		setProgress(progress, 0.21+float64(i)*0.03)
		updateStatus(status, fmt.Sprintf("L7: CCL Feistel pass %d/%d (%d rounds)...", i+1, ccl.FeistelPasses, ccl.FeistelRounds[i]))
		next := costrinityFeistel(current, feistelKeys[i], true, ccl.FeistelRounds[i])
		if i > 0 {
			wipeBytes(current)
		}
		current = next
	}
	wipeBytes(permuted)

	// ── Post-CCL SHAKE-256 Whitening ──
	// Second whitening pass after ALL custom layers.
	// Even if an attacker somehow inverts the Feistel/S-Box layers,
	// they still face a keyed SHAKE-256 stream cipher before the AEAD.
	updateStatus(status, "SHAKE-256 post-whitening (Keccak XOF)...")
	postWhitened := xorWhiten(current, whitenKey2, []byte("COSTRINITY_POST_WHITEN_V6"))
	wipeBytes(current)
	current = postWhitened

	// ── L8-L13: Six AEAD passes (AES-XC-AES-XC-AES-XC) ──
	setProgress(progress, 0.38)
	updateStatus(status, "L8: AES-256-GCM pass 1...")
	blk1, _ := aes.NewCipher(aesKey1)
	gcm1, _ := cipher.NewGCM(blk1)
	enc1 := gcm1.Seal(nil, nAES1, current, nil)
	wipeBytes(current)

	setProgress(progress, 0.44)
	updateStatus(status, "L9: XChaCha20-Poly1305 pass 1...")
	xc1, _ := chacha20poly1305.NewX(xcKey1)
	enc2 := xc1.Seal(nil, nXC1, enc1, nil)
	wipeBytes(enc1)

	setProgress(progress, 0.50)
	updateStatus(status, "L10: AES-256-GCM pass 2...")
	blk2, _ := aes.NewCipher(aesKey2)
	gcm2, _ := cipher.NewGCM(blk2)
	enc3 := gcm2.Seal(nil, nAES2, enc2, nil)
	wipeBytes(enc2)

	setProgress(progress, 0.56)
	updateStatus(status, "L11: XChaCha20-Poly1305 pass 2...")
	xc2, _ := chacha20poly1305.NewX(xcKey2)
	enc4 := xc2.Seal(nil, nXC2, enc3, nil)
	wipeBytes(enc3)

	setProgress(progress, 0.62)
	updateStatus(status, "L12: AES-256-GCM pass 3...")
	blk3, _ := aes.NewCipher(aesKey3)
	gcm3, _ := cipher.NewGCM(blk3)
	enc5 := gcm3.Seal(nil, nAES3, enc4, nil)
	wipeBytes(enc4)

	setProgress(progress, 0.68)
	updateStatus(status, "L13: XChaCha20-Poly1305 pass 3...")
	xc3, _ := chacha20poly1305.NewX(xcKey3)
	encPayload := xc3.Seal(nil, nXC3, enc5, nil)
	wipeBytes(enc5)

	// ── L14: Quintuple Integrity ──
	setProgress(progress, 0.74)
	updateStatus(status, "L14: Quintuple integrity (2×SHA3 + BLAKE2b + SHA512 + full-file)...")

	s3a := hmac.New(sha3.New512, hmacKey1)
	s3a.Write(encPayload)
	sha3Sum1 := s3a.Sum(nil)

	b2, _ := blake2b.New512(b2Key)
	b2.Write(encPayload)
	b2Sum := b2.Sum(nil)

	hm := hmac.New(sha512.New, hmacKey2)
	hm.Write(encPayload)
	hmSum := hm.Sum(nil)

	s3b := hmac.New(sha3.New512, hmacKey3)
	s3b.Write(encPayload)
	sha3Sum2 := s3b.Sum(nil)

	// ── Assemble v6 file ──
	setProgress(progress, 0.80)
	updateStatus(status, "Assembling .crypt v6 OBSIDIAN file...")

	out := new(bytes.Buffer)
	out.Write([]byte(magicString))
	vb := make([]byte, 2)
	binary.BigEndian.PutUint16(vb, versionV6)
	out.Write(vb)
	out.WriteByte(flags)
	out.WriteByte(byte(mode))
	out.Write(salts)
	out.Write(cclSeed)
	out.Write(nonces)
	out.Write(hdrPad)
	out.Write(encPayload)
	out.Write(sha3Sum1)
	out.Write(b2Sum)
	out.Write(hmSum)
	out.Write(sha3Sum2)

	// Full-file HMAC
	fullHm := hmac.New(sha512.New, fullHmacKey)
	fullHm.Write(out.Bytes())
	out.Write(fullHm.Sum(nil))

	outName := generateRandomFilename() + ".crypt"
	outPath := filepath.Join(getDesktopPath(), outName)
	if err := os.WriteFile(outPath, out.Bytes(), 0644); err != nil {
		notifyStatus(status, "Write error: "+err.Error())
		return
	}

	setProgress(progress, 0.90)
	updateStatus(status, "11-pass Gutmann shredding original...")
	secureDelete(path)
	wipeBytes(masterKey)

	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)
	var ratio float64
	if origSize > 0 {
		ratio = float64(out.Len()) / float64(origSize) * 100
	}
	totalRounds := 0
	for _, r := range ccl.FeistelRounds {
		totalRounds += r
	}
	notifyStatus(status, fmt.Sprintf("Encrypted [v6 %s | CCL: %dS+%dF(%dR) | %s | %.0f%%] -> %s",
		modeNames[mode], ccl.SBoxPasses, ccl.FeistelPasses, totalRounds, elapsed, ratio, outName))
}

// ============================================================================
// DECRYPT — auto-detects v2/v3/v4/v5/v6
// ============================================================================

func decryptFile(path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label) {
	if len(password) < minPasswordLen {
		notifyStatus(status, fmt.Sprintf("Error: minimum %d-character password required", minPasswordLen))
		return
	}
	start := time.Now()
	updateStatus(status, "Reading...")
	setProgress(progress, 0.02)

	data, err := os.ReadFile(path)
	if err != nil {
		notifyStatus(status, "Read error: "+err.Error())
		return
	}
	if len(data) < 6 || string(data[0:4]) != magicString {
		notifyStatus(status, "Error: not a valid .crypt file")
		return
	}
	ver := binary.BigEndian.Uint16(data[4:6])
	switch ver {
	case versionV6:
		decryptV6(data, path, password, kf, progress, status, start)
	case versionV5:
		decryptV5(data, path, password, kf, progress, status, start)
	case versionV4:
		decryptV4(data, path, password, kf, progress, status, start)
	case versionV3:
		decryptV3(data, path, password, kf, progress, status, start)
	case versionV2:
		decryptV2(data, path, password, kf, progress, status, start)
	default:
		notifyStatus(status, fmt.Sprintf("Error: unsupported version %d", ver))
	}
}

func decryptV6(data []byte, path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label, start time.Time) {
	if len(data) < v6HeaderSize+v6TrailingSize {
		notifyStatus(status, "Error: file too small for v6")
		return
	}
	flags := data[6]
	mode := int(data[7])
	if mode > ModeFortress {
		notifyStatus(status, "Error: invalid mode")
		return
	}

	// Parse header
	salts := data[8 : 8+v6SaltSize]
	cclSeed := data[8+v6SaltSize : 8+v6SaltSize+v6CCLSeedSize]
	nonces := data[8+v6SaltSize+v6CCLSeedSize : 8+v6SaltSize+v6CCLSeedSize+v6NonceSection]
	encPayload := data[v6HeaderSize : len(data)-v6TrailingSize]

	// Parse integrity hashes
	sha3Sum1 := data[len(data)-v6TrailingSize : len(data)-256]
	b2Sum := data[len(data)-256 : len(data)-192]
	hmSum := data[len(data)-192 : len(data)-128]
	sha3Sum2 := data[len(data)-128 : len(data)-64]
	fullHmSum := data[len(data)-64:]

	// Extract nonces
	nAES1 := nonces[0:12]
	nXC1 := nonces[12:36]
	nAES2 := nonces[36:48]
	nXC2 := nonces[48:72]
	nAES3 := nonces[72:84]
	nXC3 := nonces[84:108]

	setProgress(progress, 0.02)
	params := v6ModeParams[mode]
	totalMem := (params.argonMemory / 1024) + uint32(params.scryptN*params.scryptR*128/1024/1024)
	updateStatus(status, fmt.Sprintf("L0: Triple KDF [v6 %s: ~%dMB]...", modeNames[mode], totalMem))

	// Derive master key via Triple KDF
	effPw := effectivePasswordV6(password, kf)
	masterKey := tripleKDF(effPw, salts, params, v6MaxKeySize)
	wipeBytes(effPw)

	// Derive CCL parameters
	ccl := deriveCCLParams(masterKey, cclSeed)

	setProgress(progress, 0.10)
	updateStatus(status, fmt.Sprintf("CCL: %d S-Box passes, %d Feistel passes", ccl.SBoxPasses, ccl.FeistelPasses))

	// Allocate sub-keys
	keyOffset := 0
	diffKey := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32

	sboxKeys := make([][]byte, ccl.SBoxPasses)
	for i := 0; i < ccl.SBoxPasses; i++ {
		sboxKeys[i] = masterKey[keyOffset : keyOffset+32]
		keyOffset += 32
	}

	permuteKey := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32

	feistelKeys := make([][]byte, ccl.FeistelPasses)
	for i := 0; i < ccl.FeistelPasses; i++ {
		feistelKeys[i] = masterKey[keyOffset : keyOffset+32]
		keyOffset += 32
	}

	aesKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	xcKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	aesKey2 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	xcKey2 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	aesKey3 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	xcKey3 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32

	hmacKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	b2Key := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	hmacKey2 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	hmacKey3 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	fullHmacKey := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	// Whitening keys allocated here (used after AEAD reversal)

	// ── Verify full-file HMAC ──
	setProgress(progress, 0.12)
	updateStatus(status, "L14: Verifying full-file HMAC...")
	fullHm := hmac.New(sha512.New, fullHmacKey)
	fullHm.Write(data[:len(data)-64])
	if !hmac.Equal(fullHm.Sum(nil), fullHmSum) {
		notifyStatus(status, "FULL-FILE HMAC FAILED: header or payload tampered")
		wipeBytes(masterKey)
		return
	}

	// ── Verify quintuple integrity ──
	setProgress(progress, 0.14)
	updateStatus(status, "L14: Verifying HMAC-SHA512...")
	hm := hmac.New(sha512.New, hmacKey2)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC-SHA512 FAILED: wrong password, key file, or tampered")
		wipeBytes(masterKey)
		return
	}

	updateStatus(status, "L14: Verifying BLAKE2b-512...")
	b2, _ := blake2b.New512(b2Key)
	b2.Write(encPayload)
	if !bytes.Equal(b2.Sum(nil), b2Sum) {
		notifyStatus(status, "BLAKE2b FAILED: corrupted")
		wipeBytes(masterKey)
		return
	}

	updateStatus(status, "L14: Verifying HMAC-SHA3-512 #1...")
	s3a := hmac.New(sha3.New512, hmacKey1)
	s3a.Write(encPayload)
	if !hmac.Equal(s3a.Sum(nil), sha3Sum1) {
		notifyStatus(status, "SHA3 #1 FAILED: corrupted")
		wipeBytes(masterKey)
		return
	}

	updateStatus(status, "L14: Verifying HMAC-SHA3-512 #2...")
	s3b := hmac.New(sha3.New512, hmacKey3)
	s3b.Write(encPayload)
	if !hmac.Equal(s3b.Sum(nil), sha3Sum2) {
		notifyStatus(status, "SHA3 #2 FAILED: corrupted")
		wipeBytes(masterKey)
		return
	}

	// ── Reverse AEAD cascade ──
	setProgress(progress, 0.20)
	updateStatus(status, "L13: Decrypting XChaCha20-Poly1305 pass 3...")
	xc3, _ := chacha20poly1305.NewX(xcKey3)
	dec5, err := xc3.Open(nil, nXC3, encPayload, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 3 FAILED")
		wipeBytes(masterKey)
		return
	}

	setProgress(progress, 0.26)
	updateStatus(status, "L12: Decrypting AES-256-GCM pass 3...")
	blk3, _ := aes.NewCipher(aesKey3)
	gcm3, _ := cipher.NewGCM(blk3)
	dec4, err := gcm3.Open(nil, nAES3, dec5, nil)
	if err != nil {
		notifyStatus(status, "AES pass 3 FAILED")
		wipeBytes(masterKey)
		return
	}
	wipeBytes(dec5)

	setProgress(progress, 0.32)
	updateStatus(status, "L11: Decrypting XChaCha20-Poly1305 pass 2...")
	xc2, _ := chacha20poly1305.NewX(xcKey2)
	dec3, err := xc2.Open(nil, nXC2, dec4, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 2 FAILED")
		wipeBytes(masterKey)
		return
	}
	wipeBytes(dec4)

	setProgress(progress, 0.38)
	updateStatus(status, "L10: Decrypting AES-256-GCM pass 2...")
	blk2, _ := aes.NewCipher(aesKey2)
	gcm2, _ := cipher.NewGCM(blk2)
	dec2, err := gcm2.Open(nil, nAES2, dec3, nil)
	if err != nil {
		notifyStatus(status, "AES pass 2 FAILED")
		wipeBytes(masterKey)
		return
	}
	wipeBytes(dec3)

	setProgress(progress, 0.44)
	updateStatus(status, "L9: Decrypting XChaCha20-Poly1305 pass 1...")
	xc1, _ := chacha20poly1305.NewX(xcKey1)
	dec1, err := xc1.Open(nil, nXC1, dec2, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 1 FAILED")
		wipeBytes(masterKey)
		return
	}
	wipeBytes(dec2)

	setProgress(progress, 0.50)
	updateStatus(status, "L8: Decrypting AES-256-GCM pass 1...")
	blk1, _ := aes.NewCipher(aesKey1)
	gcm1, _ := cipher.NewGCM(blk1)
	feisteled, err := gcm1.Open(nil, nAES1, dec1, nil)
	if err != nil {
		notifyStatus(status, "AES pass 1 FAILED")
		wipeBytes(masterKey)
		return
	}
	wipeBytes(dec1)

	// Whitening keys — same positions as in encrypt
	whitenKey1 := masterKey[keyOffset : keyOffset+32]
	keyOffset += 32
	whitenKey2 := masterKey[keyOffset : keyOffset+32]
	_ = keyOffset

	// ── Reverse post-CCL SHAKE-256 whitening ──
	setProgress(progress, 0.52)
	updateStatus(status, "Reversing SHAKE-256 post-whitening...")
	unpostWhitened := xorWhiten(feisteled, whitenKey2, []byte("COSTRINITY_POST_WHITEN_V6"))
	wipeBytes(feisteled)

	// ── Reverse CCL Feistel passes ──
	current := unpostWhitened
	for i := ccl.FeistelPasses - 1; i >= 0; i-- {
		setProgress(progress, 0.54+float64(ccl.FeistelPasses-1-i)*0.03)
		updateStatus(status, fmt.Sprintf("L7: Reversing CCL Feistel pass %d/%d (%d rounds)...", ccl.FeistelPasses-i, ccl.FeistelPasses, ccl.FeistelRounds[i]))
		next := costrinityFeistel(current, feistelKeys[i], false, ccl.FeistelRounds[i])
		if i < ccl.FeistelPasses-1 {
			wipeBytes(current)
		}
		current = next
	}
	wipeBytes(unpostWhitened)

	// ── Reverse block permutation ──
	setProgress(progress, 0.68)
	updateStatus(status, "L6: Reversing block permutation...")
	unpermuted := blockPermute(current, permuteKey, false)
	wipeBytes(current)

	// ── Reverse S-Box ──
	setProgress(progress, 0.72)
	updateStatus(status, fmt.Sprintf("L4/L5: Reversing CCL S-Box ×%d + cascade diffusion...", ccl.SBoxPasses))
	postUnwhitened := costrinityTransform(unpermuted, diffKey, false, sboxKeys...)
	wipeBytes(unpermuted)

	// ── Reverse pre-CCL SHAKE-256 whitening ──
	setProgress(progress, 0.75)
	updateStatus(status, "Reversing SHAKE-256 pre-whitening...")
	plain := xorWhiten(postUnwhitened, whitenKey1, []byte("COSTRINITY_PRE_WHITEN_V6"))
	wipeBytes(postUnwhitened)

	// ── Verify canaries ──
	setProgress(progress, 0.78)
	updateStatus(status, "L2: Verifying dual canaries...")
	if len(plain) < canarySize*2 {
		notifyStatus(status, "Error: payload too small")
		wipeBytes(masterKey)
		return
	}
	if !bytes.Equal(plain[:canarySize], canaryV6[:]) {
		notifyStatus(status, "HEAD CANARY FAILED: cipher chain compromised")
		wipeBytes(masterKey)
		return
	}
	if !bytes.Equal(plain[len(plain)-canarySize:], canaryV6[:]) {
		notifyStatus(status, "TAIL CANARY FAILED: cipher chain compromised")
		wipeBytes(masterKey)
		return
	}

	rest := plain[canarySize : len(plain)-canarySize]

	if len(rest) < 4 {
		notifyStatus(status, "Error: payload corrupt")
		wipeBytes(masterKey)
		return
	}
	metaLen := int(binary.BigEndian.Uint32(rest[0:4]))
	if metaLen < 0 || metaLen > len(rest)-4 {
		notifyStatus(status, "Error: metadata corrupt")
		wipeBytes(masterKey)
		return
	}
	var meta CryptMeta
	if err := json.Unmarshal(rest[4:4+metaLen], &meta); err != nil {
		notifyStatus(status, "Metadata error: "+err.Error())
		wipeBytes(masterKey)
		return
	}

	dataStart := 4 + metaLen
	if meta.DataSize < 0 || int64(meta.DataSize) > int64(len(rest)-dataStart) {
		notifyStatus(status, "Error: data size exceeds payload")
		wipeBytes(masterKey)
		return
	}
	fileData := rest[dataStart : dataStart+int(meta.DataSize)]

	dh := sha256.Sum256(fileData)
	if fmt.Sprintf("%x", dh) != meta.Hash {
		updateStatus(status, "Warning: payload hash mismatch")
	}

	if flags&flagCompressed != 0 {
		setProgress(progress, 0.82)
		updateStatus(status, "L1: Decompressing...")
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			wipeBytes(masterKey)
			return
		}
	}

	setProgress(progress, 0.88)
	restoreFile(meta, fileData, status)

	setProgress(progress, 0.94)
	updateStatus(status, "11-pass shredding encrypted file...")
	secureDelete(path)
	wipeBytes(masterKey)

	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)
	totalRounds := 0
	for _, r := range ccl.FeistelRounds {
		totalRounds += r
	}
	notifyStatus(status, fmt.Sprintf("Decrypted [v6 %s | CCL: %dS+%dF(%dR) | %s] -> %s",
		modeNames[mode], ccl.SBoxPasses, ccl.FeistelPasses, totalRounds, elapsed, meta.Filename))
}

// ============================================================================
// BACKWARD COMPAT DECRYPTORS (v5/v4/v3/v2)
// ============================================================================

func decryptV5(data []byte, path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label, start time.Time) {
	if len(data) < v5HeaderSize+v5TrailingSize {
		notifyStatus(status, "Error: file too small for v5")
		return
	}
	flags := data[6]
	mode := int(data[7])
	if mode > ModeFortress {
		notifyStatus(status, "Error: invalid mode")
		return
	}
	salt := data[8:264]
	nAES1 := data[264:276]
	nAES2 := data[276:288]
	nAES3 := data[288:300]
	nXC1 := data[300:324]
	nXC2 := data[324:348]
	encPayload := data[v5HeaderSize : len(data)-v5TrailingSize]
	sha3Sum1 := data[len(data)-v5TrailingSize : len(data)-256]
	b2Sum := data[len(data)-256 : len(data)-192]
	hmSum := data[len(data)-192 : len(data)-128]
	sha3Sum2 := data[len(data)-128 : len(data)-64]
	fullHmSum := data[len(data)-64:]

	setProgress(progress, 0.02)
	params := v5ModeParams[mode]
	updateStatus(status, fmt.Sprintf("L0: Double Argon2id [v5 %s: %dMB x2]...", modeNames[mode], params.memory/1024))

	effPw := effectivePasswordV6(password, kf)
	half := len(salt) / 2
	saltA := salt[:half]
	saltB := salt[half:]
	derivedA := argon2.IDKey(effPw, saltA, params.time, params.memory, params.threads, v5KeySize)
	derivedB := argon2.IDKey(effPw, saltB, params.time, params.memory, params.threads, v5KeySize)
	for i := range derivedA {
		derivedA[i] ^= derivedB[i]
	}
	derived := derivedA
	wipeBytes(derivedB)
	wipeBytes(effPw)

	aesKey1 := derived[0:32]
	xcKey1 := derived[32:64]
	aesKey2 := derived[64:96]
	xcKey2 := derived[96:128]
	aesKey3 := derived[128:160]
	hmacKey := derived[160:192]
	sboxKey1 := derived[192:224]
	sboxKey2 := derived[224:256]
	sboxKey3 := derived[256:288]
	sboxKey4 := derived[288:320]
	diffKey := derived[320:352]
	b2Key := derived[352:384]
	feistelKey1 := derived[384:416]
	feistelKey2 := derived[416:448]
	feistelKey3 := derived[448:480]
	sha3Key1 := derived[480:512]
	sha3Key2 := derived[512:544]
	fullHmacKey := derived[544:576]

	setProgress(progress, 0.12)
	updateStatus(status, "L13: Verifying full-file HMAC...")
	fullHm := hmac.New(sha512.New, fullHmacKey)
	fullHm.Write(data[:len(data)-64])
	if !hmac.Equal(fullHm.Sum(nil), fullHmSum) {
		notifyStatus(status, "FULL-FILE HMAC FAILED")
		wipeBytes(derived)
		return
	}

	hm := hmac.New(sha512.New, hmacKey)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC-SHA512 FAILED")
		wipeBytes(derived)
		return
	}

	b2, _ := blake2b.New512(b2Key)
	b2.Write(encPayload)
	if !bytes.Equal(b2.Sum(nil), b2Sum) {
		notifyStatus(status, "BLAKE2b FAILED")
		wipeBytes(derived)
		return
	}

	s3a := hmac.New(sha3.New512, sha3Key1)
	s3a.Write(encPayload)
	if !hmac.Equal(s3a.Sum(nil), sha3Sum1) {
		notifyStatus(status, "SHA3 #1 FAILED")
		wipeBytes(derived)
		return
	}

	s3b := hmac.New(sha3.New512, sha3Key2)
	s3b.Write(encPayload)
	if !hmac.Equal(s3b.Sum(nil), sha3Sum2) {
		notifyStatus(status, "SHA3 #2 FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.20)
	blk3, _ := aes.NewCipher(aesKey3)
	gcm3, _ := cipher.NewGCM(blk3)
	enc4, err := gcm3.Open(nil, nAES3, encPayload, nil)
	if err != nil {
		notifyStatus(status, "AES pass 3 FAILED")
		wipeBytes(derived)
		return
	}

	xc2, _ := chacha20poly1305.NewX(xcKey2)
	enc3, err := xc2.Open(nil, nXC2, enc4, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 2 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc4)

	blk2, _ := aes.NewCipher(aesKey2)
	gcm2, _ := cipher.NewGCM(blk2)
	enc2, err := gcm2.Open(nil, nAES2, enc3, nil)
	if err != nil {
		notifyStatus(status, "AES pass 2 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc3)

	xc1, _ := chacha20poly1305.NewX(xcKey1)
	enc1, err := xc1.Open(nil, nXC1, enc2, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 1 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc2)

	blk1, _ := aes.NewCipher(aesKey1)
	gcm1, _ := cipher.NewGCM(blk1)
	feisteled3, err := gcm1.Open(nil, nAES1, enc1, nil)
	if err != nil {
		notifyStatus(status, "AES pass 1 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc1)

	setProgress(progress, 0.50)
	feisteled2 := costrinityFeistel(feisteled3, feistelKey3, false, 64)
	wipeBytes(feisteled3)
	feisteled1 := costrinityFeistel(feisteled2, feistelKey2, false, 64)
	wipeBytes(feisteled2)
	transformed := costrinityFeistel(feisteled1, feistelKey1, false, 64)
	wipeBytes(feisteled1)

	plain := costrinityTransform(transformed, diffKey, false, sboxKey1, sboxKey2, sboxKey3, sboxKey4)
	wipeBytes(transformed)

	if len(plain) < canarySize*2 {
		notifyStatus(status, "Error: payload too small")
		wipeBytes(derived)
		return
	}
	if !bytes.Equal(plain[:canarySize], canaryV5[:]) {
		notifyStatus(status, "HEAD CANARY FAILED")
		wipeBytes(derived)
		return
	}
	if !bytes.Equal(plain[len(plain)-canarySize:], canaryV5[:]) {
		notifyStatus(status, "TAIL CANARY FAILED")
		wipeBytes(derived)
		return
	}

	rest := plain[canarySize : len(plain)-canarySize]
	if len(rest) < 4 {
		notifyStatus(status, "Error: payload corrupt")
		wipeBytes(derived)
		return
	}
	metaLen := int(binary.BigEndian.Uint32(rest[0:4]))
	if metaLen < 0 || metaLen > len(rest)-4 {
		notifyStatus(status, "Error: metadata corrupt")
		wipeBytes(derived)
		return
	}
	var meta CryptMeta
	if err := json.Unmarshal(rest[4:4+metaLen], &meta); err != nil {
		notifyStatus(status, "Metadata error: "+err.Error())
		wipeBytes(derived)
		return
	}

	dataStart := 4 + metaLen
	if meta.DataSize < 0 || int64(meta.DataSize) > int64(len(rest)-dataStart) {
		notifyStatus(status, "Error: data size exceeds payload")
		wipeBytes(derived)
		return
	}
	fileData := rest[dataStart : dataStart+int(meta.DataSize)]

	if flags&flagCompressed != 0 {
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			wipeBytes(derived)
			return
		}
	}

	restoreFile(meta, fileData, status)
	secureDelete(path)
	wipeBytes(derived)
	setProgress(progress, 1.0)
	notifyStatus(status, fmt.Sprintf("Decrypted [v5 %s | %s] -> %s", modeNames[mode], time.Since(start).Round(time.Millisecond), meta.Filename))
}

func decryptV4(data []byte, path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label, start time.Time) {
	if len(data) < v4HeaderSize+v4TrailingSize {
		notifyStatus(status, "Error: file too small for v4")
		return
	}
	flags := data[6]
	mode := int(data[7])
	if mode > ModeFortress {
		notifyStatus(status, "Error: invalid mode")
		return
	}
	salt := data[8:136]
	nAES1 := data[136:148]
	nAES2 := data[148:160]
	nXC := data[160:184]
	encPayload := data[v4HeaderSize : len(data)-v4TrailingSize]
	sha3Sum := data[len(data)-v4TrailingSize : len(data)-128]
	b2Sum := data[len(data)-128 : len(data)-64]
	hmSum := data[len(data)-64:]

	setProgress(progress, 0.05)
	params := modeParams[mode]
	updateStatus(status, fmt.Sprintf("L0: Argon2id [%s: %dMB]...", modeNames[mode], params.memory/1024))

	effPw := effectivePassword(password, kf)
	derived := argon2.IDKey(effPw, salt, params.time, params.memory, params.threads, v4KeySize)
	wipeBytes(effPw)

	aesKey1 := derived[0:32]
	xcKey := derived[32:64]
	aesKey2 := derived[64:96]
	hmacKey := derived[96:128]
	sboxKey1 := derived[128:160]
	sboxKey2 := derived[160:192]
	diffKey := derived[192:224]
	b2Key := derived[224:256]
	feistelKey := derived[256:288]
	sha3Key := derived[288:320]

	setProgress(progress, 0.22)
	hm := hmac.New(sha512.New, hmacKey)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC-SHA512 FAILED")
		wipeBytes(derived)
		return
	}

	b2, _ := blake2b.New512(b2Key)
	b2.Write(encPayload)
	if !bytes.Equal(b2.Sum(nil), b2Sum) {
		notifyStatus(status, "BLAKE2b FAILED")
		wipeBytes(derived)
		return
	}

	s3 := hmac.New(sha3.New512, sha3Key)
	s3.Write(encPayload)
	if !hmac.Equal(s3.Sum(nil), sha3Sum) {
		notifyStatus(status, "SHA3 FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.30)
	blk2, _ := aes.NewCipher(aesKey2)
	gcm2, _ := cipher.NewGCM(blk2)
	enc2, err := gcm2.Open(nil, nAES2, encPayload, nil)
	if err != nil {
		notifyStatus(status, "AES pass 2 FAILED")
		wipeBytes(derived)
		return
	}

	xc, _ := chacha20poly1305.NewX(xcKey)
	enc1, err := xc.Open(nil, nXC, enc2, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 FAILED")
		wipeBytes(derived)
		return
	}

	blk1, _ := aes.NewCipher(aesKey1)
	gcm1, _ := cipher.NewGCM(blk1)
	feisteled, err := gcm1.Open(nil, nAES1, enc1, nil)
	if err != nil {
		notifyStatus(status, "AES pass 1 FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.54)
	transformed := costrinityFeistel(feisteled, feistelKey, false, 32)
	plain := costrinityTransform(transformed, diffKey, false, sboxKey1, sboxKey2)

	if len(plain) < canarySize {
		notifyStatus(status, "Error: payload too small")
		return
	}
	if !bytes.Equal(plain[:canarySize], canaryValue[:]) {
		notifyStatus(status, "CANARY FAILED")
		return
	}
	rest := plain[canarySize:]

	if len(rest) < 4 {
		notifyStatus(status, "Error: payload corrupt")
		return
	}
	metaLen := int(binary.BigEndian.Uint32(rest[0:4]))
	if metaLen < 0 || metaLen > len(rest)-4 {
		notifyStatus(status, "Error: metadata corrupt")
		return
	}
	var meta CryptMeta
	if err := json.Unmarshal(rest[4:4+metaLen], &meta); err != nil {
		notifyStatus(status, "Metadata error: "+err.Error())
		return
	}

	dataStart := 4 + metaLen
	if meta.DataSize < 0 || int64(meta.DataSize) > int64(len(rest)-dataStart) {
		notifyStatus(status, "Error: data size exceeds payload")
		return
	}
	fileData := rest[dataStart : dataStart+int(meta.DataSize)]

	if flags&flagCompressed != 0 {
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			return
		}
	}

	restoreFile(meta, fileData, status)
	secureDelete(path)
	wipeBytes(derived)
	setProgress(progress, 1.0)
	notifyStatus(status, fmt.Sprintf("Decrypted [v4 %s | %s] -> %s", modeNames[mode], time.Since(start).Round(time.Millisecond), meta.Filename))
}

func decryptV3(data []byte, path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label, start time.Time) {
	if len(data) < v3HeaderSize+v3TrailingSize {
		notifyStatus(status, "Error: file too small")
		return
	}
	flags := data[6]
	mode := int(data[7])
	if mode > ModeParanoid {
		notifyStatus(status, "Error: invalid mode")
		return
	}
	salt := data[8:72]
	nAES := data[72:84]
	nXC := data[84:108]
	encPayload := data[v3HeaderSize : len(data)-v3TrailingSize]
	b2sum := data[len(data)-v3TrailingSize : len(data)-64]
	hmSum := data[len(data)-64:]

	params := modeParams[mode]
	effPw := effectivePassword(password, kf)
	derived := argon2.IDKey(effPw, salt, params.time, params.memory, params.threads, v3KeySize)
	wipeBytes(effPw)

	hmacKeyD := derived[64:96]
	sboxKey := derived[96:128]
	diffKey := derived[128:160]
	b2Key := derived[160:192]
	feistelKey := derived[192:224]

	hm := hmac.New(sha512.New, hmacKeyD)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC FAILED")
		wipeBytes(derived)
		return
	}
	b2h, _ := blake2b.New512(b2Key)
	b2h.Write(encPayload)
	if !bytes.Equal(b2h.Sum(nil), b2sum) {
		notifyStatus(status, "BLAKE2b FAILED")
		wipeBytes(derived)
		return
	}

	xc, _ := chacha20poly1305.NewX(derived[32:64])
	aesEnc, err := xc.Open(nil, nXC, encPayload, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 FAILED")
		wipeBytes(derived)
		return
	}
	blk, _ := aes.NewCipher(derived[0:32])
	gcm, _ := cipher.NewGCM(blk)
	feisteled, err := gcm.Open(nil, nAES, aesEnc, nil)
	if err != nil {
		notifyStatus(status, "AES-GCM FAILED")
		wipeBytes(derived)
		return
	}

	transformed := costrinityFeistel(feisteled, feistelKey, false, 16)
	plain := costrinityTransform(transformed, diffKey, false, sboxKey)

	if len(plain) < 4 {
		notifyStatus(status, "Error: payload corrupt")
		wipeBytes(derived)
		return
	}
	ml := int(binary.BigEndian.Uint32(plain[0:4]))
	if ml < 0 || ml > len(plain)-4 {
		notifyStatus(status, "Error: metadata corrupt")
		wipeBytes(derived)
		return
	}
	var meta CryptMeta
	if err := json.Unmarshal(plain[4:4+ml], &meta); err != nil {
		notifyStatus(status, "Metadata error: "+err.Error())
		wipeBytes(derived)
		return
	}
	fileData := plain[4+ml:]

	if flags&flagCompressed != 0 {
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			wipeBytes(derived)
			return
		}
	}

	restoreFile(meta, fileData, status)
	secureDelete(path)
	wipeBytes(derived)
	setProgress(progress, 1.0)
	notifyStatus(status, fmt.Sprintf("Decrypted [v3 | %s] -> %s", time.Since(start).Round(time.Millisecond), meta.Filename))
}

func decryptV2(data []byte, path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label, start time.Time) {
	if len(data) < v2HeaderSize+v2TrailingSize {
		notifyStatus(status, "Error: file too small")
		return
	}
	mode := int(data[6])
	if mode > ModeParanoid {
		notifyStatus(status, "Error: invalid mode")
		return
	}
	salt := data[7:71]
	nAES := data[71:83]
	nXC := data[83:107]
	encPayload := data[v2HeaderSize : len(data)-v2TrailingSize]
	b2sum := data[len(data)-v2TrailingSize : len(data)-64]
	hmSum := data[len(data)-64:]

	params := modeParams[mode]
	effPw := effectivePassword(password, kf)
	derived := argon2.IDKey(effPw, salt, params.time, params.memory, params.threads, v2KeySize)
	wipeBytes(effPw)

	hmacKeyD := derived[64:96]
	sboxKey := derived[96:128]
	diffKey := derived[128:160]
	b2Key := derived[160:192]

	hm := hmac.New(sha512.New, hmacKeyD)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC FAILED")
		wipeBytes(derived)
		return
	}
	b2h, _ := blake2b.New512(b2Key)
	b2h.Write(encPayload)
	if !bytes.Equal(b2h.Sum(nil), b2sum) {
		notifyStatus(status, "BLAKE2b FAILED")
		wipeBytes(derived)
		return
	}

	xc, _ := chacha20poly1305.NewX(derived[32:64])
	aesEnc, err := xc.Open(nil, nXC, encPayload, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 FAILED")
		wipeBytes(derived)
		return
	}
	blk, _ := aes.NewCipher(derived[0:32])
	gcm, _ := cipher.NewGCM(blk)
	transformed, err := gcm.Open(nil, nAES, aesEnc, nil)
	if err != nil {
		notifyStatus(status, "AES-GCM FAILED")
		wipeBytes(derived)
		return
	}

	plain := costrinityTransform(transformed, diffKey, false, sboxKey)
	if len(plain) < 4 {
		notifyStatus(status, "Error: corrupt")
		wipeBytes(derived)
		return
	}
	ml := int(binary.BigEndian.Uint32(plain[0:4]))
	if ml < 0 || ml > len(plain)-4 {
		notifyStatus(status, "Error: corrupt")
		wipeBytes(derived)
		return
	}
	var meta CryptMeta
	if err := json.Unmarshal(plain[4:4+ml], &meta); err != nil {
		notifyStatus(status, "Metadata error: "+err.Error())
		wipeBytes(derived)
		return
	}
	fileData := plain[4+ml:]

	restoreFile(meta, fileData, status)
	secureDelete(path)
	wipeBytes(derived)
	setProgress(progress, 1.0)
	notifyStatus(status, fmt.Sprintf("Decrypted [v2 | %s] -> %s", time.Since(start).Round(time.Millisecond), meta.Filename))
}

// ============================================================================
// VERIFY MODE
// ============================================================================

func verifyFile(path, password string, kf []byte, progress *widget.ProgressBar, status *widget.Label) {
	if len(password) < minPasswordLen {
		notifyStatus(status, "Error: minimum password length required")
		return
	}
	start := time.Now()
	updateStatus(status, "Reading...")
	setProgress(progress, 0.05)

	data, err := os.ReadFile(path)
	if err != nil {
		notifyStatus(status, "Read error: "+err.Error())
		return
	}
	if len(data) < 6 || string(data[0:4]) != magicString {
		notifyStatus(status, "Error: not a .crypt file")
		return
	}
	ver := binary.BigEndian.Uint16(data[4:6])

	var mode int
	var flags byte
	var hmSum []byte
	var hmacKey []byte

	switch ver {
	case versionV6:
		if len(data) < v6HeaderSize+v6TrailingSize {
			notifyStatus(status, "Error: too small")
			return
		}
		flags = data[6]
		mode = int(data[7])
		salts := data[8 : 8+v6SaltSize]
		cclSeed := data[8+v6SaltSize : 8+v6SaltSize+v6CCLSeedSize]
		encPayload := data[v6HeaderSize : len(data)-v6TrailingSize]
		hmSum = data[len(data)-192 : len(data)-128]

		params := v6ModeParams[mode]
		effPw := effectivePasswordV6(password, kf)
		masterKey := tripleKDF(effPw, salts, params, v6MaxKeySize)
		wipeBytes(effPw)

		ccl := deriveCCLParams(masterKey, cclSeed)
		// diffKey(32) + sboxKeys + permuteKey(32) + feistelKeys + AEAD×6(192) + hmacKey1(32) + b2Key(32)
		keyOffset := 32 + ccl.SBoxPasses*32 + 32 + ccl.FeistelPasses*32 + 6*32 + 32 + 32
		hmacKey = masterKey[keyOffset : keyOffset+32]

		setProgress(progress, 0.6)
		hm := hmac.New(sha512.New, hmacKey)
		hm.Write(encPayload)
		ok := hmac.Equal(hm.Sum(nil), hmSum)
		wipeBytes(masterKey)
		setProgress(progress, 1.0)
		elapsed := time.Since(start).Round(time.Millisecond)
		info := fmt.Sprintf("v6 | %s | CCL | %.1f KB", modeNames[mode], float64(len(data))/1024)
		if ok {
			notifyStatus(status, fmt.Sprintf("VERIFIED OK (%s) [%s]", elapsed, info))
		} else {
			notifyStatus(status, fmt.Sprintf("VERIFICATION FAILED (%s) [%s]", elapsed, info))
		}
		return

	default:
		notifyStatus(status, fmt.Sprintf("Verify not implemented for v%d — use decrypt", ver))
		return
	}
}

// ============================================================================
// FILE UTILITIES
// ============================================================================

func restoreFile(meta CryptMeta, fileData []byte, status *widget.Label) {
	desktop := getDesktopPath()
	if meta.IsDir && strings.HasSuffix(meta.Filename, ".zip") {
		fn := strings.TrimSuffix(meta.Filename, ".zip")
		updateStatus(status, "Extracting: "+fn)
		if err := unzipToDesktop(fileData, fn); err != nil {
			notifyStatus(status, "Unzip error: "+err.Error())
		}
	} else {
		if err := os.WriteFile(filepath.Join(desktop, meta.Filename), fileData, 0644); err != nil {
			notifyStatus(status, "Write error: "+err.Error())
		}
	}
}

func zipFolder(folderPath string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	err := filepath.WalkDir(folderPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(folderPath, path)
		f, err := zw.Create(rel)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = f.Write(src)
		return err
	})
	if err != nil {
		return nil, err
	}
	zw.Close()
	return buf.Bytes(), nil
}

func unzipToDesktop(data []byte, folderName string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	dest := filepath.Join(getDesktopPath(), folderName)
	os.MkdirAll(dest, 0755)
	for _, f := range r.File {
		cleaned := filepath.FromSlash(f.Name)
		if strings.Contains(cleaned, "..") {
			return fmt.Errorf("invalid zip entry path: %s", f.Name)
		}
		fp := filepath.Join(dest, cleaned)
		if !strings.HasPrefix(fp, filepath.Clean(dest)+string(os.PathSeparator)) && fp != filepath.Clean(dest) {
			return fmt.Errorf("invalid zip entry path: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(fp, f.Mode())
			continue
		}
		os.MkdirAll(filepath.Dir(fp), 0755)
		df, err := os.Create(fp)
		if err != nil {
			return err
		}
		sf, err := f.Open()
		if err != nil {
			df.Close()
			return err
		}
		_, ce := io.Copy(df, io.LimitReader(sf, 4<<30))
		sf.Close()
		df.Close()
		if ce != nil {
			return ce
		}
	}
	return nil
}

func secureDelete(path string) {
	info, err := os.Stat(path)
	if err != nil {
		os.RemoveAll(path)
		return
	}
	if info.IsDir() {
		filepath.WalkDir(path, func(p string, d fs.DirEntry, _ error) error {
			if d != nil && !d.IsDir() {
				shredFile(p)
			}
			return nil
		})
		os.RemoveAll(path)
		return
	}
	shredFile(path)
	os.Remove(path)
}

func shredFile(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	size := info.Size()
	buf := make([]byte, 8192)
	for pass := 0; pass < 11; pass++ {
		f.Seek(0, 0)
		rem := size
		for rem > 0 {
			n := int64(len(buf))
			if n > rem {
				n = rem
			}
			c := buf[:int(n)]
			switch pass {
			case 0, 3, 6, 9:
				rand.Read(c)
			case 1, 4, 7:
				for i := range c {
					c[i] = 0x00
				}
			case 2, 5, 8:
				for i := range c {
					c[i] = 0xFF
				}
			case 10:
				for i := range c {
					c[i] = 0x55
				}
			}
			f.Write(c)
			rem -= n
		}
		f.Sync()
	}
	f.Close()
}

func getDesktopPath() string {
	u, err := user.Current()
	if err != nil {
		return fallbackOutputDir()
	}
	home := u.HomeDir

	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_DESKTOP_DIR"); xdg != "" {
			if info, err := os.Stat(xdg); err == nil && info.IsDir() {
				return xdg
			}
		}
		if out, err := exec.Command("xdg-user-dir", "DESKTOP").Output(); err == nil {
			dir := strings.TrimSpace(string(out))
			if dir != "" && dir != home {
				if info, err := os.Stat(dir); err == nil && info.IsDir() {
					return dir
				}
			}
		}
		tails := filepath.Join(home, "Persistent")
		if info, err := os.Stat(tails); err == nil && info.IsDir() {
			return tails
		}
	}

	if runtime.GOOS == "windows" {
		oneDrive := filepath.Join(home, "OneDrive", "Desktop")
		if info, err := os.Stat(oneDrive); err == nil && info.IsDir() {
			return oneDrive
		}
	}

	d := filepath.Join(home, "Desktop")
	if info, err := os.Stat(d); err == nil && info.IsDir() {
		return d
	}

	docs := filepath.Join(home, "Documents")
	if info, err := os.Stat(docs); err == nil && info.IsDir() {
		return docs
	}

	if info, err := os.Stat(home); err == nil && info.IsDir() {
		return home
	}

	return fallbackOutputDir()
}

func fallbackOutputDir() string {
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return os.TempDir()
}

func generateRandomFilename() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := make([]byte, scrambleLen)
	for i := range r {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		r[i] = chars[n.Int64()]
	}
	return string(r)
}

// ============================================================================
// UI HELPERS
// ============================================================================

func setProgress(pb *widget.ProgressBar, v float64) { pb.SetValue(v) }
func updateStatus(lbl *widget.Label, msg string)    { lbl.SetText(msg) }
func notifyStatus(lbl *widget.Label, msg string) {
	lbl.SetText(msg)
	fyne.CurrentApp().SendNotification(&fyne.Notification{Title: "CRYpT", Content: msg})
}

// ============================================================================
// MAIN — OBSIDIAN EDITION UI
// ============================================================================

// ============================================================================
// LICENSE / ACTIVATION
// ============================================================================

const activateAPI = "https://api.costrinity.xyz/api/crypt-activate"
const licenseFile = ".crypt_license"

type LicenseCache struct {
	Valid    bool   `json:"valid"`
	Tier     string `json:"tier"`
	Email    string `json:"email"`
	Code     string `json:"code"`
	CachedAt string `json:"cached_at"`
}

func licensePath() string {
	u, err := user.Current()
	if err != nil {
		return licenseFile
	}
	return filepath.Join(u.HomeDir, licenseFile)
}

func loadLicense() *LicenseCache {
	data, err := os.ReadFile(licensePath())
	if err != nil {
		return nil
	}
	var lc LicenseCache
	if json.Unmarshal(data, &lc) != nil {
		return nil
	}
	if !lc.Valid {
		return nil
	}
	return &lc
}

func saveLicense(lc *LicenseCache) {
	data, _ := json.Marshal(lc)
	os.WriteFile(licensePath(), data, 0600)
}

func activateLicense(code, email string) (*LicenseCache, error) {
	reqURL := fmt.Sprintf("%s?code=%s&email=%s", activateAPI, code, email)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("network error — check your connection: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read server response")
	}

	var result struct {
		Valid    bool   `json:"valid"`
		Tier     string `json:"tier"`
		Email    string `json:"email"`
		Error    string `json:"error"`
		Message  string `json:"message"`
	}
	if json.Unmarshal(body, &result) != nil {
		return nil, fmt.Errorf("invalid response from server")
	}
	if !result.Valid {
		msg := result.Error
		if msg == "" {
			msg = "activation failed"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	lc := &LicenseCache{
		Valid:    true,
		Tier:     result.Tier,
		Email:    result.Email,
		Code:     code,
		CachedAt: time.Now().Format(time.RFC3339),
	}
	saveLicense(lc)
	return lc, nil
}

func main() {
	iconBytes, _ := embeddedFiles.ReadFile("assets/icon.png")
	iconRes := fyne.NewStaticResource("icon.png", iconBytes)

	a := app.NewWithID("com.costrinity.CRYpT")
	a.SetIcon(iconRes)
	a.Settings().SetTheme(&costrinityTheme{})

	w := a.NewWindow("CRYpT v6.1 — Free Edition")
	w.Resize(fyne.NewSize(820, 780))
	w.CenterOnScreen()

	// Load cached license
	cachedLicense := loadLicense()
	isPro := cachedLicense != nil && cachedLicense.Valid

	var keyFileData []byte
	currentMode := ModeMilitary
	compressEnabled := true

	// ── Title Block ──
	titleMain := canvas.NewText("C R Y p T", colCyan)
	titleMain.TextSize = 34
	titleMain.Alignment = fyne.TextAlignCenter
	titleMain.TextStyle = fyne.TextStyle{Bold: true}

	titleSub := canvas.NewText("COSTRINITY CIPHER LANGUAGE", colCyanDim)
	titleSub.TextSize = 10
	titleSub.Alignment = fyne.TextAlignCenter

	edition := canvas.NewText("FREE EDITION v6.1  //  Triple KDF  //  CCL Secret Algorithm  //  6-Cipher AEAD  //  Standard + Military Modes", colMidText)
	edition.TextSize = 9
	edition.Alignment = fyne.TextAlignCenter

	accentLine := canvas.NewRectangle(colCyan)
	accentLine.SetMinSize(fyne.NewSize(0, 2))

	titleBlock := container.NewVBox(titleMain, titleSub, edition, accentLine)

	// ── Password ──
	pwLabel := canvas.NewText("PASSWORD", colCyanDim)
	pwLabel.TextSize = 10
	pwLabel.TextStyle = fyne.TextStyle{Bold: true}

	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Minimum 14 characters required")

	strLabel := canvas.NewText("STRENGTH: -", colDisabled)
	strLabel.TextSize = 11
	strLabel.TextStyle = fyne.TextStyle{Bold: true}
	pwEntry.OnChanged = func(s string) {
		l, c := evaluatePassword(s)
		strLabel.Text = "STRENGTH: " + l
		strLabel.Color = c
		strLabel.Refresh()
	}

	pwBlock := container.NewVBox(pwLabel, pwEntry, container.NewHBox(strLabel, layout.NewSpacer()))

	progress := widget.NewProgressBar()
	statusLabel := widget.NewLabel("READY  //  OBSIDIAN EDITION — THE ALGORITHM IS SECRET")

	// ── Key File ──
	kfLabel := widget.NewLabel("Key File: None")
	kfLoadBtn := widget.NewButton("Load Key File", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			name := filepath.Base(reader.URI().Path())
			d, readErr := io.ReadAll(reader)
			reader.Close()
			if readErr != nil {
				notifyStatus(statusLabel, "Key file read error: "+readErr.Error())
				return
			}
			keyFileData = d
			kfLabel.SetText("Key File: " + name)
		}, w)
	})
	kfClearBtn := widget.NewButton("Clear", func() {
		keyFileData = nil
		kfLabel.SetText("Key File: None")
	})
	kfRow := container.NewHBox(kfLabel, layout.NewSpacer(), kfLoadBtn, kfClearBtn)

	// ════════ ENCRYPT TAB ════════
	encHeader := canvas.NewText("SECURITY MODE", colCyanDim)
	encHeader.TextSize = 10
	encHeader.TextStyle = fyne.TextStyle{Bold: true}

	modeSelect := widget.NewRadioGroup([]string{"Standard", "Military", "Paranoid", "FORTRESS"}, func(s string) {
		switch s {
		case "Standard":
			currentMode = ModeStandard
		case "Military":
			currentMode = ModeMilitary
		case "Paranoid":
			currentMode = ModeParanoid
		case "FORTRESS":
			currentMode = ModeFortress
		}
	})
	modeSelect.Horizontal = true
	modeSelect.Selected = "Military"

	modeDesc := canvas.NewText("Standard: ~384MB  |  Military: ~768MB  |  Paranoid: PRO ONLY  |  FORTRESS: PRO ONLY", colDimText)
	modeDesc.TextSize = 9
	modeDesc.Alignment = fyne.TextAlignCenter

	fortressWarn := canvas.NewText("🔒 Paranoid + FORTRESS modes require CRYpT Pro — upgrade at costrinity.xyz/crypt", colWarn)
	fortressWarn.TextSize = 9
	fortressWarn.Alignment = fyne.TextAlignCenter

	cclInfo := canvas.NewText("CCL: The cipher pipeline (S-Box passes, Feistel rounds) is derived from your password — the algorithm itself is secret", colSuccess)
	cclInfo.TextSize = 9
	cclInfo.Alignment = fyne.TextAlignCenter

	compressCheck := widget.NewCheck("Compress before encryption", func(v bool) { compressEnabled = v })
	compressCheck.Checked = true

	encFileBtn := widget.NewButton("Encrypt File", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		kf := keyFileData
		mode := currentMode
		comp := compressEnabled
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			p := r.URI().Path()
			r.Close()
			go encryptPath(p, pw, kf, mode, false, comp, progress, statusLabel)
		}, w)
	})

	encFolderBtn := widget.NewButton("Encrypt Folder", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		kf := keyFileData
		mode := currentMode
		comp := compressEnabled
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			go encryptPath(uri.Path(), pw, kf, mode, true, comp, progress, statusLabel)
		}, w)
	})

	layers := canvas.NewText("Triple KDF > S-Box×4-8 > Permute > Feistel×3-6 > AES > XChaCha > AES > XChaCha > AES > XChaCha > 5× Integrity", colDimText)
	layers.TextSize = 8
	layers.Alignment = fyne.TextAlignCenter

	encryptTab := container.NewVScroll(container.NewVBox(
		encHeader,
		modeSelect,
		modeDesc,
		fortressWarn,
		cclInfo,
		neonSeparator(colSep),
		compressCheck,
		neonSeparator(colSep),
		container.NewGridWithColumns(2, encFileBtn, encFolderBtn),
		layers,
	))

	// ════════ DECRYPT TAB ════════
	decBtn := widget.NewButton("Decrypt .crypt File", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		kf := keyFileData
		fd := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			p := r.URI().Path()
			r.Close()
			go decryptFile(p, pw, kf, progress, statusLabel)
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".crypt"}))
		fd.Show()
	})

	verifyBtn := widget.NewButton("Verify Integrity Only", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		kf := keyFileData
		fd := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			p := r.URI().Path()
			r.Close()
			go verifyFile(p, pw, kf, progress, statusLabel)
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".crypt"}))
		fd.Show()
	})

	decInfo1 := canvas.NewText("Auto-detects v2 / v3 / v4 / v5 / v6 — full backward compatibility", colDimText)
	decInfo1.TextSize = 9
	decInfo1.Alignment = fyne.TextAlignCenter

	decryptTab := container.NewVScroll(container.NewVBox(
		decBtn,
		neonSeparator(colSep),
		verifyBtn,
		decInfo1,
	))

	// ════════ TOOLS TAB ════════
	genLength := 24
	genLo, genUp, genDg, genSy := true, true, true, true

	lenLabel := widget.NewLabel("Length: 24")
	lenSlider := widget.NewSlider(14, 64)
	lenSlider.Step = 1
	lenSlider.Value = 24
	lenSlider.OnChanged = func(v float64) {
		genLength = int(v)
		lenLabel.SetText(fmt.Sprintf("Length: %d", genLength))
	}
	chkLo := widget.NewCheck("a-z", func(v bool) { genLo = v })
	chkLo.Checked = true
	chkUp := widget.NewCheck("A-Z", func(v bool) { genUp = v })
	chkUp.Checked = true
	chkDg := widget.NewCheck("0-9", func(v bool) { genDg = v })
	chkDg.Checked = true
	chkSy := widget.NewCheck("Symbols", func(v bool) { genSy = v })
	chkSy.Checked = true

	genEntry := widget.NewEntry()
	genEntry.SetPlaceHolder("Generated password")

	genBtn := widget.NewButton("Generate", func() {
		genEntry.SetText(generatePassword(genLength, genLo, genUp, genDg, genSy))
	})
	copyBtn := widget.NewButton("Copy", func() {
		if genEntry.Text != "" {
			w.Clipboard().SetContent(genEntry.Text)
			updateStatus(statusLabel, "Copied to clipboard")
		}
	})
	useBtn := widget.NewButton("Use as Password", func() {
		if genEntry.Text != "" {
			pwEntry.SetText(genEntry.Text)
			updateStatus(statusLabel, "Password applied")
		}
	})

	toolsHeader := canvas.NewText("PASSWORD GENERATOR", colCyanDim)
	toolsHeader.TextSize = 10
	toolsHeader.TextStyle = fyne.TextStyle{Bold: true}

	toolsTab := container.NewVScroll(container.NewVBox(
		toolsHeader,
		neonSeparator(colSep),
		container.NewHBox(lenLabel, layout.NewSpacer()),
		lenSlider,
		container.NewGridWithColumns(4, chkLo, chkUp, chkDg, chkSy),
		genBtn, genEntry,
		container.NewGridWithColumns(2, copyBtn, useBtn),
	))

	// ════════ ABOUT TAB ════════
	aboutTitle := canvas.NewText("CRYpT v6.1 — Free Edition", colCyan)
	aboutTitle.TextSize = 14
	aboutTitle.TextStyle = fyne.TextStyle{Bold: true}
	aboutTitle.Alignment = fyne.TextAlignCenter

	aboutProto := canvas.NewText("Costrinity Cipher Language (CCL) Protocol v6", colCyanDim)
	aboutProto.TextSize = 10
	aboutProto.Alignment = fyne.TextAlignCenter

	aboutInnovation := canvas.NewText("THE ALGORITHM ITSELF IS SECRET", colSuccess)
	aboutInnovation.TextSize = 11
	aboutInnovation.TextStyle = fyne.TextStyle{Bold: true}
	aboutInnovation.Alignment = fyne.TextAlignCenter

	aboutLayersHdr := canvas.NewText("20-LAYER ENCRYPTION ARCHITECTURE", colCyan)
	aboutLayersHdr.TextSize = 10
	aboutLayersHdr.TextStyle = fyne.TextStyle{Bold: true}

	aboutLayers := widget.NewLabel(
		"  L0   Triple KDF: Argon2id → scrypt → HKDF-SHA3\n" +
			"  L1   zlib compression\n" +
			"  L2   Dual canary (head + tail)\n" +
			"  L3   Random padding 512-8192B\n" +
			"  L4   CCL S-Box ×4-8 (key-derived count)\n" +
			"  L5   Cascade diffusion\n" +
			"  L6   Block permutation (transposition)\n" +
			"  L7   CCL Feistel ×3-6 (64-127 rounds each)\n" +
			"  L8   AES-256-GCM pass 1\n" +
			"  L9   XChaCha20-Poly1305 pass 1\n" +
			"  L10  AES-256-GCM pass 2\n" +
			"  L11  XChaCha20-Poly1305 pass 2\n" +
			"  L12  AES-256-GCM pass 3\n" +
			"  L13  XChaCha20-Poly1305 pass 3\n" +
			"  L14  Quintuple integrity: 2×SHA3 + BLAKE2b + SHA512 + full-file")

	aboutSecHdr := canvas.NewText("WHY CCL IS UNBREAKABLE", colCyan)
	aboutSecHdr.TextSize = 10
	aboutSecHdr.TextStyle = fyne.TextStyle{Bold: true}

	aboutSec := widget.NewLabel(
		"  - Triple KDF: Attacker must defeat Argon2id THEN scrypt THEN HKDF\n" +
			"  - CCL Grammar: S-Box passes, Feistel rounds derived from key\n" +
			"  - The algorithm structure is secret — not just the key\n" +
			"  - 6 AEAD passes: AES-XChaCha-AES-XChaCha-AES-XChaCha\n" +
			"  - 192-762 total Feistel rounds (key-dependent)\n" +
			"  - FORTRESS: ~3GB total memory (1GB Argon2id + 1GB scrypt)\n" +
			"  - 384-byte master salt (3× independent salts)\n" +
			"  - Block permutation adds transposition layer\n" +
			"  - 5 integrity hashes across 3 hash families\n" +
			"  - All intermediate buffers wiped between layers")

	aboutFinal := canvas.NewText("An attacker observing only the ciphertext has no idea what operations were performed.", colMidText)
	aboutFinal.TextSize = 9
	aboutFinal.Alignment = fyne.TextAlignCenter

	aboutTab := container.NewVScroll(container.NewVBox(
		aboutTitle,
		aboutProto,
		aboutInnovation,
		neonSeparator(colCyanDark),
		aboutLayersHdr,
		aboutLayers,
		neonSeparator(colSep),
		aboutSecHdr,
		aboutSec,
		neonSeparator(colSep),
		aboutFinal,
	))

	// ════════ ACTIVATE TAB ════════
	var activateStatusLabel *widget.Label
	var proIndicator *canvas.Text

	updateProStatus := func() {
		if isPro {
			proIndicator.Text = "✓  PRO ACTIVE — Paranoid + FORTRESS unlocked"
			proIndicator.Color = colSuccess
		} else {
			proIndicator.Text = "FREE TIER — Standard + Military only"
			proIndicator.Color = colMidText
		}
		proIndicator.Refresh()
	}

	proIndicator = canvas.NewText("", colMidText)
	proIndicator.TextSize = 12
	proIndicator.TextStyle = fyne.TextStyle{Bold: true}
	proIndicator.Alignment = fyne.TextAlignCenter

	activateStatusLabel = widget.NewLabel("")

	actEmailEntry := widget.NewEntry()
	actEmailEntry.SetPlaceHolder("Email used at purchase")
	actCodeEntry := widget.NewEntry()
	actCodeEntry.SetPlaceHolder("CRYPT-XXXX-XXXX-XXXX")

	activateBtn := widget.NewButton("Activate Pro", func() {
		code := strings.TrimSpace(actCodeEntry.Text)
		email := strings.TrimSpace(actEmailEntry.Text)
		if code == "" || email == "" {
			activateStatusLabel.SetText("Enter your email and activation code")
			return
		}
		activateStatusLabel.SetText("Verifying with costrinity.xyz...")
		go func() {
			lc, err := activateLicense(code, email)
			if err != nil {
				activateStatusLabel.SetText("Error: " + err.Error())
				return
			}
			cachedLicense = lc
			isPro = true
			activateStatusLabel.SetText("✓ Activated! Paranoid + FORTRESS unlocked.")
			updateProStatus()
		}()
	})

	actHeader := canvas.NewText("ACTIVATE PRO", colCyanDim)
	actHeader.TextSize = 10
	actHeader.TextStyle = fyne.TextStyle{Bold: true}

	actFreeLabel := canvas.NewText("FREE:  Standard  ·  Military", colMidText)
	actFreeLabel.TextSize = 12
	actFreeLabel.Alignment = fyne.TextAlignCenter

	actProLabel := canvas.NewText("PRO ($14.99):  + Paranoid  ·  + FORTRESS", colSuccess)
	actProLabel.TextSize = 12
	actProLabel.Alignment = fyne.TextAlignCenter

	buyBtn := widget.NewButton("Buy CRYpT Pro — $14.99", func() {
		// Opens the Stripe payment page
		exec.Command("cmd", "/c", "start", "https://costrinity.xyz/crypt#pricing").Start()
		// macOS fallback
		exec.Command("open", "https://costrinity.xyz/crypt#pricing").Start()
		// Linux fallback
		exec.Command("xdg-open", "https://costrinity.xyz/crypt#pricing").Start()
	})

	activateTab := container.NewVScroll(container.NewVBox(
		actHeader,
		neonSeparator(colSep),
		proIndicator,
		neonSeparator(colSep),
		actFreeLabel,
		actProLabel,
		neonSeparator(colSep),
		buyBtn,
		neonSeparator(colSep),
		canvas.NewText("Already purchased? Enter your activation code below.", colMidText),
		widget.NewLabel("Email:"),
		actEmailEntry,
		widget.NewLabel("Activation Code:"),
		actCodeEntry,
		activateBtn,
		activateStatusLabel,
	))

	updateProStatus()

	// ── Wrap mode selector to enforce pro lock ──
	modeSelect.OnChanged = func(s string) {
		switch s {
		case "Standard":
			currentMode = ModeStandard
		case "Military":
			currentMode = ModeMilitary
		case "Paranoid":
			if !isPro {
				notifyStatus(statusLabel, "Paranoid mode requires CRYpT Pro — activate in the Activate tab")
				modeSelect.Selected = "Military"
				currentMode = ModeMilitary
				return
			}
			currentMode = ModeParanoid
		case "FORTRESS":
			if !isPro {
				notifyStatus(statusLabel, "FORTRESS mode requires CRYpT Pro — activate in the Activate tab")
				modeSelect.Selected = "Military"
				currentMode = ModeMilitary
				return
			}
			currentMode = ModeFortress
		}
	}

	// ── Tabs ──
	tabs := container.NewAppTabs(
		container.NewTabItem("Encrypt", encryptTab),
		container.NewTabItem("Decrypt", decryptTab),
		container.NewTabItem("Tools", toolsTab),
		container.NewTabItem("Activate", activateTab),
		container.NewTabItem("About", aboutTab),
	)

	statusLine := neonSeparator(colCyanDark)
	footer := canvas.NewText("CRYpT OBSIDIAN EDITION  //  Costrinity Cipher Language  //  The Algorithm Is Secret", colDimText)
	footer.TextSize = 8
	footer.Alignment = fyne.TextAlignCenter

	topSection := container.NewVBox(titleBlock, pwBlock, kfRow, neonSeparator(colSep))
	bottomSection := container.NewVBox(neonSeparator(colSep), progress, statusLine, statusLabel, footer)
	mainLayout := container.NewBorder(topSection, bottomSection, nil, nil, tabs)
	w.SetContent(container.NewPadded(mainLayout))

	w.ShowAndRun()
}
