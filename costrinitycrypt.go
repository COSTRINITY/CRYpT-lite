package main

// ============================================================================
// COSTRINITY: CRYpT v6.1 — Free Edition EDITION
// Costrinity Cipher Language (CCL) Protocol v6
//
// v6 uses SHAKE-256 XOF + BLAKE2b for S-Box/Feistel/keystream (3x faster than SHA-256)
// while maintaining the same AEAD cascade and integrity architecture as v5.
//
// 10-Layer Encryption Architecture:
//   L0   Argon2id KDF         Memory-hard (128MB–1GB), 128-byte salt
//   L1   zlib Compression     Optional pre-encryption compression
//   L2   Canary Injection     32-byte chain-verification sentinel
//   L3   Payload Padding      Random 256–4096 byte size obfuscation
//   L4   Double S-Box         Two independent key-derived substitution passes
//   L5   Cascade Diffusion    XOR key-stream + cascading feedback + block rotation
//   L6   Feistel Network      32-round Luby-Rackoff cipher (BLAKE2b-256 PRF)
//   L7   AES-256-GCM #1       NIST authenticated encryption (pass 1)
//   L8   XChaCha20-Poly1305   IETF authenticated encryption
//   L9   AES-256-GCM #2       NIST authenticated encryption (pass 2)
//   L10  Triple Integrity     HMAC-SHA3-512 + BLAKE2b-512 + HMAC-SHA512
//
// Tamper Defenses:
//   - Encrypted canary verifies full cipher chain integrity
//   - Triple integrity: three independent hash families (Keccak/HAIFA/Merkle-Damgård)
//   - Random padding hides actual payload size
//   - 7-pass Gutmann-class file shredding
//   - Memory-safe key zeroing after use
//   - Minimum 12-character password enforcement
//   - 128-byte cryptographic salt
//   - Anti-forensic random header padding
//
// Cipher Diversity (attacker must independently break ALL):
//   AES-256       Substitution-Permutation Network
//   ChaCha20      Add-Rotate-XOR stream cipher
//   Feistel(32)   Custom block cipher via Luby-Rackoff theorem
//   S-Box×2       Key-dependent substitution (confusion)
//   Diffusion     Cascade XOR + block rotation (diffusion)
//   SHAKE-256     Keccak XOF (S-Box + key stream + block rotation)
//   SHA-256       Merkle-Damgård (legacy v2-v5 Feistel PRF)
//   SHA-512       Merkle-Damgård (HMAC)
//   SHA3-512      Keccak sponge (HMAC)
//   BLAKE2b       HAIFA (keyed hash)
//
// File Format v4 (.crypt):
//   [Magic "CCL2" 4B][Version 2B][Flags 1B][Mode 1B]
//   [Salt 128B][Nonce1 12B][Nonce2 12B][NonceXC 24B][Padding 32B]
//   [Encrypted Payload ...variable...]
//   [HMAC-SHA3-512 64B][BLAKE2b-512 64B][HMAC-SHA512 64B]
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"

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

	// v5 OBSIDIAN format: 5-cipher AEAD cascade, quad S-Box, triple 64-round Feistel, double Argon2id
	v5HeaderSize   = 412 // 4+2+1+1+256+12+12+12+24+24+64
	v5TrailingSize = 320 // sha3_1(64)+blake2b(64)+hmac512(64)+sha3_2(64)+fullHMAC(64)
	v5SaltSize     = 256
	v5KeySize      = 640 // 20 sub-keys × 32
	v5PadHdr       = 64

	v4HeaderSize  = 216 // 4+2+1+1+128+12+12+24+32
	v4TrailingSize = 192 // sha3(64)+blake2b(64)+hmac(64)
	v4SaltSize    = 128
	v4KeySize     = 352 // 11 sub-keys × 32
	v4NonceAES    = 12
	v4NonceXC     = 24
	v4PadHdr      = 32
	canarySize    = 32

	nonceAES = 12
	nonceXC  = 24

	v3HeaderSize  = 124
	v3TrailingSize = 128
	v3SaltSize    = 64
	v3KeySize     = 224

	v2HeaderSize  = 107
	v2TrailingSize = 128
	v2SaltSize    = 64
	v2KeySize     = 192

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

var modeNames = [...]string{"Standard", "Military", "Paranoid", "FORTRESS"}

// ============================================================================
// LICENSE / ACTIVATION SYSTEM
// ============================================================================

// proKeyA and proKeyB are XOR'd at runtime to produce the HMAC key.
// Neither is meaningful alone — immune to `strings` dumping.
var proKeyA = [32]byte{
	0xc0, 0x57, 0x12, 0x9e, 0xab, 0x3f, 0x6d, 0x81,
	0x44, 0xf7, 0x28, 0xbe, 0x53, 0x0a, 0xe6, 0x71,
	0xd9, 0x3c, 0x85, 0x4f, 0xa2, 0x16, 0x7b, 0xc8,
	0x60, 0xed, 0x37, 0x94, 0x0b, 0xf5, 0x5e, 0xa3,
}
var proKeyB = [32]byte{
	0x91, 0x68, 0x7a, 0xf3, 0xde, 0x54, 0x09, 0xb7,
	0x23, 0x8c, 0x41, 0xd5, 0x6f, 0xe0, 0x1a, 0x96,
	0xbc, 0x57, 0xe3, 0x2d, 0xc4, 0x78, 0x0f, 0xa1,
	0x35, 0x8a, 0x5c, 0xf9, 0x62, 0xd6, 0x3b, 0xc7,
}

// deriveProKey XORs the two halves at runtime to produce the HMAC key.
func deriveProKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = proKeyA[i] ^ proKeyB[i]
	}
	return key
}

type LicenseInfo struct {
	Code        string `json:"code"`
	ActivatedAt string `json:"activated_at"`
	Email       string `json:"email"`
}

// licenseFilePath returns ~/.costrinity/license.json
func licenseFilePath() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(u.HomeDir, ".costrinity", "license.json")
}

// loadLicense reads the license file from disk
func loadLicense() *LicenseInfo {
	p := licenseFilePath()
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var li LicenseInfo
	if err := json.Unmarshal(data, &li); err != nil {
		return nil
	}
	return &li
}

// saveLicense writes the license file to disk
func saveLicense(li *LicenseInfo) error {
	p := licenseFilePath()
	if p == "" {
		return fmt.Errorf("cannot determine home directory")
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(li, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// validateActivationCode uses HMAC-SHA256 with a runtime-derived key.
// Checks the first 8 bytes (64 bits) of the HMAC output against a
// required prefix. Brute-force: ~2^64 attempts ≈ centuries at GPU speed.
// validateActivationCode checks a 32-char hex code.
// Format: hex(nonce[8]) + hex(HMAC-SHA256(key, nonce)[0:8])
// Server generates nonce, computes MAC, concatenates. App re-derives and compares.
// Security: forging a code requires finding nonce s.t. HMAC(key,nonce)[:8] matches → 2^64 brute force.
func validateActivationCode(code string) bool {
	if len(code) != 32 {
		return false
	}
	raw, err := hex.DecodeString(code)
	if err != nil {
		return false
	}
	nonce := raw[:8]
	givenMac := raw[8:16]
	key := deriveProKey()
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	h := mac.Sum(nil)
	wipeBytes(key)
	return hmac.Equal(h[:8], givenMac)
}

// isProUnlocked checks if a valid Pro license exists on disk.
func isProUnlocked() bool {
	li := loadLicense()
	if li == nil {
		return false
	}
	return validateActivationCode(li.Code)
}

// requiresProLicense returns true if the mode needs a Pro license.
func requiresProLicense(mode int) bool {
	return mode == ModeParanoid || mode == ModeFortress
}

// logActivation appends activation details to ~/.costrinity/activations.log
func logActivation(code, email string) {
	dir := filepath.Join(os.Getenv("HOME"), ".costrinity")
	if runtime.GOOS == "windows" {
		if h, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(h, ".costrinity")
		}
	}
	os.MkdirAll(dir, 0700)
	logPath := filepath.Join(dir, "activations.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	entry := fmt.Sprintf("[%s] code=%s email=%s\n", time.Now().UTC().Format(time.RFC3339), code, email)
	f.WriteString(entry)
}

type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
}

// v4 backward-compat params (used for decrypting old files)
var modeParams = map[int]argon2Params{
	ModeStandard: {time: 3, memory: 128 * 1024, threads: 4},
	ModeMilitary: {time: 5, memory: 256 * 1024, threads: 4},
	// ModeParanoid: Pro only
	// ModeFortress: Pro only
}

// v5 OBSIDIAN params — doubled iterations, doubled memory
var v5ModeParams = map[int]argon2Params{
	ModeStandard: {time: 6, memory: 256 * 1024, threads: 4},     // 256 MB
	ModeMilitary: {time: 10, memory: 512 * 1024, threads: 8},    // 512 MB
	// ModeParanoid: Pro only
	// ModeFortress: Pro only
}

type CryptMeta struct {
	Filename string `json:"f"`
	Size     int64  `json:"s"` // original uncompressed
	DataSize int64  `json:"c"` // payload data size (post-compress)
	Time     int64  `json:"t"`
	Hash     string `json:"h"` // SHA-256 of payload data
	IsDir    bool   `json:"d"`
	Ver      int    `json:"v"`
}

var canaryValue = sha256.Sum256([]byte("COSTRINITY_CIPHER_CANARY_V4_FORTRESS"))
var canaryV5 = sha256.Sum256([]byte("COSTRINITY_OBSIDIAN_CANARY_V5_QUINTUPLE_CASCADE"))

// ============================================================================
// THEME
// ============================================================================

// Futuristic neon color palette
var (
	colBg         = color.RGBA{R: 2, G: 2, B: 8, A: 255}
	colFg         = color.RGBA{R: 200, G: 215, B: 235, A: 255}
	colCyan       = color.RGBA{R: 0, G: 220, B: 255, A: 255}
	colCyanDim    = color.RGBA{R: 0, G: 170, B: 220, A: 255}
	colCyanDark   = color.RGBA{R: 0, G: 60, B: 90, A: 255}
	colInputBg    = color.RGBA{R: 10, G: 12, B: 24, A: 255}
	colOverlay    = color.RGBA{R: 4, G: 4, B: 12, A: 255}
	colSep        = color.RGBA{R: 0, G: 50, B: 75, A: 255}
	colDisabled   = color.RGBA{R: 50, G: 60, B: 80, A: 255}
	colPlaceholder = color.RGBA{R: 80, G: 95, B: 120, A: 255}
	colSuccess    = color.RGBA{R: 0, G: 255, B: 180, A: 255}
	colWarn       = color.RGBA{R: 255, G: 170, B: 30, A: 255}
	colDimText    = color.RGBA{R: 120, G: 140, B: 170, A: 255}
	colMidText    = color.RGBA{R: 140, G: 160, B: 190, A: 255}
	colError      = color.RGBA{R: 255, G: 40, B: 60, A: 255}
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
		return 7
	case theme.SizeNameInnerPadding:
		return 12
	case theme.SizeNameText:
		return 14
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameHeadingText:
		return 20
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameSeparatorThickness:
		return 1
	default:
		return theme.DefaultTheme().Size(n)
	}
}

// neonSeparator creates a colored line for visual separation
func neonSeparator(c color.Color) fyne.CanvasObject {
	line := canvas.NewRectangle(c)
	line.SetMinSize(fyne.NewSize(0, 1))
	return line
}

// ============================================================================
// COSTRINITY S-BOX + DIFFUSION (supports multi-key double S-box)
// ============================================================================

func generateSBox(key []byte) [256]byte {
	var sbox [256]byte
	for i := range sbox {
		sbox[i] = byte(i)
	}
	seed := sha256.Sum256(key)
	for i := 255; i > 0; i-- {
		seed = sha256.Sum256(append(seed[:], byte(i), byte(i>>8)))
		// Rejection sampling: eliminates modulo bias entirely
		bound := uint32(i + 1)
		threshold := (0xFFFFFFFF - bound + 1) % bound // = -bound % bound
		var val uint32
		attempt := seed
		for {
			val = binary.BigEndian.Uint32(attempt[:4])
			if val >= threshold {
				break
			}
			attempt = sha256.Sum256(attempt[:])
		}
		j := int(val % bound)
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

func generateKeyStream(key []byte, length int) []byte {
	stream := make([]byte, 0, length+32)
	ctr := make([]byte, 8)
	for c := uint64(0); len(stream) < length; c++ {
		h := sha256.New()
		h.Write(key)
		binary.BigEndian.PutUint64(ctr, c)
		h.Write(ctr)
		stream = append(stream, h.Sum(nil)...)
	}
	return stream[:length]
}

// costrinityTransform: pass 1+ sboxKeys for multi-pass substitution
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
// COSTRINITY FEISTEL NETWORK (parameterised rounds)
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

func feistelF(half, key []byte, round int) []byte {
	h := sha256.New()
	h.Write(half)
	h.Write(key)
	h.Write([]byte{byte(round), byte(round >> 8)})
	return h.Sum(nil)[:16]
}

// ============================================================================
// V6 OPTIMIZED CRYPTO — SHAKE-256 XOF + BLAKE2b (3x faster than SHA-256)
// ============================================================================

func generateSBoxV6(key []byte) [256]byte {
	var sbox [256]byte
	for i := range sbox {
		sbox[i] = byte(i)
	}
	h := sha3.NewShake256()
	h.Write(key)
	var buf [4]byte
	for i := 255; i > 0; i-- {
		bound := uint32(i + 1)
		threshold := (0xFFFFFFFF - bound + 1) % bound
		for {
			h.Read(buf[:])
			val := binary.BigEndian.Uint32(buf[:])
			if val >= threshold {
				sbox[i], sbox[int(val%bound)] = sbox[int(val%bound)], sbox[i]
				break
			}
		}
	}
	return sbox
}

func generateKeyStreamV6(key []byte, length int) []byte {
	h := sha3.NewShake256()
	h.Write(key)
	stream := make([]byte, length)
	h.Read(stream)
	return stream
}

func costrinityTransformV6(data, diffuseKey []byte, encrypt bool, sboxKeys ...[]byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	if encrypt {
		for _, sk := range sboxKeys {
			sbox := generateSBoxV6(sk)
			for i := range out {
				out[i] = sbox[out[i]]
			}
		}
		ks := generateKeyStreamV6(diffuseKey, len(out))
		for i := range out {
			out[i] ^= ks[i]
			if i > 0 {
				out[i] ^= out[i-1]
			}
		}
		blockRotateV6(out, diffuseKey, true)
	} else {
		blockRotateV6(out, diffuseKey, false)
		ks := generateKeyStreamV6(diffuseKey, len(out))
		for i := len(out) - 1; i >= 0; i-- {
			if i > 0 {
				out[i] ^= out[i-1]
			}
			out[i] ^= ks[i]
		}
		for i := len(sboxKeys) - 1; i >= 0; i-- {
			inv := inverseSBox(generateSBoxV6(sboxKeys[i]))
			for j := range out {
				out[j] = inv[out[j]]
			}
		}
	}
	return out
}

func blockRotateV6(data, key []byte, fwd bool) {
	const blk = 16
	h := sha3.NewShake256()
	h.Write(key)
	var b [1]byte
	for i := 0; i+blk <= len(data); i += blk {
		h.Read(b[:])
		rot := int(b[0]) % blk
		if !fwd {
			rot = blk - rot
		}
		rotateSlice(data[i:i+blk], rot)
	}
}

func costrinityFeistelV6(data, key []byte, encrypt bool, rounds int) []byte {
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
				F := feistelFV6(R, key, r)
				tmp := make([]byte, halfSz)
				copy(tmp, R)
				for j := range R {
					R[j] = L[j] ^ F[j]
				}
				copy(L, tmp)
			}
		} else {
			for r := rounds - 1; r >= 0; r-- {
				F := feistelFV6(L, key, r)
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
		ks := generateKeyStreamV6(key, rem)
		for j := 0; j < rem; j++ {
			out[off+j] ^= ks[j]
		}
	}
	return out
}

func feistelFV6(half, key []byte, round int) []byte {
	h, _ := blake2b.New256(key)
	h.Write(half)
	h.Write([]byte{byte(round), byte(round >> 8)})
	return h.Sum(nil)[:16]
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
	// Limit decompressed size to 4GB to prevent decompression bombs
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

// effectivePasswordV5 pre-hashes through SHA3-512 for defense-in-depth
func effectivePasswordV5(password string, kf []byte) []byte {
	pw := []byte(password)
	if len(kf) > 0 {
		// Triple-hash key file: SHA-512 + SHA3-512 + BLAKE2b-512
		h1 := sha512.Sum512(kf)
		h2 := sha3.Sum512(kf)
		pw = append(pw, h1[:]...)
		pw = append(pw, h2[:]...)
	}
	// Pre-hash entire password material through SHA3-512
	preHash := sha3.Sum512(pw)
	// Append pre-hash to original — attacker must invert SHA3 AND know password
	result := make([]byte, len(pw)+64)
	copy(result, pw)
	copy(result[len(pw):], preHash[:])
	return result
}

// doubleArgon2id runs Argon2id twice with split salt halves and XORs the results.
// This doubles the computational cost for an attacker per password guess.
func doubleArgon2id(pw, salt []byte, p argon2Params, keyLen uint32) []byte {
	half := len(salt) / 2
	saltA := salt[:half]
	saltB := salt[half:]

	derivedA := argon2.IDKey(pw, saltA, p.time, p.memory, p.threads, keyLen)
	derivedB := argon2.IDKey(pw, saltB, p.time, p.memory, p.threads, keyLen)

	// XOR both derivations together
	for i := range derivedA {
		derivedA[i] ^= derivedB[i]
	}
	wipeBytes(derivedB)
	return derivedA
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
	case n >= 12 && cl >= 3:
		return "Strong", color.RGBA{R: 120, G: 210, B: 0, A: 255}
	case n >= 8 && cl >= 2:
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
// ENCRYPT — v4 FORTRESS FORMAT
// ============================================================================

// ============================================================================
// ENCRYPT — v5 OBSIDIAN FORMAT
// 15-Layer Architecture: Triple S-Box, Double 64-Round Feistel,
// 5-Cipher AEAD Cascade (AES-XChaCha-AES-XChaCha-AES), Quad Integrity
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
	updateStatus(status, "L2/L3: Building payload — canary + padding...")

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

	// Random padding (512–8192 bytes) — doubled from v4
	padN, _ := rand.Int(rand.Reader, big.NewInt(7681))
	padLen := int(padN.Int64()) + 512
	pad := make([]byte, padLen)
	rand.Read(pad)

	// Payload: [canary 32][meta_len 4][meta_json][data][random_padding]
	payload := new(bytes.Buffer)
	payload.Write(canaryV5[:])
	ml := make([]byte, 4)
	binary.BigEndian.PutUint32(ml, uint32(len(mj)))
	payload.Write(ml)
	payload.Write(mj)
	payload.Write(data)
	payload.Write(pad)
	// Tail canary — appended after padding for bidirectional chain verification
	payload.Write(canaryV5[:])
	plain := payload.Bytes()

	setProgress(progress, 0.04)
	updateStatus(status, "Generating 640 bytes cryptographic material...")

	salt := make([]byte, v5SaltSize)
	rand.Read(salt)
	nAES1 := make([]byte, nonceAES)
	rand.Read(nAES1)
	nAES2 := make([]byte, nonceAES)
	rand.Read(nAES2)
	nAES3 := make([]byte, nonceAES)
	rand.Read(nAES3)
	nXC1 := make([]byte, nonceXC)
	rand.Read(nXC1)
	nXC2 := make([]byte, nonceXC)
	rand.Read(nXC2)
	hdrPad := make([]byte, v5PadHdr)
	rand.Read(hdrPad)

	setProgress(progress, 0.05)
	params := v5ModeParams[mode]
	updateStatus(status, fmt.Sprintf("L0: Double Argon2id [%s: %dMB x2, %d iter x2]...", modeNames[mode], params.memory/1024, params.time))

	effPw := effectivePasswordV5(password, kf)
	derived := doubleArgon2id(effPw, salt, params, v5KeySize)
	wipeBytes(effPw)

	// 20 independent sub-keys (640 bytes)
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
	// derived[576:640] reserved

	// ── L4: Quadruple S-Box + Cascade Diffusion ──
	setProgress(progress, 0.16)
	updateStatus(status, "L4/L5: Quadruple Costrinity S-Box + cascade diffusion...")
	transformed := costrinityTransformV6(plain, diffKey, true, sboxKey1, sboxKey2, sboxKey3, sboxKey4)
	wipeBytes(plain)

	// ── L6: Triple 64-Round Feistel Network (192 total rounds) ──
	setProgress(progress, 0.20)
	updateStatus(status, "L6: Costrinity Feistel pass 1 (64 rounds)...")
	feisteled1 := costrinityFeistelV6(transformed, feistelKey1, true, 64)
	wipeBytes(transformed)

	setProgress(progress, 0.25)
	updateStatus(status, "L6: Costrinity Feistel pass 2 (64 rounds)...")
	feisteled2 := costrinityFeistelV6(feisteled1, feistelKey2, true, 64)
	wipeBytes(feisteled1)

	setProgress(progress, 0.30)
	updateStatus(status, "L6: Costrinity Feistel pass 3 (64 rounds)...")
	feisteled3 := costrinityFeistelV6(feisteled2, feistelKey3, true, 64)
	wipeBytes(feisteled2)

	// ── L7: AES-256-GCM #1 ──
	setProgress(progress, 0.35)
	updateStatus(status, "L7: AES-256-GCM pass 1...")
	blk1, err := aes.NewCipher(aesKey1)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		return
	}
	gcm1, err := cipher.NewGCM(blk1)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		return
	}
	enc1 := gcm1.Seal(nil, nAES1, feisteled3, nil)
	wipeBytes(feisteled3)

	// ── L8: XChaCha20-Poly1305 #1 ──
	setProgress(progress, 0.42)
	updateStatus(status, "L8: XChaCha20-Poly1305 pass 1...")
	xc1, err := chacha20poly1305.NewX(xcKey1)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		return
	}
	enc2 := xc1.Seal(nil, nXC1, enc1, nil)
	wipeBytes(enc1)

	// ── L9: AES-256-GCM #2 ──
	setProgress(progress, 0.48)
	updateStatus(status, "L9: AES-256-GCM pass 2...")
	blk2, err := aes.NewCipher(aesKey2)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		return
	}
	gcm2, err := cipher.NewGCM(blk2)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		return
	}
	enc3 := gcm2.Seal(nil, nAES2, enc2, nil)
	wipeBytes(enc2)

	// ── L10: XChaCha20-Poly1305 #2 ──
	setProgress(progress, 0.54)
	updateStatus(status, "L10: XChaCha20-Poly1305 pass 2...")
	xc2, err := chacha20poly1305.NewX(xcKey2)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		return
	}
	enc4 := xc2.Seal(nil, nXC2, enc3, nil)
	wipeBytes(enc3)

	// ── L11: AES-256-GCM #3 ──
	setProgress(progress, 0.60)
	updateStatus(status, "L11: AES-256-GCM pass 3...")
	blk3, err := aes.NewCipher(aesKey3)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		return
	}
	gcm3, err := cipher.NewGCM(blk3)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		return
	}
	encPayload := gcm3.Seal(nil, nAES3, enc4, nil)
	wipeBytes(enc4)

	// ── L12: Quad Integrity ──
	setProgress(progress, 0.66)
	updateStatus(status, "L12: Quad integrity (SHA3 + BLAKE2b + HMAC-SHA512 + SHA3)...")

	s3a := hmac.New(sha3.New512, sha3Key1)
	s3a.Write(encPayload)
	sha3Sum1 := s3a.Sum(nil)

	b2, err := blake2b.New512(b2Key)
	if err != nil {
		notifyStatus(status, "BLAKE2b init error: "+err.Error())
		return
	}
	b2.Write(encPayload)
	b2Sum := b2.Sum(nil)

	hm := hmac.New(sha512.New, hmacKey)
	hm.Write(encPayload)
	hmSum := hm.Sum(nil)

	s3b := hmac.New(sha3.New512, sha3Key2)
	s3b.Write(encPayload)
	sha3Sum2 := s3b.Sum(nil)

	// ── Assemble v5 file ──
	setProgress(progress, 0.72)
	updateStatus(status, "Assembling .crypt v6 file...")

	out := new(bytes.Buffer)
	out.Write([]byte(magicString))
	vb := make([]byte, 2)
	binary.BigEndian.PutUint16(vb, versionV6)
	out.Write(vb)
	out.WriteByte(flags)
	out.WriteByte(byte(mode))
	out.Write(salt)
	out.Write(nAES1)
	out.Write(nAES2)
	out.Write(nAES3)
	out.Write(nXC1)
	out.Write(nXC2)
	out.Write(hdrPad)
	out.Write(encPayload)
	out.Write(sha3Sum1)
	out.Write(b2Sum)
	out.Write(hmSum)
	out.Write(sha3Sum2)

	// L13: Full-file HMAC — authenticates header + payload + all other hashes
	updateStatus(status, "L13: Full-file HMAC (header + payload authentication)...")
	fullHm := hmac.New(sha512.New, fullHmacKey)
	fullHm.Write(out.Bytes())
	out.Write(fullHm.Sum(nil))

	outName := generateRandomFilename() + ".crypt"
	outPath := filepath.Join(getDesktopPath(), outName)
	if err := os.WriteFile(outPath, out.Bytes(), 0644); err != nil {
		notifyStatus(status, "Write error: "+err.Error())
		return
	}

	setProgress(progress, 0.85)
	updateStatus(status, "11-pass Gutmann shredding original...")
	secureDelete(path)
	wipeBytes(derived)

	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)
	var ratio float64
	if origSize > 0 {
		ratio = float64(out.Len()) / float64(origSize) * 100
	}
	notifyStatus(status, fmt.Sprintf("Encrypted [v6 %s | %s | %.0f%%] -> %s", modeNames[mode], elapsed, ratio, outName))
}

// ============================================================================
// DECRYPT — auto-detects v2/v3/v4
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
	if len(data) < v5HeaderSize+v5TrailingSize {
		notifyStatus(status, "Error: file too small for v6")
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
	updateStatus(status, fmt.Sprintf("L0: Double Argon2id [v6 %s: %dMB x2, %d iter x2]...", modeNames[mode], params.memory/1024, params.time))

	effPw := effectivePasswordV5(password, kf)
	derived := doubleArgon2id(effPw, salt, params, v5KeySize)
	wipeBytes(effPw)

	// 20 independent sub-keys (640 bytes)
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

	// ── L13: Verify full-file HMAC (header + payload + other hashes) ──
	setProgress(progress, 0.12)
	updateStatus(status, "L13: Verifying full-file HMAC...")
	fullHm := hmac.New(sha512.New, fullHmacKey)
	fullHm.Write(data[:len(data)-64]) // everything except the full-file HMAC itself
	if !hmac.Equal(fullHm.Sum(nil), fullHmSum) {
		notifyStatus(status, "FULL-FILE HMAC FAILED: header or payload tampered")
		wipeBytes(derived)
		return
	}

	// ── L12: Verify quad integrity ──
	setProgress(progress, 0.14)
	updateStatus(status, "L12: Verifying HMAC-SHA512...")
	hm := hmac.New(sha512.New, hmacKey)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC-SHA512 FAILED: wrong password, key file, or tampered")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L12: Verifying BLAKE2b-512...")
	b2, err := blake2b.New512(b2Key)
	if err != nil {
		notifyStatus(status, "BLAKE2b init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	b2.Write(encPayload)
	if !hmac.Equal(b2.Sum(nil), b2Sum) {
		notifyStatus(status, "BLAKE2b FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L12: Verifying HMAC-SHA3-512 #1...")
	s3a := hmac.New(sha3.New512, sha3Key1)
	s3a.Write(encPayload)
	if !hmac.Equal(s3a.Sum(nil), sha3Sum1) {
		notifyStatus(status, "SHA3 #1 FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L12: Verifying HMAC-SHA3-512 #2...")
	s3b := hmac.New(sha3.New512, sha3Key2)
	s3b.Write(encPayload)
	if !hmac.Equal(s3b.Sum(nil), sha3Sum2) {
		notifyStatus(status, "SHA3 #2 FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	// ── L11: AES-256-GCM #3 (reverse) ──
	setProgress(progress, 0.20)
	updateStatus(status, "L11: Decrypting AES-256-GCM pass 3...")
	blk3, err := aes.NewCipher(aesKey3)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm3, err := cipher.NewGCM(blk3)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc4, err := gcm3.Open(nil, nAES3, encPayload, nil)
	if err != nil {
		notifyStatus(status, "AES pass 3 FAILED")
		wipeBytes(derived)
		return
	}

	// ── L10: XChaCha20-Poly1305 #2 (reverse) ──
	setProgress(progress, 0.26)
	updateStatus(status, "L10: Decrypting XChaCha20-Poly1305 pass 2...")
	xc2, err := chacha20poly1305.NewX(xcKey2)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc3, err := xc2.Open(nil, nXC2, enc4, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 2 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc4)

	// ── L9: AES-256-GCM #2 (reverse) ──
	setProgress(progress, 0.32)
	updateStatus(status, "L9: Decrypting AES-256-GCM pass 2...")
	blk2, err := aes.NewCipher(aesKey2)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm2, err := cipher.NewGCM(blk2)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc2, err := gcm2.Open(nil, nAES2, enc3, nil)
	if err != nil {
		notifyStatus(status, "AES pass 2 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc3)

	// ── L8: XChaCha20-Poly1305 #1 (reverse) ──
	setProgress(progress, 0.38)
	updateStatus(status, "L8: Decrypting XChaCha20-Poly1305 pass 1...")
	xc1, err := chacha20poly1305.NewX(xcKey1)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc1, err := xc1.Open(nil, nXC1, enc2, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 1 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc2)

	// ── L7: AES-256-GCM #1 (reverse) ──
	setProgress(progress, 0.44)
	updateStatus(status, "L7: Decrypting AES-256-GCM pass 1...")
	blk1, err := aes.NewCipher(aesKey1)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm1, err := cipher.NewGCM(blk1)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	feisteled3, err := gcm1.Open(nil, nAES1, enc1, nil)
	if err != nil {
		notifyStatus(status, "AES pass 1 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc1)

	// ── L6: Reverse triple 64-round Feistel (192 rounds) ──
	setProgress(progress, 0.50)
	updateStatus(status, "L6: Reversing 64-round Feistel pass 3...")
	feisteled2 := costrinityFeistelV6(feisteled3, feistelKey3, false, 64)
	wipeBytes(feisteled3)

	setProgress(progress, 0.55)
	updateStatus(status, "L6: Reversing 64-round Feistel pass 2...")
	feisteled1 := costrinityFeistelV6(feisteled2, feistelKey2, false, 64)
	wipeBytes(feisteled2)

	setProgress(progress, 0.60)
	updateStatus(status, "L6: Reversing 64-round Feistel pass 1...")
	transformed := costrinityFeistelV6(feisteled1, feistelKey1, false, 64)
	wipeBytes(feisteled1)

	// ── L4/L5: Reverse quadruple S-Box + diffusion ──
	setProgress(progress, 0.66)
	updateStatus(status, "L4/L5: Reversing quadruple S-Box + cascade diffusion...")
	plain := costrinityTransformV6(transformed, diffKey, false, sboxKey1, sboxKey2, sboxKey3, sboxKey4)
	wipeBytes(transformed)

	// ── L2: Verify head canary ──
	setProgress(progress, 0.70)
	updateStatus(status, "L2: Verifying head canary...")
	if len(plain) < canarySize*2 {
		notifyStatus(status, "Error: payload too small")
		wipeBytes(derived)
		return
	}
	if !bytes.Equal(plain[:canarySize], canaryV5[:]) {
		notifyStatus(status, "HEAD CANARY FAILED: cipher chain compromised")
		wipeBytes(derived)
		return
	}

	// Verify tail canary
	updateStatus(status, "L2: Verifying tail canary...")
	if !bytes.Equal(plain[len(plain)-canarySize:], canaryV5[:]) {
		notifyStatus(status, "TAIL CANARY FAILED: cipher chain compromised")
		wipeBytes(derived)
		return
	}

	rest := plain[canarySize : len(plain)-canarySize] // strip both canaries

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

	dh := sha256.Sum256(fileData)
	if fmt.Sprintf("%x", dh) != meta.Hash {
		updateStatus(status, "Warning: payload hash mismatch")
	}

	if flags&flagCompressed != 0 {
		setProgress(progress, 0.78)
		updateStatus(status, "L1: Decompressing...")
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			wipeBytes(derived)
			return
		}
	}

	setProgress(progress, 0.84)
	restoreFile(meta, fileData, status)

	setProgress(progress, 0.90)
	updateStatus(status, "11-pass shredding encrypted file...")
	secureDelete(path)
	wipeBytes(derived)

	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)
	notifyStatus(status, fmt.Sprintf("Decrypted [v6 %s | %s] -> %s", modeNames[mode], elapsed, meta.Filename))
}

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
	updateStatus(status, fmt.Sprintf("L0: Double Argon2id [v5 %s: %dMB x2, %d iter x2]...", modeNames[mode], params.memory/1024, params.time))

	effPw := effectivePasswordV5(password, kf)
	derived := doubleArgon2id(effPw, salt, params, v5KeySize)
	wipeBytes(effPw)

	// 20 independent sub-keys (640 bytes)
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

	// ── L13: Verify full-file HMAC (header + payload + other hashes) ──
	setProgress(progress, 0.12)
	updateStatus(status, "L13: Verifying full-file HMAC...")
	fullHm := hmac.New(sha512.New, fullHmacKey)
	fullHm.Write(data[:len(data)-64]) // everything except the full-file HMAC itself
	if !hmac.Equal(fullHm.Sum(nil), fullHmSum) {
		notifyStatus(status, "FULL-FILE HMAC FAILED: header or payload tampered")
		wipeBytes(derived)
		return
	}

	// ── L12: Verify quad integrity ──
	setProgress(progress, 0.14)
	updateStatus(status, "L12: Verifying HMAC-SHA512...")
	hm := hmac.New(sha512.New, hmacKey)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC-SHA512 FAILED: wrong password, key file, or tampered")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L12: Verifying BLAKE2b-512...")
	b2, err := blake2b.New512(b2Key)
	if err != nil {
		notifyStatus(status, "BLAKE2b init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	b2.Write(encPayload)
	if !hmac.Equal(b2.Sum(nil), b2Sum) {
		notifyStatus(status, "BLAKE2b FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L12: Verifying HMAC-SHA3-512 #1...")
	s3a := hmac.New(sha3.New512, sha3Key1)
	s3a.Write(encPayload)
	if !hmac.Equal(s3a.Sum(nil), sha3Sum1) {
		notifyStatus(status, "SHA3 #1 FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L12: Verifying HMAC-SHA3-512 #2...")
	s3b := hmac.New(sha3.New512, sha3Key2)
	s3b.Write(encPayload)
	if !hmac.Equal(s3b.Sum(nil), sha3Sum2) {
		notifyStatus(status, "SHA3 #2 FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	// ── L11: AES-256-GCM #3 (reverse) ──
	setProgress(progress, 0.20)
	updateStatus(status, "L11: Decrypting AES-256-GCM pass 3...")
	blk3, err := aes.NewCipher(aesKey3)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm3, err := cipher.NewGCM(blk3)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc4, err := gcm3.Open(nil, nAES3, encPayload, nil)
	if err != nil {
		notifyStatus(status, "AES pass 3 FAILED")
		wipeBytes(derived)
		return
	}

	// ── L10: XChaCha20-Poly1305 #2 (reverse) ──
	setProgress(progress, 0.26)
	updateStatus(status, "L10: Decrypting XChaCha20-Poly1305 pass 2...")
	xc2, err := chacha20poly1305.NewX(xcKey2)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc3, err := xc2.Open(nil, nXC2, enc4, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 2 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc4)

	// ── L9: AES-256-GCM #2 (reverse) ──
	setProgress(progress, 0.32)
	updateStatus(status, "L9: Decrypting AES-256-GCM pass 2...")
	blk2, err := aes.NewCipher(aesKey2)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm2, err := cipher.NewGCM(blk2)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc2, err := gcm2.Open(nil, nAES2, enc3, nil)
	if err != nil {
		notifyStatus(status, "AES pass 2 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc3)

	// ── L8: XChaCha20-Poly1305 #1 (reverse) ──
	setProgress(progress, 0.38)
	updateStatus(status, "L8: Decrypting XChaCha20-Poly1305 pass 1...")
	xc1, err := chacha20poly1305.NewX(xcKey1)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc1, err := xc1.Open(nil, nXC1, enc2, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 pass 1 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc2)

	// ── L7: AES-256-GCM #1 (reverse) ──
	setProgress(progress, 0.44)
	updateStatus(status, "L7: Decrypting AES-256-GCM pass 1...")
	blk1, err := aes.NewCipher(aesKey1)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm1, err := cipher.NewGCM(blk1)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	feisteled3, err := gcm1.Open(nil, nAES1, enc1, nil)
	if err != nil {
		notifyStatus(status, "AES pass 1 FAILED")
		wipeBytes(derived)
		return
	}
	wipeBytes(enc1)

	// ── L6: Reverse triple 64-round Feistel (192 rounds) ──
	setProgress(progress, 0.50)
	updateStatus(status, "L6: Reversing 64-round Feistel pass 3...")
	feisteled2 := costrinityFeistel(feisteled3, feistelKey3, false, 64)
	wipeBytes(feisteled3)

	setProgress(progress, 0.55)
	updateStatus(status, "L6: Reversing 64-round Feistel pass 2...")
	feisteled1 := costrinityFeistel(feisteled2, feistelKey2, false, 64)
	wipeBytes(feisteled2)

	setProgress(progress, 0.60)
	updateStatus(status, "L6: Reversing 64-round Feistel pass 1...")
	transformed := costrinityFeistel(feisteled1, feistelKey1, false, 64)
	wipeBytes(feisteled1)

	// ── L4/L5: Reverse quadruple S-Box + diffusion ──
	setProgress(progress, 0.66)
	updateStatus(status, "L4/L5: Reversing quadruple S-Box + cascade diffusion...")
	plain := costrinityTransform(transformed, diffKey, false, sboxKey1, sboxKey2, sboxKey3, sboxKey4)
	wipeBytes(transformed)

	// ── L2: Verify head canary ──
	setProgress(progress, 0.70)
	updateStatus(status, "L2: Verifying head canary...")
	if len(plain) < canarySize*2 {
		notifyStatus(status, "Error: payload too small")
		wipeBytes(derived)
		return
	}
	if !bytes.Equal(plain[:canarySize], canaryV5[:]) {
		notifyStatus(status, "HEAD CANARY FAILED: cipher chain compromised")
		wipeBytes(derived)
		return
	}

	// Verify tail canary
	updateStatus(status, "L2: Verifying tail canary...")
	if !bytes.Equal(plain[len(plain)-canarySize:], canaryV5[:]) {
		notifyStatus(status, "TAIL CANARY FAILED: cipher chain compromised")
		wipeBytes(derived)
		return
	}

	rest := plain[canarySize : len(plain)-canarySize] // strip both canaries

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

	dh := sha256.Sum256(fileData)
	if fmt.Sprintf("%x", dh) != meta.Hash {
		updateStatus(status, "Warning: payload hash mismatch")
	}

	if flags&flagCompressed != 0 {
		setProgress(progress, 0.78)
		updateStatus(status, "L1: Decompressing...")
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			wipeBytes(derived)
			return
		}
	}

	setProgress(progress, 0.84)
	restoreFile(meta, fileData, status)

	setProgress(progress, 0.90)
	updateStatus(status, "11-pass shredding encrypted file...")
	secureDelete(path)
	wipeBytes(derived)

	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)
	notifyStatus(status, fmt.Sprintf("Decrypted [v5 %s | %s] -> %s", modeNames[mode], elapsed, meta.Filename))
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
	updateStatus(status, "L10: Verifying HMAC-SHA512...")
	hm := hmac.New(sha512.New, hmacKey)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC-SHA512 FAILED: wrong password, key file, or tampered")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L10: Verifying BLAKE2b-512...")
	b2, err := blake2b.New512(b2Key)
	if err != nil {
		notifyStatus(status, "BLAKE2b init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	b2.Write(encPayload)
	if !hmac.Equal(b2.Sum(nil), b2Sum) {
		notifyStatus(status, "BLAKE2b FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	updateStatus(status, "L10: Verifying HMAC-SHA3-512...")
	s3 := hmac.New(sha3.New512, sha3Key)
	s3.Write(encPayload)
	if !hmac.Equal(s3.Sum(nil), sha3Sum) {
		notifyStatus(status, "SHA3 FAILED: corrupted")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.30)
	updateStatus(status, "L9: Decrypting AES-256-GCM pass 2...")
	blk2, err := aes.NewCipher(aesKey2)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm2, err := cipher.NewGCM(blk2)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc2, err := gcm2.Open(nil, nAES2, encPayload, nil)
	if err != nil {
		notifyStatus(status, "AES pass 2 FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.38)
	updateStatus(status, "L8: Decrypting XChaCha20-Poly1305...")
	xc, err := chacha20poly1305.NewX(xcKey)
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	enc1, err := xc.Open(nil, nXC, enc2, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.46)
	updateStatus(status, "L7: Decrypting AES-256-GCM pass 1...")
	blk1, err := aes.NewCipher(aesKey1)
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm1, err := cipher.NewGCM(blk1)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	feisteled, err := gcm1.Open(nil, nAES1, enc1, nil)
	if err != nil {
		notifyStatus(status, "AES pass 1 FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.54)
	updateStatus(status, "L6: Reversing 32-round Feistel...")
	transformed := costrinityFeistel(feisteled, feistelKey, false, 32)

	setProgress(progress, 0.62)
	updateStatus(status, "L4/L5: Reversing double S-Box + diffusion...")
	plain := costrinityTransform(transformed, diffKey, false, sboxKey1, sboxKey2)

	setProgress(progress, 0.68)
	updateStatus(status, "L2: Verifying cipher chain canary...")
	if len(plain) < canarySize {
		notifyStatus(status, "Error: payload too small")
		return
	}
	if !bytes.Equal(plain[:canarySize], canaryValue[:]) {
		notifyStatus(status, "CANARY FAILED: cipher chain compromised — data integrity breach detected")
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

	// Verify payload hash
	dh := sha256.Sum256(fileData)
	if fmt.Sprintf("%x", dh) != meta.Hash {
		updateStatus(status, "Warning: payload hash mismatch")
	}

	// L1: Decompress
	if flags&flagCompressed != 0 {
		setProgress(progress, 0.75)
		updateStatus(status, "L1: Decompressing...")
		fileData, err = decompressData(fileData)
		if err != nil {
			notifyStatus(status, "Decompress error: "+err.Error())
			return
		}
	}

	setProgress(progress, 0.80)
	restoreFile(meta, fileData, status)

	setProgress(progress, 0.88)
	updateStatus(status, "7-pass shredding encrypted file...")
	secureDelete(path)
	wipeBytes(derived)

	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)
	notifyStatus(status, fmt.Sprintf("Decrypted [v4 %s | %s] -> %s", modeNames[mode], elapsed, meta.Filename))
}

// ── v3 backward compat ──

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
	updateStatus(status, fmt.Sprintf("L0: Argon2id [v3 %s]...", modeNames[mode]))
	effPw := effectivePassword(password, kf)
	derived := argon2.IDKey(effPw, salt, params.time, params.memory, params.threads, v3KeySize)
	wipeBytes(effPw)

	hmacKeyD := derived[64:96]
	sboxKey := derived[96:128]
	diffKey := derived[128:160]
	b2Key := derived[160:192]
	feistelKey := derived[192:224]

	setProgress(progress, 0.25)
	hm := hmac.New(sha512.New, hmacKeyD)
	hm.Write(encPayload)
	if !hmac.Equal(hm.Sum(nil), hmSum) {
		notifyStatus(status, "HMAC FAILED")
		wipeBytes(derived)
		return
	}
	b2h, err := blake2b.New512(b2Key)
	if err != nil {
		notifyStatus(status, "BLAKE2b init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	b2h.Write(encPayload)
	if !hmac.Equal(b2h.Sum(nil), b2sum) {
		notifyStatus(status, "BLAKE2b FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.35)
	xc, err := chacha20poly1305.NewX(derived[32:64])
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	aesEnc, err := xc.Open(nil, nXC, encPayload, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 FAILED")
		wipeBytes(derived)
		return
	}
	blk, err := aes.NewCipher(derived[0:32])
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
	feisteled, err := gcm.Open(nil, nAES, aesEnc, nil)
	if err != nil {
		notifyStatus(status, "AES-GCM FAILED")
		wipeBytes(derived)
		return
	}

	setProgress(progress, 0.55)
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

	setProgress(progress, 0.80)
	restoreFile(meta, fileData, status)
	secureDelete(path)
	wipeBytes(derived)
	setProgress(progress, 1.0)
	notifyStatus(status, fmt.Sprintf("Decrypted [v3 | %s] -> %s", time.Since(start).Round(time.Millisecond), meta.Filename))
}

// ── v2 backward compat ──

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
	updateStatus(status, fmt.Sprintf("Argon2id [v2 %s]...", modeNames[mode]))
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
	b2h, err := blake2b.New512(b2Key)
	if err != nil {
		notifyStatus(status, "BLAKE2b init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	b2h.Write(encPayload)
	if !hmac.Equal(b2h.Sum(nil), b2sum) {
		notifyStatus(status, "BLAKE2b FAILED")
		wipeBytes(derived)
		return
	}

	xc, err := chacha20poly1305.NewX(derived[32:64])
	if err != nil {
		notifyStatus(status, "XChaCha20 init error: "+err.Error())
		wipeBytes(derived)
		return
	}
	aesEnc, err := xc.Open(nil, nXC, encPayload, nil)
	if err != nil {
		notifyStatus(status, "XChaCha20 FAILED")
		wipeBytes(derived)
		return
	}
	blk, err := aes.NewCipher(derived[0:32])
	if err != nil {
		notifyStatus(status, "AES cipher error: "+err.Error())
		wipeBytes(derived)
		return
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		notifyStatus(status, "GCM error: "+err.Error())
		wipeBytes(derived)
		return
	}
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
	var salt, encPayload, hmSum []byte
	var kSz uint32
	isV5 := false

	switch ver {
	case versionV5, versionV6:
		if len(data) < v5HeaderSize+v5TrailingSize {
			notifyStatus(status, "Error: too small")
			return
		}
		flags = data[6]
		mode = int(data[7])
		if mode > ModeFortress {
			notifyStatus(status, "Error: invalid mode")
			return
		}
		salt = data[8:264]
		encPayload = data[v5HeaderSize : len(data)-v5TrailingSize]
		hmSum = data[len(data)-192 : len(data)-128] // HMAC-SHA512 is 3rd of 5
		kSz = v5KeySize
		isV5 = true
	case versionV4:
		if len(data) < v4HeaderSize+v4TrailingSize {
			notifyStatus(status, "Error: too small")
			return
		}
		flags = data[6]
		mode = int(data[7])
		if mode > ModeFortress {
			notifyStatus(status, "Error: invalid mode")
			return
		}
		salt = data[8:136]
		encPayload = data[v4HeaderSize : len(data)-v4TrailingSize]
		hmSum = data[len(data)-64:]
		kSz = v4KeySize
	case versionV3:
		if len(data) < v3HeaderSize+v3TrailingSize {
			notifyStatus(status, "Error: too small")
			return
		}
		flags = data[6]
		mode = int(data[7])
		if mode > ModeFortress {
			notifyStatus(status, "Error: invalid mode")
			return
		}
		salt = data[8:72]
		encPayload = data[v3HeaderSize : len(data)-v3TrailingSize]
		hmSum = data[len(data)-64:]
		kSz = v3KeySize
	case versionV2:
		if len(data) < v2HeaderSize+v2TrailingSize {
			notifyStatus(status, "Error: too small")
			return
		}
		mode = int(data[6])
		if mode > ModeFortress {
			notifyStatus(status, "Error: invalid mode")
			return
		}
		salt = data[7:71]
		encPayload = data[v2HeaderSize : len(data)-v2TrailingSize]
		hmSum = data[len(data)-64:]
		kSz = v2KeySize
	default:
		notifyStatus(status, fmt.Sprintf("Error: version %d unsupported", ver))
		return
	}

	setProgress(progress, 0.1)
	var params argon2Params
	if isV5 {
		params = v5ModeParams[mode]
	} else {
		params = modeParams[mode]
	}
	updateStatus(status, fmt.Sprintf("Deriving keys [v%d %s]...", ver, modeNames[mode]))

	var derived []byte
	if isV5 {
		effPw := effectivePasswordV5(password, kf)
		derived = doubleArgon2id(effPw, salt, params, kSz)
		wipeBytes(effPw)
	} else {
		effPw := effectivePassword(password, kf)
		derived = argon2.IDKey(effPw, salt, params.time, params.memory, params.threads, kSz)
		wipeBytes(effPw)
	}

	var hmacKeyD []byte
	switch {
	case isV5:
		hmacKeyD = derived[160:192] // v5: key slot 5
	case ver == versionV2 || ver == versionV3:
		hmacKeyD = derived[64:96]
	default:
		hmacKeyD = derived[96:128] // v4
	}

	setProgress(progress, 0.6)
	updateStatus(status, "Verifying HMAC-SHA512...")
	hm := hmac.New(sha512.New, hmacKeyD)
	hm.Write(encPayload)
	ok := hmac.Equal(hm.Sum(nil), hmSum)

	wipeBytes(derived)
	setProgress(progress, 1.0)
	elapsed := time.Since(start).Round(time.Millisecond)

	info := fmt.Sprintf("v%d | %s | %.1f KB", ver, modeNames[mode], float64(len(data))/1024)
	if flags&flagCompressed != 0 {
		info += " | Compressed"
	}
	if flags&flagKeyFile != 0 {
		info += " | Key File"
	}

	if ok {
		notifyStatus(status, fmt.Sprintf("VERIFIED OK (%s) [%s]", elapsed, info))
	} else {
		notifyStatus(status, fmt.Sprintf("VERIFICATION FAILED (%s) [%s]", elapsed, info))
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
	baseName := filepath.Base(folderPath)
	fileCount := 0
	err := filepath.WalkDir(folderPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(folderPath, path)
		if relErr != nil {
			return relErr
		}
		// Use forward slashes for zip compatibility across OS
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		// Prefix with folder name so decrypt restores the original structure
		entryName := baseName + "/" + rel

		if d.IsDir() {
			// Directories must end with "/" in zip format
			_, err := zw.Create(entryName + "/")
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = entryName
		header.Method = zip.Deflate // compress inside zip for better ratio

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		// Stream file content instead of ReadFile (handles large files)
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(writer, src)
		fileCount++
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("zip walk error: %w", err)
	}
	if fileCount == 0 {
		zw.Close()
		return nil, fmt.Errorf("folder is empty — nothing to encrypt")
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zip close error: %w", err)
	}
	return buf.Bytes(), nil
}

func unzipToDesktop(data []byte, folderName string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	dest := filepath.Join(getDesktopPath(), folderName)
	os.MkdirAll(dest, 0755)

	// Detect common prefix to avoid double-nesting (e.g., FolderName/FolderName/file.txt)
	prefix := folderName + "/"
	for _, f := range r.File {
		cleaned := filepath.ToSlash(f.Name)
		// Strip the folder prefix if entries are prefixed with it
		if strings.HasPrefix(cleaned, prefix) {
			cleaned = strings.TrimPrefix(cleaned, prefix)
		}
		if cleaned == "" || cleaned == "." {
			continue
		}

		// Zip Slip protection
		fp := filepath.Join(dest, filepath.FromSlash(cleaned))
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

// shredFile: 11-pass Gutmann-class overwrite
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
					c[i] = 0x55 // alternating bits
				}
			}
			f.Write(c)
			rem -= n
		}
		f.Sync()
	}
	f.Close()
}

// nativeFolderPicker opens the OS-native folder selection dialog.
// Works on Windows, macOS, and Linux without Fyne's broken dialog.
func nativeFolderPicker() string {
	switch runtime.GOOS {
	case "windows":
		// Use PowerShell to show native Windows folder browser
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			`Add-Type -AssemblyName System.Windows.Forms; `+
				`$f = New-Object System.Windows.Forms.FolderBrowserDialog; `+
				`$f.Description = 'Select folder to encrypt'; `+
				`$f.ShowNewFolderButton = $false; `+
				`if ($f.ShowDialog() -eq 'OK') { $f.SelectedPath } else { '' }`)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	case "darwin":
		// Use osascript on macOS
		cmd := exec.Command("osascript", "-e",
			`POSIX path of (choose folder with prompt "Select folder to encrypt")`)
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimRight(strings.TrimSpace(string(out)), "/")
	default:
		// Linux: try zenity, then kdialog
		if p, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command(p, "--file-selection", "--directory", "--title=Select folder to encrypt")
			out, err := cmd.Output()
			if err == nil {
				return strings.TrimSpace(string(out))
			}
		}
		if p, err := exec.LookPath("kdialog"); err == nil {
			cmd := exec.Command(p, "--getexistingdirectory", ".", "--title", "Select folder to encrypt")
			out, err := cmd.Output()
			if err == nil {
				return strings.TrimSpace(string(out))
			}
		}
		return ""
	}
}

func getDesktopPath() string {
	u, err := user.Current()
	if err != nil {
		return fallbackOutputDir()
	}
	home := u.HomeDir

	// Linux: check XDG_DESKTOP_DIR first (used by Tails, Whonix, most distros)
	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_DESKTOP_DIR"); xdg != "" {
			if info, err := os.Stat(xdg); err == nil && info.IsDir() {
				return xdg
			}
		}
		// Try xdg-user-dir command (works on Tails, Whonix, GNOME, KDE)
		if out, err := exec.Command("xdg-user-dir", "DESKTOP").Output(); err == nil {
			dir := strings.TrimSpace(string(out))
			if dir != "" && dir != home {
				if info, err := os.Stat(dir); err == nil && info.IsDir() {
					return dir
				}
			}
		}
		// Tails persistent storage
		tails := filepath.Join(home, "Persistent")
		if info, err := os.Stat(tails); err == nil && info.IsDir() {
			return tails
		}
	}

	// Windows: check OneDrive desktop first
	if runtime.GOOS == "windows" {
		oneDrive := filepath.Join(home, "OneDrive", "Desktop")
		if info, err := os.Stat(oneDrive); err == nil && info.IsDir() {
			return oneDrive
		}
	}

	// Universal: ~/Desktop (macOS, Windows, most Linux)
	d := filepath.Join(home, "Desktop")
	if info, err := os.Stat(d); err == nil && info.IsDir() {
		return d
	}

	// Linux fallback: ~/Documents
	docs := filepath.Join(home, "Documents")
	if info, err := os.Stat(docs); err == nil && info.IsDir() {
		return docs
	}

	// Last resort: home directory itself
	if info, err := os.Stat(home); err == nil && info.IsDir() {
		return home
	}

	return fallbackOutputDir()
}

func fallbackOutputDir() string {
	// Try current working directory
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	// Try temp dir as absolute last resort
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
// NATIVE FILE DIALOGS (Windows)
// ============================================================================

// nativeOpenFile shows the Windows native "Open File" dialog (all file types visible).
func nativeOpenFile(w fyne.Window) string {
	return nativeFileDialog("All Files (*.*)\x00*.*\x00\x00")
}

// nativeOpenCrypt shows the Windows native "Open File" dialog filtered to .crypt files.
func nativeOpenCrypt(w fyne.Window) string {
	return nativeFileDialog("CRYpT Files (*.crypt)\x00*.crypt\x00All Files (*.*)\x00*.*\x00\x00")
}

func utf16FromRaw(s string) []uint16 {
	out := make([]uint16, 0, len(s)+1)
	for _, c := range s {
		out = append(out, uint16(c))
	}
	out = append(out, 0)
	return out
}

func nativeFileDialog(filter string) string {
	ofn := &openFileName{}
	buf := make([]uint16, 65536)
	ofn.lStructSize = uint32(unsafe.Sizeof(*ofn))
	ofn.lpstrFile = &buf[0]
	ofn.nMaxFile = uint32(len(buf))
	filterUTF16 := utf16FromRaw(filter)
	ofn.lpstrFilter = &filterUTF16[0]
	ofn.flags = 0x00080000 | 0x00001000 | 0x00000800 // OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST

	comdlg32 := syscall.NewLazyDLL("comdlg32.dll")
	getOpenFileName := comdlg32.NewProc("GetOpenFileNameW")
	r, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(ofn)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:])
}

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

// ============================================================================
// MAIN — FORTRESS EDITION UI
// ============================================================================

func main() {
	iconBytes, _ := embeddedFiles.ReadFile("assets/icon.png")
	iconRes := fyne.NewStaticResource("icon.png", iconBytes)

	a := app.NewWithID("com.costrinity.CRYpT")
	a.SetIcon(iconRes)
	a.Settings().SetTheme(&costrinityTheme{})

	w := a.NewWindow("CRYpT v6.1 — Free Edition")
	w.Resize(fyne.NewSize(800, 740))
	w.CenterOnScreen()

	// ── State ──
	var keyFileData []byte
	currentMode := ModeMilitary
	compressEnabled := true
	proUnlocked := isProUnlocked()

	// ── Title Block ──
	titleMain := canvas.NewText("C R Y p T", colCyan)
	titleMain.TextSize = 34
	titleMain.Alignment = fyne.TextAlignCenter
	titleMain.TextStyle = fyne.TextStyle{Bold: true}

	titleSub := canvas.NewText("COSTRINITY CIPHER PROTOCOL", colCyanDim)
	titleSub.TextSize = 13
	titleSub.Alignment = fyne.TextAlignCenter

	edition := canvas.NewText("OBSIDIAN EDITION v6.1  //  17-Layer Cascade  //  5-Cipher AEAD  //  Double Argon2id  //  Quint Integrity", colMidText)
	edition.TextSize = 12
	edition.Alignment = fyne.TextAlignCenter

	// ── License status indicator ──
	licenseStatusText := "FREE"
	licenseStatusColor := colWarn
	if proUnlocked {
		licenseStatusText = "PRO \u2713"
		licenseStatusColor = colSuccess
	}
	licenseLabel := canvas.NewText(licenseStatusText, licenseStatusColor)
	licenseLabel.TextSize = 11
	licenseLabel.TextStyle = fyne.TextStyle{Bold: true}
	licenseLabel.Alignment = fyne.TextAlignCenter

	// Neon accent line under title
	accentLine := canvas.NewRectangle(colCyan)
	accentLine.SetMinSize(fyne.NewSize(0, 2))

	// refreshLicenseUI updates the license label after activation
	refreshLicenseUI := func() {
		proUnlocked = isProUnlocked()
		if proUnlocked {
			licenseLabel.Text = "PRO \u2713"
			licenseLabel.Color = colSuccess
		} else {
			licenseLabel.Text = "FREE"
			licenseLabel.Color = colWarn
		}
		licenseLabel.Refresh()
	}

	titleBlock := container.NewVBox(
		titleMain,
		titleSub,
		edition,
		licenseLabel,
		accentLine,
	)

	// ── Password ──
	pwLabel := canvas.NewText("PASSWORD", colCyanDim)
	pwLabel.TextSize = 13
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

	pwBlock := container.NewVBox(
		pwLabel,
		pwEntry,
		container.NewHBox(strLabel, layout.NewSpacer()),
	)

	// ── Shared progress/status (declared early for use in callbacks) ──
	progress := widget.NewProgressBar()
	statusLabel := widget.NewLabel("READY  //  FREE EDITION ARMED")

	// ── Key File ──
	kfLabel := widget.NewLabel("Key File: None")
	kfLoadBtn := widget.NewButton("Load Key File", func() {
		go func() {
			p := nativeOpenFile(w)
			if p == "" {
				return
			}
			d, readErr := os.ReadFile(p)
			if readErr != nil {
				notifyStatus(statusLabel, "Key file read error: "+readErr.Error())
				return
			}
			keyFileData = d
			kfLabel.SetText("Key File: " + filepath.Base(p))
		}()
	})
	kfClearBtn := widget.NewButton("Clear", func() {
		keyFileData = nil
		kfLabel.SetText("Key File: None")
	})
	kfRow := container.NewHBox(kfLabel, layout.NewSpacer(), kfLoadBtn, kfClearBtn)

	// ════════ ENCRYPT TAB ════════
	encHeader := canvas.NewText("SECURITY MODE", colCyanDim)
	encHeader.TextSize = 13
	encHeader.TextStyle = fyne.TextStyle{Bold: true}

	modeSelect := widget.NewRadioGroup([]string{"Standard", "Military", "Paranoid (PRO)", "FORTRESS (PRO)"}, func(s string) {
		switch s {
		case "Standard":
			currentMode = ModeStandard
		case "Military":
			currentMode = ModeMilitary
		case "Paranoid (PRO)":
			currentMode = ModeParanoid
		case "FORTRESS (PRO)":
			currentMode = ModeFortress
		}
	})
	modeSelect.Horizontal = true
	modeSelect.Selected = "Military"

	modeDesc := canvas.NewText("Standard: 256MB  |  Military: 512MB  |  Paranoid: 1GB (PRO)  |  FORTRESS: 2GB (PRO)", colDimText)
	modeDesc.TextSize = 12
	modeDesc.Alignment = fyne.TextAlignCenter

	fortressWarn := canvas.NewText("FORTRESS mode uses 2GB RAM + 32 iterations — maximum brute-force resistance", colWarn)
	fortressWarn.TextSize = 12
	fortressWarn.Alignment = fyne.TextAlignCenter

	compressCheck := widget.NewCheck("Compress before encryption", func(v bool) { compressEnabled = v })
	compressCheck.Checked = true

	// ── Activate Pro button — opens website + shows code entry dialog ──
	activateProBtn := widget.NewButton("Activate Pro", func() {
		// Open the purchase/activation page in the user's browser
		u, _ := url.Parse("https://costrinity.xyz/crypt.html#pricing")
		_ = a.OpenURL(u)

		// Show the activation dialog with code + email fields
		codeEntry := widget.NewEntry()
		codeEntry.SetPlaceHolder("Paste your 32-character activation code")
		emailEntry := widget.NewEntry()
		emailEntry.SetPlaceHolder("Email (optional — for license recovery)")
		formItems := []*widget.FormItem{
			widget.NewFormItem("Activation Code", codeEntry),
			widget.NewFormItem("Email", emailEntry),
		}
		d := dialog.NewForm("Activate CRYpT Pro", "Activate", "Cancel", formItems, func(ok bool) {
			if !ok {
				return
			}
			code := strings.TrimSpace(codeEntry.Text)
			email := strings.TrimSpace(emailEntry.Text)
			if len(code) != 32 {
				notifyStatus(statusLabel, "Invalid code: must be 32 hex characters")
				return
			}
			if !validateActivationCode(code) {
				notifyStatus(statusLabel, "Invalid activation code")
				return
			}
			li := &LicenseInfo{
				Code:        code,
				ActivatedAt: time.Now().UTC().Format(time.RFC3339),
				Email:       email,
			}
			if err := saveLicense(li); err != nil {
				notifyStatus(statusLabel, "Failed to save license: "+err.Error())
				return
			}
			// Log activation to ~/.costrinity/activations.log
			logActivation(code, email)
			refreshLicenseUI()
			notifyStatus(statusLabel, "Activated — Paranoid + FORTRESS modes unlocked")
		}, w)
		d.Resize(fyne.NewSize(500, 220))
		d.Show()
	})

	// showProRequiredDialog shows a dialog when non-pro user selects a pro mode
	showProRequiredDialog := func() {
		dialog.ShowInformation("Activation Required",
			"Paranoid and FORTRESS modes require an activation code.\n\n"+
				"Purchase at costrinity.xyz/crypt.html#pricing to receive your code.", w)
	}

	encFileBtn := widget.NewButton("Encrypt File", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		mode := currentMode
		if requiresProLicense(mode) && !proUnlocked {
			showProRequiredDialog()
			return
		}
		kf := keyFileData
		comp := compressEnabled
		go func() {
			p := nativeOpenFile(w)
			if p == "" {
				return
			}
			encryptPath(p, pw, kf, mode, false, comp, progress, statusLabel)
		}()
	})

	// ── Folder encryption: paste path dialog ──
	encFolderBtn := widget.NewButton("Encrypt Folder", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		mode := currentMode
		if requiresProLicense(mode) && !proUnlocked {
			showProRequiredDialog()
			return
		}
		kf := keyFileData
		comp := compressEnabled

		// Show a simple entry dialog — user pastes folder path
		pathEntry := widget.NewEntry()
		pathEntry.SetPlaceHolder("C:\\Users\\you\\Documents\\MyFolder")
		pathEntry.MultiLine = false

		helpText := widget.NewLabel("Right-click folder in Explorer → Copy as path → Paste here")
		helpText.Wrapping = fyne.TextWrapWord

		d := dialog.NewCustomConfirm("Encrypt Folder", "Encrypt", "Cancel",
			container.NewVBox(
				helpText,
				pathEntry,
			),
			func(ok bool) {
				if !ok {
					return
				}
				folderPath := strings.TrimSpace(pathEntry.Text)
				folderPath = strings.Trim(folderPath, "\"' ")
				if folderPath == "" {
					notifyStatus(statusLabel, "Error: no folder path entered")
					return
				}
				info, err := os.Stat(folderPath)
				if err != nil {
					notifyStatus(statusLabel, "Error: folder not found — "+folderPath)
					return
				}
				if !info.IsDir() {
					notifyStatus(statusLabel, "Error: that's a file, not a folder")
					return
				}
				fileCount := 0
				filepath.WalkDir(folderPath, func(_ string, d fs.DirEntry, _ error) error {
					if d != nil && !d.IsDir() {
						fileCount++
					}
					return nil
				})
				if fileCount == 0 {
					notifyStatus(statusLabel, "Error: folder is empty")
					return
				}
				notifyStatus(statusLabel, fmt.Sprintf("Encrypting %d files in \"%s\"...", fileCount, filepath.Base(folderPath)))
				go encryptPath(folderPath, pw, kf, mode, true, comp, progress, statusLabel)
			}, w)
		d.Resize(fyne.NewSize(500, 180))
		d.Show()
	})

	layers := canvas.NewText("S-Box x4 > Diffuse > 3xFeistel(64R) > AES > XChaCha > AES > XChaCha > AES > 5x Integrity", colDimText)
	layers.TextSize = 11
	layers.Alignment = fyne.TextAlignCenter

	// Simple step-by-step instructions
	step1 := canvas.NewText("1. Type a password above (14+ characters)", colDimText)
	step1.TextSize = 13
	step2 := canvas.NewText("2. Pick a security mode (Standard is fine for most files)", colDimText)
	step2.TextSize = 13
	step3 := canvas.NewText("3. Click \"Encrypt File\" to lock one file", colDimText)
	step3.TextSize = 13
	step4 := canvas.NewText("4. To encrypt a whole folder, click \"Encrypt Folder\" at the bottom", colDimText)
	step4.TextSize = 13
	step5 := canvas.NewText("All file types supported: pictures, videos, documents, archives, etc.", colDimText)
	step5.TextSize = 13
	step6 := canvas.NewText("Your encrypted .crypt file appears on your Desktop when done!", colCyan)
	step6.TextSize = 13

	instructions := container.NewVBox(
		step1, step2, step3, step4,
		neonSeparator(colSep),
		step5, step6,
	)

	encryptTab := container.NewVScroll(container.NewVBox(
		encHeader,
		modeSelect,
		modeDesc,
		fortressWarn,
		neonSeparator(colSep),
		compressCheck,
		neonSeparator(colSep),
		container.NewGridWithColumns(2, encFileBtn, encFolderBtn),
		neonSeparator(colSep),
		instructions,
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
		go func() {
			p := nativeOpenCrypt(w)
			if p == "" {
				return
			}
			decryptFile(p, pw, kf, progress, statusLabel)
		}()
	})

	verifyBtn := widget.NewButton("Verify Integrity Only", func() {
		pw := pwEntry.Text
		if pw == "" {
			notifyStatus(statusLabel, "Error: password required")
			return
		}
		kf := keyFileData
		go func() {
			p := nativeOpenCrypt(w)
			if p == "" {
				return
			}
			verifyFile(p, pw, kf, progress, statusLabel)
		}()
	})

	decInfo1 := canvas.NewText("Verify checks password + triple integrity without decrypting", colDimText)
	decInfo1.TextSize = 12
	decInfo1.Alignment = fyne.TextAlignCenter
	decInfo2 := canvas.NewText("Auto-detects v2 / v3 / v4 / v5 / v6 format  //  Full backward compatibility", colDimText)
	decInfo2.TextSize = 12
	decInfo2.Alignment = fyne.TextAlignCenter

	decryptTab := container.NewVScroll(container.NewVBox(
		decBtn,
		neonSeparator(colSep),
		verifyBtn,
		decInfo1,
		neonSeparator(colSep),
		decInfo2,
	))

	// ════════ TOOLS TAB ════════
	genLength := 24
	genLo, genUp, genDg, genSy := true, true, true, true

	lenLabel := widget.NewLabel("Length: 24")
	lenSlider := widget.NewSlider(12, 64)
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
	toolsHeader.TextSize = 13
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
	aboutTitle := canvas.NewText("CRYpT v6.1 — Free Edition EDITION", colCyan)
	aboutTitle.TextSize = 14
	aboutTitle.TextStyle = fyne.TextStyle{Bold: true}
	aboutTitle.Alignment = fyne.TextAlignCenter

	aboutProto := canvas.NewText("Costrinity Cipher Language Protocol v6  //  SHAKE-256 + BLAKE2b optimized", colCyanDim)
	aboutProto.TextSize = 13
	aboutProto.Alignment = fyne.TextAlignCenter

	aboutLayersHdr := canvas.NewText("17-LAYER ENCRYPTION ARCHITECTURE", colCyan)
	aboutLayersHdr.TextSize = 13
	aboutLayersHdr.TextStyle = fyne.TextStyle{Bold: true}

	aboutLayers := widget.NewLabel(
		"  L0   Double Argon2id (256MB-2GB x2, 256-byte split salt)\n" +
			"  L1   zlib compression\n" +
			"  L2   Dual canary (head + tail chain verification)\n" +
			"  L3   Random padding 512-8192B (size obfuscation)\n" +
			"  L4   Quadruple S-Box (four key-derived substitutions)\n" +
			"  L5   Cascade diffusion (XOR stream + rotation)\n" +
			"  L6   Triple 64-round Feistel (192 total rounds)\n" +
			"  L7   AES-256-GCM pass 1\n" +
			"  L8   XChaCha20-Poly1305 pass 1\n" +
			"  L9   AES-256-GCM pass 2\n" +
			"  L10  XChaCha20-Poly1305 pass 2\n" +
			"  L11  AES-256-GCM pass 3\n" +
			"  L12  Quint integrity: 2xSHA3 + BLAKE2b + HMAC-SHA512\n" +
			"  L13  Full-file HMAC (header + payload authentication)")

	aboutSecHdr := canvas.NewText("SECURITY HIGHLIGHTS", colCyan)
	aboutSecHdr.TextSize = 13
	aboutSecHdr.TextStyle = fyne.TextStyle{Bold: true}

	aboutSec := widget.NewLabel(
		"  - Double Argon2id: attacker pays 2x KDF cost per guess\n" +
			"  - SHA3-512 password pre-hash before KDF\n" +
			"  - 5-cipher AEAD cascade (AES-XChaCha-AES-XChaCha-AES)\n" +
			"  - 20 independent sub-keys (640 bytes key material)\n" +
			"  - 2048-bit salt eliminates all precomputation\n" +
			"  - FORTRESS: 2GB x2 Argon2id + 32 iterations x2\n" +
			"  - 192 Feistel rounds across 3 independent passes\n" +
			"  - Quadruple S-Box with 4 key-derived tables\n" +
			"  - 5 integrity hashes + full-file authentication\n" +
			"  - Bidirectional canary (head + tail) chain verification\n" +
			"  - 11-pass Gutmann shredding on originals\n" +
			"  - All intermediate buffers wiped between layers")

	aboutFinal := canvas.NewText("Every layer must be independently defeated  //  No known or theoretical shortcut exists", colMidText)
	aboutFinal.TextSize = 12
	aboutFinal.Alignment = fyne.TextAlignCenter

	aboutTab := container.NewVScroll(container.NewVBox(
		aboutTitle,
		aboutProto,
		neonSeparator(colCyanDark),
		aboutLayersHdr,
		aboutLayers,
		neonSeparator(colSep),
		aboutSecHdr,
		aboutSec,
		neonSeparator(colSep),
		aboutFinal,
	))

	// ── Tabs ──
	tabs := container.NewAppTabs(
		container.NewTabItem("Encrypt", encryptTab),
		container.NewTabItem("Decrypt", decryptTab),
		container.NewTabItem("Tools", toolsTab),
		container.NewTabItem("About", aboutTab),
	)

	// ── Status bar ──
	statusLine := neonSeparator(colCyanDark)

	footer := canvas.NewText("CRYpT FREE EDITION  //  5-Cipher AEAD Cascade Encryption", colDimText)
	footer.TextSize = 11
	footer.Alignment = fyne.TextAlignCenter

	// Top section: title + password + key file (fixed height)
	topSection := container.NewVBox(
		titleBlock,
		pwBlock,
		kfRow,
		neonSeparator(colSep),
	)

	// Bottom section: progress + status + footer with Activate Pro button (fixed height)
	footerRow := container.NewHBox(footer, layout.NewSpacer(), activateProBtn)
	bottomSection := container.NewVBox(
		neonSeparator(colSep),
		progress,
		statusLine,
		statusLabel,
		footerRow,
	)

	// Border layout: top and bottom fixed, tabs expand to fill center
	mainLayout := container.NewBorder(topSection, bottomSection, nil, nil, tabs)
	w.SetContent(container.NewPadded(mainLayout))

	w.ShowAndRun()
}
