package aesgcm

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

/*
=====================================================
 CONSTANT
=====================================================
*/

// Ukuran blok AES (128 bit)
const (
	BlockSize = 16

	// Ukuran nonce standar GCM (96 bit)
	NonceSize = 12

	// Ukuran authentication tag (128 bit)
	TagSize = 16
)

/*
=====================================================
 STRUCT
=====================================================
*/

// AESGCM merepresentasikan implementasi manual AES-256-GCM
// yang terdiri dari:
// - AES block cipher
// - Subkey H untuk proses GHASH
type AESGCM struct {
	block cipherBlock // AES block cipher
	H0    uint64      // Bagian bawah subkey H
	H1    uint64      // Bagian atas subkey H
}

// Abstraksi block cipher agar tidak bergantung langsung
// pada implementasi AES bawaan
type cipherBlock interface {
	Encrypt(dst, src []byte)
}

/*
=====================================================
 INIT
=====================================================
*/

// NewAESGCM menginisialisasi AES-256-GCM secara manual
//
// Langkah:
//  1. Validasi panjang key (harus 256-bit / 32 byte)
//  2. Inisialisasi AES block cipher
//  3. Hitung subkey H = AES(K, 0^128)
//     → Digunakan untuk autentikasi GHASH
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 requires 32-byte key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// H = E(K, 0^128)
	var zero [16]byte
	var h [16]byte
	block.Encrypt(h[:], zero[:])

	return &AESGCM{
		block: block,
		H1:    binary.BigEndian.Uint64(h[:8]),
		H0:    binary.BigEndian.Uint64(h[8:]),
	}, nil
}

/*
=====================================================
 HELPER
=====================================================
*/

// incCounter menaikkan counter untuk mode CTR
// Counter hanya dinaikkan pada 32-bit terakhir
// (sesuai standar GCM)
func incCounter(counter []byte) {
	for i := len(counter) - 1; i >= 12; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

// equalTag membandingkan authentication tag
// menggunakan constant-time comparison
// untuk mencegah timing attack
func equalTag(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

/*
=====================================================
 GHASH (Galois Field Multiplication)
=====================================================
*/

// mul melakukan perkalian pada medan hingga GF(2¹²⁸)
// sesuai spesifikasi GCM
//
// Operasi ini digunakan oleh GHASH untuk
// menghitung authentication value
func (g *AESGCM) mul(x0, x1 uint64) (z0, z1 uint64) {
	v0, v1 := g.H0, g.H1

	for i := 0; i < 64; i++ {
		if (x1>>(63-i))&1 == 1 {
			z0 ^= v0
			z1 ^= v1
		}

		lsb := v0 & 1
		v0 >>= 1
		if v1&1 == 1 {
			v0 |= 0x8000000000000000
		}
		v1 >>= 1
		if lsb == 1 {
			v1 ^= 0xe100000000000000
		}
	}

	return
}

// ghashWithLen menghitung GHASH untuk ciphertext
// dengan menambahkan panjang ciphertext (dalam bit)
// pada blok terakhir (sesuai NIST SP 800-38D)
func (g *AESGCM) ghashWithLen(ciphertext []byte) []byte {
	data := make([]byte, 0)

	// Masukkan ciphertext
	data = append(data, ciphertext...)

	// Padding agar kelipatan 128-bit
	if rem := len(data) % 16; rem != 0 {
		data = append(data, make([]byte, 16-rem)...)
	}

	// Tambahkan panjang ciphertext dalam bit
	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
	data = append(data, lenBlock...)

	return g.ghash(data)
}

// ghash menghitung authentication hash
// dengan operasi XOR dan perkalian GF(2¹²⁸)
func (g *AESGCM) ghash(data []byte) []byte {
	var x0, x1 uint64

	for i := 0; i < len(data); i += 16 {
		var b0, b1 uint64
		if i+16 <= len(data) {
			b1 = binary.BigEndian.Uint64(data[i:])
			b0 = binary.BigEndian.Uint64(data[i+8:])
		}
		x0 ^= b0
		x1 ^= b1
		x0, x1 = g.mul(x0, x1)
	}

	tag := make([]byte, 16)
	binary.BigEndian.PutUint64(tag[:8], x1)
	binary.BigEndian.PutUint64(tag[8:], x0)
	return tag
}

/*
=====================================================
 ENCRYPT
=====================================================
*/

// Encrypt melakukan enkripsi AES-256-GCM manual
//
// Proses:
// 1. Enkripsi plaintext menggunakan AES-CTR
// 2. Hitung GHASH(ciphertext + length)
// 3. Hitung authentication tag
func (g *AESGCM) Encrypt(plaintext, nonce []byte) (ciphertext, tag []byte, err error) {
	if len(nonce) != NonceSize {
		return nil, nil, errors.New("invalid nonce size")
	}

	// Counter awal: nonce || 0x00000001
	counter := make([]byte, 16)
	copy(counter, nonce)
	counter[15] = 1

	ciphertext = make([]byte, len(plaintext))
	stream := make([]byte, 16)

	// AES-CTR Encryption
	for i := 0; i < len(plaintext); i += 16 {
		g.block.Encrypt(stream, counter)
		incCounter(counter)

		for j := 0; j < 16 && i+j < len(plaintext); j++ {
			ciphertext[i+j] = plaintext[i+j] ^ stream[j]
		}
	}

	// Authentication Tag
	j0 := make([]byte, 16)
	copy(j0, nonce)
	j0[15] = 1

	s := g.ghashWithLen(ciphertext)

	ekj0 := make([]byte, 16)
	g.block.Encrypt(ekj0, j0)

	tag = make([]byte, 16)
	for i := 0; i < 16; i++ {
		tag[i] = ekj0[i] ^ s[i]
	}
	return
}

/*
=====================================================
 DECRYPT
=====================================================
*/

// Decrypt melakukan:
// 1. Verifikasi authentication tag
// 2. Dekripsi AES-CTR jika tag valid
func (g *AESGCM) Decrypt(ciphertext, nonce, tag []byte) ([]byte, error) {

	if len(nonce) != NonceSize {
		return nil, errors.New("invalid nonce size")
	}

	// Rekonstruksi J0
	j0 := make([]byte, 16)
	copy(j0, nonce)
	j0[15] = 1

	// Hitung ulang tag
	s := g.ghashWithLen(ciphertext)

	ekj0 := make([]byte, 16)
	g.block.Encrypt(ekj0, j0)

	expectedTag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		expectedTag[i] = ekj0[i] ^ s[i]
	}

	// Verifikasi autentikasi
	if !equalTag(tag, expectedTag) {
		return nil, errors.New("authentication failed (tag mismatch)")
	}

	// AES-CTR Decryption
	counter := make([]byte, 16)
	copy(counter, nonce)
	counter[15] = 1

	plaintext := make([]byte, len(ciphertext))
	stream := make([]byte, 16)

	for i := 0; i < len(ciphertext); i += 16 {
		g.block.Encrypt(stream, counter)
		incCounter(counter)

		for j := 0; j < 16 && i+j < len(ciphertext); j++ {
			plaintext[i+j] = ciphertext[i+j] ^ stream[j]
		}
	}

	return plaintext, nil
}
