package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"backup-worker/aesgcm"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

/* ======================================================
   CONFIG
====================================================== */

type Config struct {
	Listen         string `json:"listen"`
	MinioEndpoint  string `json:"minio_endpoint"`
	MinioUseSSL    bool   `json:"minio_use_ssl"`
	MinioAccessKey string `json:"minio_access_key"`
	MinioSecretKey string `json:"minio_secret_key"`
	Bucket         string `json:"bucket"`
	AESKeyB64      string `json:"aes_key_b64"`
	CallbackURL    string `json:"callback_url"`
	MaxUploadBytes int64  `json:"max_upload_bytes"`
}

type CallbackPayload struct {
	Event        string `json:"event"`
	BackupID     int64  `json:"backup_id"`
	Filename     string `json:"filename,omitempty"`
	MinioPath    string `json:"minio_path,omitempty"`
	OriginalSize int64  `json:"original_size,omitempty"`
	FinalSize    int64  `json:"final_size,omitempty"`
	DurationMs   int64  `json:"duration_ms,omitempty"`
	HashAfter    string `json:"hash_after,omitempty"`
	// waktu (ms)
	DurationTotalMs      int64  `json:"duration_total_ms,omitempty"`
	DurationCompressMs   int64  `json:"duration_compress_ms,omitempty"`
	DurationEncryptMs    int64  `json:"duration_encrypt_ms,omitempty"`
	DurationDecryptMs    int64  `json:"duration_decrypt_ms,omitempty"`
	DurationDecompressMs int64  `json:"duration_decompress_ms,omitempty"`
	ErrorMessage         string `json:"error_message,omitempty"`
}

var (
	cfg         Config
	minioClient *minio.Client
	aesKey      []byte
)

const (
	BLOCK_SIZE   = 4 << 20          // 4MB
	LOG_INTERVAL = int64(100 << 20) // 100MB
)

var (
	compressStart time.Time
	encryptStart  time.Time
	compressDur   int64
	encryptDur    int64
)

/* ======================================================
   INIT
====================================================== */

func loadConfig() {
	f, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		log.Fatal(err)
	}

	key, err := base64.StdEncoding.DecodeString(cfg.AESKeyB64)
	if err != nil || len(key) != 32 {
		log.Fatal("AES-256 key must be 32 bytes")
	}
	aesKey = key
}

func initMinio() {
	var err error
	minioClient, err = minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: cfg.MinioUseSSL,
	})
	if err != nil {
		log.Fatal(err)
	}
}

/* ======================================================
   HELPERS
====================================================== */

func writeUint64(w io.Writer, v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// Limitasi FIle
func applyDefaults() {
	if cfg.MaxUploadBytes <= 0 {
		cfg.MaxUploadBytes = 10 << 20 // 10MB default
	}
}

func readUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := io.ReadFull(r, b[:])
	return binary.BigEndian.Uint64(b[:]), err
}

func sendCallback(p CallbackPayload) {
	if cfg.CallbackURL == "" {
		return
	}
	data, _ := json.Marshal(p)
	http.Post(cfg.CallbackURL, "application/json", bytes.NewBuffer(data))
}

func generateUniqueObjectName(
	ctx context.Context,
	bucket string,
	base string,
) (string, error) {

	object := base
	i := 1

	for {
		_, err := minioClient.StatObject(ctx, bucket, object, minio.StatObjectOptions{})
		if err != nil {
			resp := minio.ToErrorResponse(err)
			if resp.Code == "NoSuchKey" || resp.Code == "NotFound" {
				return object, nil
			}
			return "", err
		}

		// contoh: backups/file.sql.enc -> backups/file.sql-1.enc
		name := strings.TrimSuffix(base, ".enc")
		object = fmt.Sprintf("%s-%d.enc", name, i)
		i++
	}
}

/* ======================================================
   UPLOAD HANDLER
====================================================== */

func UploadHandler(w http.ResponseWriter, r *http.Request) {

	// ============================
	// LIMIT UPLOAD SIZE
	// ============================
	// Batasi ukuran request body supaya tidak bisa upload file > cfg.MaxUploadBytes
	// Contoh: cfg.MaxUploadBytes = 10 * 1024 * 1024 (10MB)
	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxUploadBytes)

	// ⏱️ Mulai hitung durasi total upload
	start := time.Now()

	// ============================
	// VALIDASI PARAMETER
	// ============================
	filename := r.URL.Query().Get("filename")
	backupIDStr := r.URL.Query().Get("backup_id")
	if filename == "" || backupIDStr == "" {
		http.Error(w, "filename & backup_id required", 400)
		return
	}

	backupID, _ := strconv.ParseInt(backupIDStr, 10, 64)

	// ============================
	// helper callback fail (ONLY ONCE)
	// ============================
	var failOnce sync.Once

	sendUploadFailed := func(msg string) {
		failOnce.Do(func() {
			log.Printf("[UPLOAD] FAILED backup_id=%d filename=%s msg=%s", backupID, filename, msg)

			sendCallback(CallbackPayload{
				Event:        "upload_failed",
				BackupID:     backupID,
				Filename:     filename,
				ErrorMessage: msg,
			})
		})
	}

	// ============================
	// GENERATE OBJECT NAME (ANTI OVERWRITE)
	// ============================
	objectBase := fmt.Sprintf("backups/%s.enc", filename)
	objectName, err := generateUniqueObjectName(
		context.Background(),
		cfg.Bucket,
		objectBase,
	)
	if err != nil {
		sendUploadFailed("failed generate object name: " + err.Error())
		http.Error(w, "failed generate object name", 500)
		return
	}

	// ============================
	// ORIGINAL SIZE CHECK (BEST EFFORT)
	// ============================
	// ContentLength kadang -1 (unknown), jadi check ini hanya jika > 0
	originalSize := r.ContentLength
	if originalSize > 0 && originalSize > cfg.MaxUploadBytes {
		msg := fmt.Sprintf("file too large (max %d bytes)", cfg.MaxUploadBytes)
		sendUploadFailed(msg)

		http.Error(w, msg, http.StatusRequestEntityTooLarge)
		return
	}

	log.Printf("[UPLOAD] start filename=%s backup_id=%d size=%d max=%d",
		filename, backupID, originalSize, cfg.MaxUploadBytes)

	// ============================
	// DETEKSI MODE UPLOAD
	// ============================
	fileReader := r.Body

	// jika multipart upload (form-data)
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			sendUploadFailed("multipart reader failed: " + err.Error())
			http.Error(w, "multipart reader failed", 500)
			return
		}

		found := false
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			if part.FormName() == "file" {
				fileReader = part
				found = true
				break
			}
		}

		if !found {
			sendUploadFailed("missing multipart field: file")
			http.Error(w, "missing file part", 400)
			return
		}

		log.Printf("[UPLOAD] multipart mode enabled")
	}

	// ============================
	// TIMER VARS
	// ============================
	var compressStart time.Time
	var encryptStart time.Time

	var compressDuration int64
	var encryptDuration int64

	// ============================
	// PIPE UNTUK STREAM KE MINIO
	// pr -> dibaca PutObject
	// pw <- ditulis pipeline
	// ============================
	pr, pw := io.Pipe()

	// =====================================================
	// ✅ NEW: CHANNEL CONTROL (ANTI STUCK)
	// =====================================================
	// pipeErr: pipeline error (misal upload too large) -> handler bisa stop PutObject dan return 413
	pipeErr := make(chan error, 1)

	// putDone: sinyal PutObject selesai
	putDone := make(chan struct{})
	var (
		info   minio.UploadInfo
		putErr error
	)

	// ============================
	// PIPELINE GOROUTINE
	// ============================
	go func() {
		defer pw.Close()

		// ============================
		// INIT AES-256-GCM MANUAL
		// ============================
		gcm, err := aesgcm.NewAESGCM(aesKey)
		if err != nil {
			sendUploadFailed("aesgcm init failed: " + err.Error())
			pw.CloseWithError(err)

			// notify handler
			select {
			case pipeErr <- err:
			default:
			}

			return
		}

		// ============================
		// PIPE: COMPRESS → ENCRYPT
		// compPw: output compressor
		// compPr: input encryptor
		// ============================
		compPr, compPw := io.Pipe()

		// Deflate compression supporting
		flateWriter, err := flate.NewWriter(compPw, flate.DefaultCompression)
		if err != nil {
			sendUploadFailed("flate.NewWriter failed: " + err.Error())
			pw.CloseWithError(err)

			// notify handler
			select {
			case pipeErr <- err:
			default:
			}

			return
		}

		var wg sync.WaitGroup
		wg.Add(1)

		var encBytes int64
		var readBytes int64

		// =====================================================
		// ENCRYPTOR
		// compPr → AES-GCM → pw
		// =====================================================
		go func() {
			defer wg.Done()
			defer compPr.Close()

			// Start encrypt timer (ketika encryptor mulai bekerja)
			encryptStart = time.Now()

			buf := make([]byte, BLOCK_SIZE)

			for {
				n, err := compPr.Read(buf)

				if n > 0 {
					encBytes += int64(n)

					// Progress log
					if encBytes%LOG_INTERVAL < int64(n) {
						log.Printf("[ENCRYPT] %s encrypted %.2f MB",
							filename, float64(encBytes)/1024/1024)
					}

					// Nonce unik per block
					nonce := make([]byte, aesgcm.NonceSize)
					if _, errRand := rand.Read(nonce); errRand != nil {
						sendUploadFailed("nonce rand failed: " + errRand.Error())
						pw.CloseWithError(errRand)

						// notify handler
						select {
						case pipeErr <- errRand:
						default:
						}

						return
					}

					// Encrypt manual AES-GCM
					ciphertext, tag, errEnc := gcm.Encrypt(buf[:n], nonce)
					if errEnc != nil {
						sendUploadFailed("encrypt failed: " + errEnc.Error())
						pw.CloseWithError(errEnc)

						// notify handler
						select {
						case pipeErr <- errEnc:
						default:
						}

						return
					}

					// Format:
					// [NONCE (12B)] [CIPHER_LEN (8B)] [CIPHERTEXT (N)] [TAG (16B)]
					if _, err := pw.Write(nonce); err != nil {
						sendUploadFailed("pipe write nonce failed: " + err.Error())

						select {
						case pipeErr <- err:
						default:
						}

						return
					}
					if err := writeUint64(pw, uint64(len(ciphertext))); err != nil {
						sendUploadFailed("pipe write cipher len failed: " + err.Error())

						select {
						case pipeErr <- err:
						default:
						}

						return
					}
					if _, err := pw.Write(ciphertext); err != nil {
						sendUploadFailed("pipe write ciphertext failed: " + err.Error())

						select {
						case pipeErr <- err:
						default:
						}

						return
					}
					if _, err := pw.Write(tag); err != nil {
						sendUploadFailed("pipe write tag failed: " + err.Error())

						select {
						case pipeErr <- err:
						default:
						}

						return
					}
				}

				if err != nil {
					// EOF normal
					return
				}
			}
		}()

		// =====================================================
		// COMPRESSOR
		// fileReader → Deflate → compPw
		// =====================================================
		buf := make([]byte, BLOCK_SIZE)
		compressStart = time.Now()

		for {
			n, err := fileReader.Read(buf)

			if err != nil {
				// 🚨 request entity too large (MaxBytesReader)
				if strings.Contains(err.Error(), "http: request body too large") {
					msg := fmt.Sprintf("file too large (max=%d bytes)", cfg.MaxUploadBytes)
					sendUploadFailed(msg)

					// ✅ notify handler utama agar response langsung selesai
					select {
					case pipeErr <- errors.New(msg):
					default:
					}

					// stop pipeline
					pw.CloseWithError(err)
					_ = flateWriter.Close()
					_ = compPw.Close()
					return
				}

				// EOF normal / atau error lain
				_ = flateWriter.Close()
				_ = compPw.Close()
				compressDuration = time.Since(compressStart).Milliseconds()
				break
			}

			if n > 0 {
				readBytes += int64(n)

				// Progress log
				if readBytes%LOG_INTERVAL < int64(n) {
					log.Printf("[READ] %s read %.2f MB",
						filename, float64(readBytes)/1024/1024)
				}

				if _, errW := flateWriter.Write(buf[:n]); errW != nil {
					sendUploadFailed("compress write failed: " + errW.Error())

					select {
					case pipeErr <- errW:
					default:
					}

					pw.CloseWithError(errW)
					_ = flateWriter.Close()
					_ = compPw.Close()
					return
				}
			}
		}

		// tunggu encryptor selesai (EOF dari compressor sudah dikirim)
		wg.Wait()

		// stop encrypt timer
		if !encryptStart.IsZero() {
			encryptDuration = time.Since(encryptStart).Milliseconds()
			log.Printf("[UPLOAD] encryption finished in %d ms", encryptDuration)
		}

		log.Printf("[UPLOAD] pipeline finished filename=%s compress=%d ms encrypt=%d ms",
			filename, compressDuration, encryptDuration)
	}()

	// =====================================================
	// ✅ NEW: PutObject ASYNC (biar select bisa cancel stuck)
	// =====================================================
	go func() {
		info, putErr = minioClient.PutObject(
			context.Background(),
			cfg.Bucket,
			objectName,
			pr,
			-1,
			minio.PutObjectOptions{},
		)
		close(putDone)
	}()

	// =====================================================
	// ✅ NEW: SELECT RESULT (PIPELINE FAIL vs PUTOBJECT DONE)
	// =====================================================
	select {
	case err := <-pipeErr:
		// pipeline fail -> stop PutObject read
		_ = pr.CloseWithError(err)

		// Return 413 supaya UI Laravel stop loading
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "failed",
			"error":  err.Error(),
		})
		return

	case <-putDone:
		// PutObject selesai
		if putErr != nil {
			sendUploadFailed("minio PutObject failed: " + putErr.Error())
			http.Error(w, putErr.Error(), 500)
			return
		}
	}

	totalDuration := time.Since(start).Milliseconds()

	// ============================
	// CALLBACK SUCCESS
	// ============================
	log.Printf(
		"[UPLOAD] done filename=%s stored=%.2f MB total=%d ms compress=%d ms encrypt=%d ms",
		filename,
		float64(info.Size)/1024/1024,
		totalDuration,
		compressDuration,
		encryptDuration,
	)

	sendCallback(CallbackPayload{
		Event:              "upload",
		BackupID:           backupID,
		Filename:           filename,
		MinioPath:          objectName,
		OriginalSize:       originalSize,
		FinalSize:          info.Size,
		DurationMs:         encryptDuration, // legacy alias
		DurationEncryptMs:  encryptDuration,
		DurationCompressMs: compressDuration,
		DurationTotalMs:    totalDuration,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "uploaded",
	})
}

/* ======================================================
   INTEGRITY HANDLER
====================================================== */

/* ======================================================
   INTEGRITY HANDLER
   - Download object dari MinIO
   - Decrypt (AES-256-GCM manual, block-based)
   - Decompress (Deflate)
   - Hash SHA-256
   - Kirim callback hasil ke Laravel
====================================================== */

func IntegrityHandler(w http.ResponseWriter, r *http.Request) {

	// ================= VALIDASI PARAM =================
	path := r.URL.Query().Get("path")
	backupIDStr := r.URL.Query().Get("backup_id")
	if path == "" || backupIDStr == "" {
		http.Error(w, "path & backup_id required", 400)
		return
	}

	backupID, _ := strconv.ParseInt(backupIDStr, 10, 64)
	start := time.Now()

	log.Printf("[INTEGRITY] start path=%s backup_id=%d", path, backupID)

	// ================= GET OBJECT =================
	obj, err := minioClient.GetObject(
		context.Background(),
		cfg.Bucket,
		path,
		minio.GetObjectOptions{},
	)
	if err != nil {
		log.Printf("[INTEGRITY] failed open object: %v", err)

		// 🚨 callback ke Laravel (FAILED)
		sendCallback(CallbackPayload{
			Event:    "integrity_failed",
			BackupID: backupID,
		})

		http.Error(w, err.Error(), 500)
		return
	}

	// ================= INIT PIPE =================
	// pr → flate reader → hasher
	// pw ← decryptor
	pr, pw := io.Pipe()

	// init manual AES-256-GCM
	gcm, err := aesgcm.NewAESGCM(aesKey)
	if err != nil {
		pw.CloseWithError(err)

		sendCallback(CallbackPayload{
			Event:    "integrity_failed",
			BackupID: backupID,
		})

		http.Error(w, "aes init failed", 500)
		return
	}

	var decBytes int64

	// ⏱️ TIMER VARS (DITAMBAHKAN)
	var decryptStart time.Time
	var decryptDuration int64
	var decompressStart time.Time
	var decompressDuration int64

	// ================= DECRYPT GOROUTINE =================
	go func() {
		defer pw.Close()

		for {
			// 1️⃣ baca nonce
			nonce := make([]byte, aesgcm.NonceSize)
			if _, err := io.ReadFull(obj, nonce); err != nil {
				return // EOF normal → selesai
			}

			// 🔹 start decrypt timer (blok pertama)
			if decryptStart.IsZero() {
				decryptStart = time.Now()
			}

			// 2️⃣ baca panjang ciphertext
			clen, err := readUint64(obj)
			if err != nil {
				pw.CloseWithError(err)
				return
			}

			// 3️⃣ baca ciphertext
			ciphertext := make([]byte, clen)
			if _, err := io.ReadFull(obj, ciphertext); err != nil {
				pw.CloseWithError(err)
				return
			}

			// 4️⃣ baca authentication tag
			tag := make([]byte, aesgcm.TagSize)
			if _, err := io.ReadFull(obj, tag); err != nil {
				pw.CloseWithError(err)
				return
			}

			// 5️⃣ decrypt + verify tag
			plain, err := gcm.Decrypt(ciphertext, nonce, tag)
			if err != nil {
				log.Printf("[INTEGRITY] decrypt failed: %v", err)

				sendCallback(CallbackPayload{
					Event:    "integrity_failed",
					BackupID: backupID,
				})

				pw.CloseWithError(err)
				return
			}

			// progress log
			decBytes += int64(len(plain))
			if decBytes%LOG_INTERVAL < int64(len(plain)) {
				log.Printf("[INTEGRITY] decrypted %.2f MB",
					float64(decBytes)/1024/1024)
			}

			// kirim plaintext ke flate reader
			pw.Write(plain)
		}
	}()

	// ================= DECOMPRESS + HASH =================
	flateR := flate.NewReader(pr)
	defer flateR.Close()

	hasher := sha256.New()
	decompressStart = time.Now()
	if _, err := io.Copy(hasher, flateR); err != nil {
		log.Printf("[INTEGRITY] hash failed: %v", err)

		sendCallback(CallbackPayload{
			Event:    "integrity_failed",
			BackupID: backupID,
		})

		http.Error(w, "integrity failed", 500)
		return
	}

	// 🔹 stop timers
	if !decryptStart.IsZero() {
		decryptDuration = time.Since(decryptStart).Milliseconds()
	}
	decompressDuration = time.Since(decompressStart).Milliseconds()
	totalDuration := time.Since(start).Milliseconds()

	// ================= FINAL RESULT =================
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	//duration := time.Since(start).Milliseconds()

	log.Printf(
		"[INTEGRITY] done path=%s size=%.2f MB duration=%d ms",
		path,
		float64(decBytes)/1024/1024,
		decryptDuration,
		decompressDuration,
		totalDuration,
	)

	// ================= CALLBACK SUCCESS =================
	sendCallback(CallbackPayload{
		Event:                "integrity",
		BackupID:             backupID,
		MinioPath:            path,
		HashAfter:            hash,
		DurationDecryptMs:    decryptDuration,
		DurationDecompressMs: decompressDuration,
		DurationTotalMs:      totalDuration,
	})

	// ================= HTTP RESPONSE =================
	json.NewEncoder(w).Encode(map[string]any{
		"hash_after": hash,
		"time_ms":    decryptDuration,
	})
}

/* ======================================================
   DOWNLOAD DECRYPTED
====================================================== */

/* ======================================================
   DOWNLOAD DECRYPTED HANDLER
   - Download object terenkripsi dari MinIO
   - Decrypt AES-256-GCM (manual, block-based)
   - Decompress Deflate
   - Stream langsung ke client (tanpa buffer besar)
====================================================== */

func DownloadDecryptedHandler(w http.ResponseWriter, r *http.Request) {

	// ================= PARAM =================
	path := r.URL.Query().Get("path")
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "restore.bin"
	}

	// ⏱️ total download timer
	start := time.Now()

	log.Printf("[DOWNLOAD] start path=%s", path)

	// ================= GET OBJECT =================
	obj, err := minioClient.GetObject(
		context.Background(),
		cfg.Bucket,
		path,
		minio.GetObjectOptions{},
	)
	if err != nil {
		log.Printf("[DOWNLOAD] failed open object: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	// ================= RESPONSE HEADER =================
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filename),
	)
	w.Header().Set("Content-Type", "application/octet-stream")

	// ================= INIT AES-GCM =================
	gcm, err := aesgcm.NewAESGCM(aesKey)
	if err != nil {
		log.Printf("[DOWNLOAD] aes init failed: %v", err)
		http.Error(w, "crypto init failed", 500)
		return
	}

	// ================= PIPE =================
	// pr → flate reader → http response
	// pw ← decryptor
	pr, pw := io.Pipe()

	var outBytes int64

	// ⏱️ TIMER VARS (DITAMBAHKAN)
	var decryptStart time.Time
	var decryptDuration int64
	var decompressStart time.Time
	var decompressDuration int64

	// ================= DECRYPT GOROUTINE =================
	go func() {
		defer pw.Close()

		for {
			// 1️⃣ read nonce
			nonce := make([]byte, aesgcm.NonceSize)
			if _, err := io.ReadFull(obj, nonce); err != nil {
				return // EOF normal
			}

			// 🔹 mulai hitung decrypt time (blok pertama)
			if decryptStart.IsZero() {
				decryptStart = time.Now()
			}

			// 2️⃣ read ciphertext length
			clen, err := readUint64(obj)
			if err != nil {
				pw.CloseWithError(err)
				return
			}

			// 3️⃣ read ciphertext
			ciphertext := make([]byte, clen)
			if _, err := io.ReadFull(obj, ciphertext); err != nil {
				pw.CloseWithError(err)
				return
			}

			// 4️⃣ read authentication tag
			tag := make([]byte, aesgcm.TagSize)
			if _, err := io.ReadFull(obj, tag); err != nil {
				pw.CloseWithError(err)
				return
			}

			// 5️⃣ decrypt + authenticate
			plain, err := gcm.Decrypt(ciphertext, nonce, tag)
			if err != nil {
				log.Printf("[DOWNLOAD] decrypt failed: %v", err)
				pw.CloseWithError(err)
				return
			}

			outBytes += int64(len(plain))
			if outBytes%LOG_INTERVAL < int64(len(plain)) {
				log.Printf("[DOWNLOAD] decrypted %.2f MB",
					float64(outBytes)/1024/1024)
			}

			// kirim ke flate reader
			pw.Write(plain)
		}
	}()

	// ================= DECOMPRESS + STREAM =================

	// 🔹 mulai hitung decompress time
	decompressStart = time.Now()

	flateR := flate.NewReader(pr)
	defer flateR.Close()

	if _, err := io.Copy(w, flateR); err != nil {
		log.Printf("[DOWNLOAD] stream error: %v", err)
		return
	}

	// ⏱️ stop timers
	if !decryptStart.IsZero() {
		decryptDuration = time.Since(decryptStart).Milliseconds()
	}
	decompressDuration = time.Since(decompressStart).Milliseconds()
	totalDuration := time.Since(start).Milliseconds()

	// ================= DONE =================
	log.Printf(
		"[DOWNLOAD] done path=%s total=%.2f MB decrypt=%d ms decompress=%d ms total=%d ms",
		path,
		float64(outBytes)/1024/1024,
		decryptDuration,
		decompressDuration,
		totalDuration,
	)
}

/* ======================================================
   DELETE HANDLER
====================================================== */

func DeleteHandler(w http.ResponseWriter, r *http.Request) {

	pathEnc := r.URL.Query().Get("path")
	if pathEnc == "" {
		http.Error(w, "path required", 400)
		return
	}

	// decode URL (karena dari Laravel biasanya di urlencode)
	path, err := url.QueryUnescape(pathEnc)
	if err != nil {
		http.Error(w, "invalid path", 400)
		return
	}

	log.Printf("[DELETE] Request delete: %s", path)

	err = minioClient.RemoveObject(
		context.Background(),
		cfg.Bucket,
		path,
		minio.RemoveObjectOptions{},
	)

	if err != nil {
		log.Printf("[DELETE] FAILED %s: %v", path, err)
		http.Error(w, "delete failed", 500)
		return
	}

	log.Printf("[DELETE] SUCCESS %s", path)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"deleted": true,
		"path":    path,
	})
}

/* ======================================================
   MAIN
====================================================== */

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			return
		}
		h(w, r)
	}
}

func main() {
	runtime.GOMAXPROCS(2)
	loadConfig()
	initMinio()

	http.HandleFunc("/upload", withCORS(UploadHandler))
	http.HandleFunc("/integrity", withCORS(IntegrityHandler))
	http.HandleFunc("/download/decrypted", withCORS(DownloadDecryptedHandler))
	http.HandleFunc("/delete", withCORS(DeleteHandler))

	log.Println("[SERVER] listening on", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, nil))
}
