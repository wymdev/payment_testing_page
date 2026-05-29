package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config holds environment configurations
type Config struct {
	Port              string
	GatewayURL        string
	MerchantPublicKey string
	MerchantSecretKey string
	WebhookSecret     string
}

var cfg Config

func main() {
	// Load environment variables
	loadEnv()

	cfg = Config{
		Port:              getEnv("PORT", "8081"),
		GatewayURL:        getEnv("PAYMENT_GATEWAY_URL", "http://localhost:8080"),
		MerchantPublicKey: getEnv("MERCHANT_PUBLIC_KEY", ""),
		MerchantSecretKey: getEnv("MERCHANT_SECRET_KEY", ""),
		WebhookSecret:     getEnv("WEBHOOK_SECRET", ""),
	}

	log.Printf("[DEMO SERVER] Starting demo page server...")
	log.Printf("[DEMO SERVER] PORT: %s", cfg.Port)
	log.Printf("[DEMO SERVER] Gateway URL: %s", cfg.GatewayURL)
	log.Printf("[DEMO SERVER] Public Key configured: %v", cfg.MerchantPublicKey != "")
	log.Printf("[DEMO SERVER] Secret Key configured: %v", cfg.MerchantSecretKey != "")
	log.Printf("[DEMO SERVER] Webhook Secret configured: %v", cfg.WebhookSecret != "")

	// Static assets
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/payment", http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	})
	http.HandleFunc("/payment", handlePaymentRoute)
	http.HandleFunc("/success", handleSuccessRoute)
	http.HandleFunc("/fail", handleFailRoute)

	// API Proxy Endpoints
	http.HandleFunc("/api/checkout", handleCheckoutAPI)
	http.HandleFunc("/api/payment/", handlePaymentDetailsAPI)

	// Start server
	log.Printf("[DEMO SERVER] Listening on http://localhost:%s/payment", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		log.Fatalf("[DEMO SERVER] Server error: %v", err)
	}
}

// loadEnv parses a local .env file if it exists
func loadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			os.Setenv(key, val)
		}
	}
}

func getEnv(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val
}

// ============================================================================
// ROUTE HANDLERS
// ============================================================================

// handlePaymentRoute acts as GET /payment (checkout UI) and POST /payment (webhook)
func handlePaymentRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		serveHTML(w, r, "purchase.html")
		return
	}

	if r.Method == http.MethodPost {
		handleWebhook(w, r)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func handleSuccessRoute(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, r, "success.html")
}

func handleFailRoute(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, r, "fail.html")
}

func serveHTML(w http.ResponseWriter, r *http.Request, filename string) {
	filePath := filepath.Join("templates", filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("Template %s not found", filename), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, filePath)
}

// ============================================================================
// WEBHOOK LOGIC (POST /payment)
// ============================================================================

type WebhookEnvelope struct {
	Payload string `json:"payload"`
}

type DecryptedPayload struct {
	Event     string      `json:"event"`
	PaymentID string      `json:"payment_id"`
	Status    string      `json:"status"`
	Amount    int         `json:"amount"`
	Currency  string      `json:"currency"`
	Provider  string      `json:"provider"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	log.Println("[WEBHOOK] Received webhook POST callback from payment gateway")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[WEBHOOK ERROR] Failed to read request body: %v", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var env WebhookEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		log.Printf("[WEBHOOK ERROR] Failed to unmarshal envelope JSON: %v. Body was: %s", err, string(body))
		http.Error(w, "Invalid JSON envelope", http.StatusBadRequest)
		return
	}

	if env.Payload == "" {
		log.Println("[WEBHOOK ERROR] Missing payload field in webhook request")
		http.Error(w, "Missing payload field", http.StatusBadRequest)
		return
	}

	if cfg.WebhookSecret == "" {
		log.Println("[WEBHOOK WARNING] Webhook received, but WEBHOOK_SECRET is not configured. Cannot decrypt.")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"warning","message":"webhook received but webhook_secret is missing"}`))
		return
	}

	// Decrypt the payload
	decryptedStr, err := decryptPayload(env.Payload, cfg.WebhookSecret)
	if err != nil {
		log.Printf("[WEBHOOK ERROR] Failed to decrypt payload: %v", err)
		http.Error(w, "Decryption failed", http.StatusUnprocessableEntity)
		return
	}

	log.Printf("[WEBHOOK SUCCESS] Decrypted plaintext payload: %s", decryptedStr)

	var payload DecryptedPayload
	if err := json.Unmarshal([]byte(decryptedStr), &payload); err != nil {
		log.Printf("[WEBHOOK ERROR] Failed to parse decrypted payload: %v", err)
	} else {
		// Log structured info
		log.Println("================================================================================")
		log.Printf("🔔 Outbound Webhook Event Processed:")
		log.Printf("   Event:     %s", payload.Event)
		log.Printf("   PaymentID: %s", payload.PaymentID)
		log.Printf("   Status:    %s", payload.Status)
		log.Printf("   Amount:    %d %s", payload.Amount, payload.Currency)
		log.Printf("   Provider:  %s", payload.Provider)
		log.Printf("   Timestamp: %s", payload.Timestamp)
		log.Println("================================================================================")
	}

	// Respond 200 OK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

// ============================================================================
// API PROXY HANDLERS
// ============================================================================

func handleCheckoutAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Forward request to Gateway: POST /v1/payments
	gatewayEndpoint := fmt.Sprintf("%s/v1/payments", cfg.GatewayURL)
	req, err := http.NewRequest(http.MethodPost, gatewayEndpoint, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[CHECKOUT ERROR] Failed to create gateway request: %v", err)
		http.Error(w, "Internal Gateway Error", http.StatusInternalServerError)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.MerchantSecretKey)
	
	// Generate random idempotency key
	idempotencyKey := generateIdempotencyKey()
	req.Header.Set("Idempotency-Key", idempotencyKey)

	log.Printf("[CHECKOUT] Proxying payment request. Amount: %s, Idempotency-Key: %s", string(body), idempotencyKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[CHECKOUT ERROR] Payment Gateway request failed: %v", err)
		http.Error(w, "Payment Gateway unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func handlePaymentDetailsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract payment ID from URL: /api/payment/:id
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		http.Error(w, "Missing Payment ID", http.StatusBadRequest)
		return
	}
	paymentID := pathParts[3]

	// Forward to Gateway: GET /v1/payments/:id
	gatewayEndpoint := fmt.Sprintf("%s/v1/payments/%s", cfg.GatewayURL, paymentID)
	req, err := http.NewRequest(http.MethodGet, gatewayEndpoint, nil)
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", "Bearer "+cfg.MerchantSecretKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Payment Gateway unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

func decryptPayload(encryptedStr, secret string) (string, error) {
	// 1. Derive 32-byte key from secret (SHA-256)
	keyBytes := sha256.Sum256([]byte(secret))
	key := keyBytes[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	// 2. Base64 decode payload to get combined IV + Ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext block size too short")
	}

	// 3. Extract IV and encrypted data
	iv := ciphertext[:aes.BlockSize]
	encryptedData := ciphertext[aes.BlockSize:]

	if len(encryptedData)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext size is not a multiple of the block size")
	}

	// 4. Decrypt in CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(encryptedData))
	mode.CryptBlocks(plaintext, encryptedData)

	// 5. Remove PKCS7 padding
	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("pkcs7 unpad: %w", err)
	}

	return string(unpadded), nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data size %d is not a multiple of block size %d", len(data), blockSize)
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen < 1 || paddingLen > blockSize {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}
	for i := len(data) - paddingLen; i < len(data); i++ {
		if int(data[i]) != paddingLen {
			return nil, fmt.Errorf("invalid padding byte at index %d: expected %d, got %d", i, paddingLen, data[i])
		}
	}
	return data[:len(data)-paddingLen], nil
}

func generateIdempotencyKey() string {
	// Simple UUID v4 mock/generator using current time and random components
	now := time.Now().UnixNano()
	return fmt.Sprintf("idem-%d-%d", now, time.Now().UnixNano()%1000000)
}
