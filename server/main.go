package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	fqdn        string
	fileBuffers = make(map[string][]byte)
	bufferMutex sync.Mutex
	key         = []byte("0123456789abcdef0123456789abcdef")
	outputDir   string
	debug       bool
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	flag.StringVar(&fqdn, "fqdn", "tunnel.local.", "FQDN to listen for")
	flag.StringVar(&outputDir, "output", "./received_files", "Directory to save received files")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.Parse()

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Explicitly bind to IPv4
	addr := &net.UDPAddr{
		Port: 53,
		IP:   net.ParseIP("0.0.0.0").To4(), // Explicitly use IPv4
	}

	log.Printf("Starting server on %s:%d", addr.IP, addr.Port)
	log.Printf("Listening for domain: %s", fqdn)

	conn, err := net.ListenUDP("udp4", addr) // Explicitly use UDP4
	if err != nil {
		log.Fatalf("Failed to bind to port 53: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	log.Printf("Successfully bound to %s:%d", localAddr.IP, localAddr.Port)

	// Simple test to verify packet reception
	log.Printf("You can test the server with: dig @127.0.0.1 test.local")

	log.Printf("DNS server listening on %s:53 for domain %s", addr.IP, fqdn)
	log.Printf("Files will be saved to: %s", outputDir)
	log.Printf("Debug logging enabled")

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		log.Printf("PACKET: %d bytes from %s", n, remoteAddr)
		log.Printf("PACKET HEADER: % x", buffer[:min(12, n)])

		rawQuery := make([]byte, n)
		copy(rawQuery, buffer[:n])
		go handleDNSRequest(rawQuery, conn, remoteAddr)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleDNSRequest(data []byte, conn *net.UDPConn, remoteAddr *net.UDPAddr) {
	log.Printf("HANDLING: %d bytes from %s", len(data), remoteAddr)

	// Create and send response regardless of query match
	defer func() {
		response := createDNSResponse(data)
		n, err := conn.WriteToUDP(response, remoteAddr)
		if err != nil {
			log.Printf("ERROR: Failed to send response: %v", err)
		} else {
			log.Printf("SUCCESS: Sent %d bytes response to %s", n, remoteAddr)
		}
	}()

	query := extractQuery(data)
	log.Printf("QUERY: %s", query)

	// Normalize both strings for comparison
	normalizedQuery := strings.TrimSuffix(query, ".")
	normalizedFQDN := strings.TrimSuffix(fqdn, ".")

	if !strings.HasSuffix(normalizedQuery, normalizedFQDN) {
		log.Printf("Query doesn't match our FQDN. Got: %s, Expected suffix: %s",
			normalizedQuery, normalizedFQDN)
		return
	}

	// Extract the encoded data part
	encodedData := strings.TrimSuffix(normalizedQuery, normalizedFQDN)
	encodedData = strings.TrimSuffix(encodedData, ".") // Remove trailing dot if present

	parts := strings.Split(encodedData, ".")
	if len(parts) < 3 {
		log.Printf("Invalid parts count: %d", len(parts))
		return
	}

	fileID := parts[0]
	chunkNum := parts[1]
	payload := parts[2]

	log.Printf("Processing - FileID: %s, Chunk: %s, Payload length: %d",
		fileID, chunkNum, len(payload))

	// Decode base32 data
	decoded, err := base32.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("ERROR decoding base32: %v", err)
		return
	}
	log.Printf("Decoded length: %d bytes", len(decoded))

	// Decrypt data
	decrypted, err := decrypt(decoded)
	if err != nil {
		log.Printf("ERROR decrypting: %v", err)
		return
	}
	log.Printf("Decrypted length: %d bytes", len(decrypted))

	bufferMutex.Lock()
	if _, exists := fileBuffers[fileID]; !exists {
		fileBuffers[fileID] = make([]byte, 0)
		log.Printf("Created new buffer for file %s", fileID)
	}
	fileBuffers[fileID] = append(fileBuffers[fileID], decrypted...)
	currentSize := len(fileBuffers[fileID])
	bufferMutex.Unlock()

	log.Printf("SUCCESS: Received chunk %s for file %s (total size: %d bytes)",
		chunkNum, fileID, currentSize)

	// Try to save the file if this seems to be the last chunk
	// (waiting more than 2 seconds since last chunk)
	go tryToSaveFile(fileID)
}

func tryToSaveFile(fileID string) {
	time.Sleep(2 * time.Second) // Wait for potential more chunks

	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	data, exists := fileBuffers[fileID]
	if !exists {
		return
	}

	// Generate filename based on fileID and timestamp
	filename := fmt.Sprintf("%s/%s_%s.bin",
		outputDir,
		fileID,
		time.Now().Format("20060102_150405"))

	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Printf("ERROR: Failed to save file %s: %v", filename, err)
		return
	}

	log.Printf("SUCCESS: Saved file %s (%d bytes)", filename, len(data))

	// Clean up the buffer
	delete(fileBuffers, fileID)
}

func decrypt(ciphertext []byte) ([]byte, error) {
	if debug {
		log.Printf("DEBUG: Decrypting %d bytes", len(ciphertext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func extractQuery(data []byte) string {
	var query strings.Builder
	idx := 12 // Skip DNS header

	log.Printf("Extracting query from %d bytes", len(data))

	for idx < len(data) {
		if idx >= len(data) {
			log.Printf("WARNING: Reached end of packet at %d", idx)
			break
		}

		length := int(data[idx])
		log.Printf("Label length at %d: %d", idx, length)

		if length == 0 {
			break
		}
		idx++

		if idx+length > len(data) {
			log.Printf("WARNING: Label would exceed packet bounds")
			break
		}

		if query.Len() > 0 {
			query.WriteByte('.')
		}
		label := string(data[idx : idx+length])
		query.WriteString(label)
		log.Printf("Added label: %s", label)

		idx += length
	}

	return query.String()
}

func createDNSResponse(request []byte) []byte {
	if len(request) < 12 {
		return nil
	}

	response := make([]byte, len(request))
	copy(response, request)

	// Set QR bit to 1 (response)
	response[2] |= 0x80

	// Add an answer section
	response = append(response, []byte{
		0xc0, 0x0c, // Name pointer to question
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3c, // TTL (60 seconds)
		0x00, 0x04, // Data length (4 bytes for IPv4)
		127, 0, 0, 1, // IP address (127.0.0.1)
	}...)

	// Set answer count to 1
	response[6] = 0x00
	response[7] = 0x01

	return response
}
