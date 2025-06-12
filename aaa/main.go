package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/html"
	"golang.org/x/time/rate"
)

// CryptoUtils provides cryptographic utilities for web content
type CryptoUtils struct {
	salt []byte
}

// NewCryptoUtils creates a new CryptoUtils instance with random salt
func NewCryptoUtils() (*CryptoUtils, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return &CryptoUtils{salt: salt}, nil
}

// HashTitle computes multiple hash values for the given title
func (c *CryptoUtils) HashTitle(title string) (map[string]string, error) {
	hashes := make(map[string]string)

	// SHA3-256 hash
	sha3Hash := sha3.Sum256([]byte(title))
	hashes["sha3-256"] = hex.EncodeToString(sha3Hash[:])

	// BLAKE2b hash
	blake2bHash := blake2b.Sum256([]byte(title))
	hashes["blake2b-256"] = hex.EncodeToString(blake2bHash[:])

	// PBKDF2 key derivation (for demonstration)
	pbkdf2Key := pbkdf2.Key([]byte(title), c.salt, 10000, 32, sha3.New256)
	hashes["pbkdf2-sha3"] = hex.EncodeToString(pbkdf2Key)
	hashes["salt"] = hex.EncodeToString(c.salt)

	return hashes, nil
}

// ValidateContentIntegrity compares content hash with expected value
func (c *CryptoUtils) ValidateContentIntegrity(content, expectedHash string) bool {
	hash := blake2b.Sum256([]byte(content))
	actualHash := hex.EncodeToString(hash[:])
	return actualHash == expectedHash
}

// HTTPClient wraps http.Client with rate limiting functionality
type HTTPClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

// NewHTTPClient creates a new HTTP client with rate limiting
// limit: requests per second, burst: maximum burst size
func NewHTTPClient(limit rate.Limit, burst int) *HTTPClient {
	return &HTTPClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(limit, burst),
	}
}

// Get performs a rate-limited HTTP GET request
func (c *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	// Wait for rate limiter permission
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Perform the request
	return c.client.Do(req)
}

// PageInfo contains information about a fetched page
type PageInfo struct {
	URL    string
	Title  string
	Hashes map[string]string
}

// fetchAndParseHTML fetches HTML content from the given URL and extracts title
func fetchAndParseHTML(url string, crypto *CryptoUtils) (*PageInfo, error) {
	// Create HTTP client with rate limiting (1 request per second, burst of 3)
	httpClient := NewHTTPClient(rate.Every(1*time.Second), 3)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("等待限流器许可...")

	// Fetch the webpage content with rate limiting
	resp, err := httpClient.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	// Parse the HTML content
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Extract the title from the parsed HTML
	title := extractTitle(doc)

	// Compute cryptographic hashes for the title
	hashes, err := crypto.HashTitle(title)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hashes: %w", err)
	}

	return &PageInfo{
		URL:    url,
		Title:  title,
		Hashes: hashes,
	}, nil
}

// extractTitle traverses the HTML tree to find the title element
func extractTitle(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "title" {
		return getTextContent(n.FirstChild)
	}

	// Recursively search through child nodes
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if title := extractTitle(c); title != "" {
			return title
		}
	}
	return ""
}

// getTextContent extracts text content from a node
func getTextContent(n *html.Node) string {
	if n == nil {
		return ""
	}
	if n.Type == html.TextNode {
		return strings.TrimSpace(n.Data)
	}
	return ""
}

// printPageInfo displays detailed information about a page
func printPageInfo(info *PageInfo) {
	fmt.Printf("网站: %s\n", info.URL)
	if info.Title != "" {
		fmt.Printf("标题: %s\n", info.Title)
		fmt.Println("加密哈希值:")
		for hashType, hashValue := range info.Hashes {
			fmt.Printf("  %s: %s\n", hashType, hashValue)
		}
	} else {
		fmt.Println("未找到网页标题")
	}
}

func main() {
	// Initialize crypto utilities
	crypto, err := NewCryptoUtils()
	if err != nil {
		log.Fatalf("Failed to initialize crypto utils: %v", err)
	}

	fmt.Printf("初始化加密工具，盐值: %s\n", hex.EncodeToString(crypto.salt))
	fmt.Println("===================================")

	// Example URLs to fetch and parse
	urls := []string{
		"https://golang.org",
		"https://pkg.go.dev",
	}

	for _, url := range urls {
		fmt.Printf("正在获取并解析网页: %s\n", url)

		pageInfo, err := fetchAndParseHTML(url, crypto)
		if err != nil {
			log.Printf("Error fetching %s: %v", url, err)
			continue
		}

		printPageInfo(pageInfo)

		// Demonstrate content integrity validation
		if pageInfo.Title != "" {
			isValid := crypto.ValidateContentIntegrity(pageInfo.Title, pageInfo.Hashes["blake2b-256"])
			fmt.Printf("内容完整性验证: %v\n", isValid)
		}

		fmt.Println("---")
	}
}
