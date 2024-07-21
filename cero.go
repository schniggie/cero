package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ScanResult struct {
	Timestamp time.Time `json:"@timestamp"`
	Address   string    `json:"address"`
	Names     []string  `json:"names"`
	ScanID    string    `json:"scan_id"`
}

/* result of processing a domain name */
type procResult struct {
	addr  string
	names []string
	err   error
}

// run parameters (filled from CLI arguments)
var (
	verbose              bool
	concurrency          int
	defaultPorts         []string
	timeout              int
	onlyValidDomainNames bool
	scanIDSuffix         string
)

var usage = "" +
	`usage: cero [options] [targets]
if [targets] not provided in commandline arguments, will read from stdin
`

// Global variables for metrics
var (
	totalScanned    int64
	successfulScans int64
	namesFound      int64
	startTime       time.Time
)

// Metrics struct for JSON output
type Metrics struct {
	TotalScanned      int64   `json:"total_scanned"`
	SuccessfulScans   int64   `json:"successful_scans"`
	NamesFound        int64   `json:"names_found"`
	ElapsedTime       float64 `json:"elapsed_time"`
	EstimatedTimeLeft float64 `json:"estimated_time_left"`
	ScanRate          float64 `json:"scan_rate"`
	MemoryUsage       float64 `json:"memory_usage"`
}

func main() {
	// parse CLI arguments
	var ports string

	flag.BoolVar(&verbose, "v", false, `Be verbose: Output results as 'addr -- [result list]', output errors to stderr as 'addr -- error message'`)
	flag.IntVar(&concurrency, "c", 100, "Concurrency level")
	flag.StringVar(&ports, "p", "443", "TLS ports to use, if not specified explicitly in host address. Use comma-separated list")
	flag.IntVar(&timeout, "t", 4, "TLS Connection timeout in seconds")
	flag.BoolVar(&onlyValidDomainNames, "d", false, "Output only valid domain names (e.g. strip IPs, wildcard domains and gibberish)")
	flag.StringVar(&scanIDSuffix, "id", "", "Optional suffix to append to the ScanID")

	// set custom usage text
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usage)
		fmt.Fprintln(os.Stderr, "options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Create the Elasticsearch client
	es, err := elasticsearch.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error creating the client: %s", err)
	}

	// parse default port list into string slice
	defaultPorts = strings.Split(ports, `,`)

	// Set up memory management
	debug.SetGCPercent(20)                       // More aggressive garbage collection
	debug.SetMemoryLimit(2 * 1024 * 1024 * 1024) // 2GB memory limit

	// Use a buffered channel to control input flow
	chanInput := make(chan string, 1000)
	chanResult := make(chan *procResult, 1000)

	// a common dialer
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Initialize start time
	startTime = time.Now()

	// Start HTTP server for metrics
	go func() {
		port := 8081
		var listener net.Listener
		var err error

		for {
			listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				if isPortInUseError(err) {
					port++
					continue
				}
				log.Fatalf("Failed to start metrics server: %v", err)
			}
			break
		}

		log.Printf("Metrics server listening on port %d", port)

		http.HandleFunc("/metrics", corsMiddleware(metricsHandler))
		log.Fatal(http.Serve(listener, nil))
	}()

	// Start a goroutine to periodically print metrics to the terminal
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printMetrics()
			}
		}
	}()

	// create and start concurrent workers
	var workersWG sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workersWG.Add(1)
		go func() {
			for addr := range chanInput {
				result := &procResult{addr: addr}
				result.names, result.err = grabCert(addr, dialer, onlyValidDomainNames)
				chanResult <- result
			}
			workersWG.Done()
		}()
	}

	// close result channel when workers are done
	go func() {
		workersWG.Wait()
		close(chanResult)
	}()

	// create and start result-processing worker
	var outputWG sync.WaitGroup
	outputWG.Add(1)

	go func() {
		resultBatch := make([]*procResult, 0, 1000)
		resultTicker := time.NewTicker(5 * time.Second)
		defer resultTicker.Stop()

		for {
			select {
			case result, ok := <-chanResult:
				if !ok {
					// Process remaining results
					processResultBatch(resultBatch, es)
					outputWG.Done()
					return
				}
				resultBatch = append(resultBatch, result)
				if len(resultBatch) >= 1000 {
					processResultBatch(resultBatch, es)
					resultBatch = resultBatch[:0]
				}
			case <-resultTicker.C:
				if len(resultBatch) > 0 {
					processResultBatch(resultBatch, es)
					resultBatch = resultBatch[:0]
				}
				// Trigger garbage collection
				runtime.GC()
			}
		}
	}()

	if len(flag.Args()) > 0 {
		for _, addr := range flag.Args() {
			processInputItem(addr, chanInput, chanResult)
		}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			addr := strings.TrimSpace(sc.Text())
			processInputItem(addr, chanInput, chanResult)
		}
	}

	close(chanInput)
	outputWG.Wait()

	// Final metrics output
	printMetrics()
}

func processResultBatch(batch []*procResult, es *elasticsearch.Client) {
	for _, result := range batch {
		atomic.AddInt64(&totalScanned, 1)

		if result.err == nil && len(result.names) > 0 {
			atomic.AddInt64(&successfulScans, 1)
			atomic.AddInt64(&namesFound, int64(len(result.names)))

			scanID := time.Now().Format("2006-01-02")
			if scanIDSuffix != "" {
				scanID = scanID + "-" + scanIDSuffix
			}
			scanResult := ScanResult{
				Timestamp: time.Now(),
				Address:   result.addr,
				Names:     result.names,
				ScanID:    scanID,
			}

			data, err := json.Marshal(scanResult)
			if err != nil {
				log.Printf("Error marshaling document: %s", err)
				continue
			}
			if verbose {
				log.Printf("Attempting to index document: %s", string(data))
			}

			req := esapi.IndexRequest{
				Index:      "cero-scans",
				Body:       bytes.NewReader(data),
				Refresh:    "true",
				DocumentID: "",
			}

			res, err := req.Do(context.Background(), es)
			if err != nil {
				log.Printf("Error getting response: %s", err)
				continue
			}
			defer res.Body.Close()

			if res.IsError() {
				bodyBytes, err := ioutil.ReadAll(res.Body)
				if err != nil {
					log.Printf("Error reading error response body: %s", err)
				}
				log.Printf("[%s] Error indexing document: %s", res.Status(), string(bodyBytes))
			} else {
				var r map[string]interface{}
				if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
					log.Printf("Error parsing the response body: %s", err)
				} else if verbose {
					log.Printf("[%s] %s; version=%d", res.Status(), r["result"], int(r["_version"].(float64)))
				}
			}
		}

		if verbose {
			if result.err != nil {
				fmt.Fprintf(os.Stderr, "%s -- %s\n", result.addr, result.err)
			} else {
				fmt.Fprintf(os.Stdout, "%s -- %s\n", result.addr, result.names)
			}
		}
	}
}

// process input item
// if orrors occur during parsing, they are pushed straight to result channel
func processInputItem(input string, chanInput chan string, chanResult chan *procResult) {
	// initial inputs are skipped
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	// split input to host and port (if specified)
	host, port := splitHostPort(input)

	// get ports list to use
	var ports []string
	if port == "" {
		// use ports from default list if not specified explicitly
		ports = defaultPorts
	} else {
		ports = []string{port}
	}

	// CIDR?
	if isCIDR(host) {
		// expand CIDR
		ips, err := expandCIDR(host)
		if err != nil {
			chanResult <- &procResult{addr: input, err: err}
			return
		}

		// feed IPs from CIDR to input channel
		for ip := range ips {
			for _, port := range ports {
				chanInput <- net.JoinHostPort(ip, port)
			}
		}
	} else {
		// feed atomic host to input channel
		for _, port := range ports {
			chanInput <- net.JoinHostPort(host, port)
		}
	}
}

// connects to addr and grabs certificate information.
// returns slice of domain names from grabbed certificate
func grabCert(addr string, dialer *net.Dialer, onlyValidDomainNames bool) ([]string, error) {
	// dial
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// get first certificate in chain
	cert := conn.ConnectionState().PeerCertificates[0]

	// get CommonName and all SANs into a slice
	names := make([]string, 0, len(cert.DNSNames)+1)
	if onlyValidDomainNames && isDomainName(cert.Subject.CommonName) || !onlyValidDomainNames {
		names = append(names, cert.Subject.CommonName)
	}

	// append all SANs, excluding one that is equal to CN (if any)
	for _, name := range cert.DNSNames {
		if name != cert.Subject.CommonName {
			if onlyValidDomainNames && isDomainName(name) || !onlyValidDomainNames {
				names = append(names, name)
			}
		}
	}

	return names, nil
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := getMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func getMetrics() Metrics {
	elapsedTime := time.Since(startTime).Seconds()
	totalScanned := atomic.LoadInt64(&totalScanned)
	scanRate := float64(totalScanned) / elapsedTime
	estimatedTimeLeft := float64(concurrency-int(totalScanned)) / scanRate

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return Metrics{
		TotalScanned:      atomic.LoadInt64(&totalScanned),
		SuccessfulScans:   atomic.LoadInt64(&successfulScans),
		NamesFound:        atomic.LoadInt64(&namesFound),
		ElapsedTime:       elapsedTime,
		EstimatedTimeLeft: estimatedTimeLeft,
		ScanRate:          scanRate,
		MemoryUsage:       float64(m.Alloc) / 1024 / 1024, // Memory usage in MB
	}
}

func printMetrics() {
	metrics := getMetrics()
	fmt.Printf("\rScanned: %d | Successful: %d | Names Found: %d | Elapsed Time: %.2fs | Est. Time Left: %.2fs | Scan Rate: %.2f/s | Memory Usage: %.2f MB",
		metrics.TotalScanned, metrics.SuccessfulScans, metrics.NamesFound, metrics.ElapsedTime, metrics.EstimatedTimeLeft, metrics.ScanRate, metrics.MemoryUsage)
}

// isPortInUseError checks if the error is due to the port being already in use
func isPortInUseError(err error) bool {
	return strings.Contains(err.Error(), "address already in use")
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}
