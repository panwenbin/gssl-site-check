package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type SSLInfo struct {
	Website    string    `json:"website"`
	CommonName string    `json:"common_name"`
	DNSNames   []string  `json:"dns_names"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	IdValid    bool      `json:"is_valid"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func getSSLCertificate(hostname string) (*x509.Certificate, error) {
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		DualStack: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", hostname+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		return cert, nil
	}

	return nil, fmt.Errorf("unable to retrieve SSL certificate information")
}

func getSSLCertificateChain(hostname string) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		DualStack: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", hostname+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return state.PeerCertificates, nil
}

func sslInfoHandler(w http.ResponseWriter, r *http.Request) {
	website := r.URL.Query().Get("website")
	if website == "" {
		errorResponse := ErrorResponse{Error: "Missing 'website' parameter"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	cert, err := getSSLCertificate(website)
	if err != nil {
		errorResponse := ErrorResponse{Error: err.Error()}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cert)
}

func sslDatesHandler(w http.ResponseWriter, r *http.Request) {
	website := r.URL.Query().Get("website")
	if website == "" {
		errorResponse := ErrorResponse{Error: "Missing 'website' parameter"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	cert, err := getSSLCertificate(website)
	if err != nil {
		errorResponse := ErrorResponse{Error: err.Error()}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	sslInfo := SSLInfo{
		Website:    website,
		CommonName: cert.Subject.CommonName,
		DNSNames:   cert.DNSNames,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		IdValid:    time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sslInfo)
}

func sslChainHandler(w http.ResponseWriter, r *http.Request) {
	website := r.URL.Query().Get("website")
	if website == "" {
		errorResponse := ErrorResponse{Error: "Missing 'website' parameter"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	certs, err := getSSLCertificateChain(website)
	if err != nil {
		errorResponse := ErrorResponse{Error: err.Error()}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

func main() {
	http.HandleFunc("/ssl-info", sslInfoHandler)
	http.HandleFunc("/ssl-dates", sslDatesHandler)
	http.HandleFunc("/ssl-chain", sslChainHandler)

	port := 8080
	fmt.Printf("Server is running on :%d...\n", port)
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
