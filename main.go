package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type SSLInfo struct {
	Website   string    `json:"website"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	IdValid   bool      `json:"is_valid"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func getSSLCertificateDates(hostname string) (time.Time, time.Time, error) {
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		DualStack: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", hostname+":443", nil)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		return cert.NotBefore, cert.NotAfter, nil
	}

	return time.Time{}, time.Time{}, fmt.Errorf("unable to retrieve SSL certificate information")
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

	notBefore, notAfter, err := getSSLCertificateDates(website)
	if err != nil {
		errorResponse := ErrorResponse{Error: err.Error()}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	sslInfo := SSLInfo{
		Website:   website,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IdValid:   time.Now().Before(notAfter),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sslInfo)
}

func main() {
	http.HandleFunc("/ssl-dates", sslInfoHandler)

	port := 8080
	fmt.Printf("Server is running on :%d...\n", port)
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
