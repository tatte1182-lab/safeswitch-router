package mitm

import (
	"fmt"
	"log"
	"net/http"
)

// ServeCAEndpoint registers GET /ca/cert on the given mux. Enrolled devices
// hit this endpoint during enrollment to download and install the root CA cert.
//
// The endpoint is intentionally unauthenticated over HTTP because the device
// hasn't trusted any SafeSwitch cert yet — it uses the node token to verify
// it's talking to the right node before installing.
func ServeCAEndpoint(mux *http.ServeMux, ca *CA) {
	mux.HandleFunc("/ca/cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		log.Printf("[mitm] CA cert requested from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="safeswitch-ca.pem"`)
		w.Write(ca.RawCert())
	})

	log.Println("[mitm] CA cert endpoint registered at GET /ca/cert")
}

// ServeCAInfo registers GET /ca/info which returns a JSON summary of the CA
// (subject, expiry) for parent-app display.
func ServeCAInfo(mux *http.ServeMux, ca *CA) {
	mux.HandleFunc("/ca/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"subject":%q,"not_after":%q}`,
			ca.cert.Subject.CommonName,
			ca.cert.NotAfter.Format("2006-01-02"),
		)
	})
}
