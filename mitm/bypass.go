package mitm

import "strings"

// bypassHosts contains hostname suffixes that must never be intercepted.
// These apps use certificate pinning and will break if we MITM them.
// For these hosts we pass the raw CONNECT tunnel through unchanged.
var bypassHosts = []string{
	// Apple
	"apple.com",
	"icloud.com",
	"mzstatic.com",
	"cdn-apple.com",
	"apple-dns.net",

	// Google
	"google.com",
	"googleapis.com",
	"gstatic.com",
	"googleusercontent.com",
	"gvt1.com",
	"gvt2.com",
	"play.google.com",
	"android.clients.google.com",

	// Android / Google Play
	"dl.google.com",
	"android.googleapis.com",

	// Meta / WhatsApp
	"whatsapp.com",
	"whatsapp.net",
	"instagram.com",
	"cdninstagram.com",

	// Banks (AU)
	"commbank.com.au",
	"nab.com.au",
	"westpac.com.au",
	"anz.com.au",
	"ing.com.au",
	"bendigo.com.au",
	"macquarie.com.au",
	"ubank.com.au",
	"86400.com.au",

	// Telcos (AU)
	"telstra.com",
	"optus.com.au",
	"vodafone.com.au",

	// Microsoft
	"microsoft.com",
	"microsoftonline.com",
	"live.com",
	"azure.com",
	"windowsupdate.com",

	// SafeSwitch infrastructure — never intercept our own traffic
	"safeswitch.io",
	"supabase.co",
	"supabase.com",
}

// ShouldBypass returns true if the given hostname should be passed through
// without MITM interception (cert pinning bypass).
func ShouldBypass(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	// Strip port if present
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		h = h[:idx]
	}
	for _, suffix := range bypassHosts {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return false
}
