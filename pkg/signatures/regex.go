package signatures

import "regexp"

type Signature struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
}

var (
	// --- LEVEL 1: HARDCODED SECRETS (YANG LAMA) ---
	awsAccessKey  = regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA)[A-Z0-9]{16})\b`)
	googleApiKey  = regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`)
	genericSecret = regexp.MustCompile(`(?i)\b(password|passwd|api_?key|access_?token|secret)["']?\s*[:=]\s*["']([a-zA-Z0-9@#$%^&+=_\-\.]{8,60})["']`)

	// --- LEVEL 2: INFRASTRUCTURE LEAKS (BARU) ---
	// Mencari IP Internal (192.168.x.x / 10.x.x.x) - Sering tertinggal di config dev
	internalIP = regexp.MustCompile(`\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}\b`)

	// Mencari URL S3 Bucket (Tempat penyimpanan file cloud)
	s3Bucket = regexp.MustCompile(`[a-zA-Z0-9.-]+\.s3\.amazonaws\.com`)

	// --- LEVEL 3: DANGEROUS FUNCTIONS (DOM XSS) ---
	// Mencari fungsi JS berbahaya yang bisa dieksekusi hacker (eval, innerHTML)
	dangerousJS = regexp.MustCompile(`(?i)\b(eval|setTimeout|setInterval|execScript|innerHTML|outerHTML)\s*\(`)

	// --- LEVEL 4: DEVELOPER COMMENTS (Information Disclosure) ---
	// Mencari komentar "TODO" atau "FIXME" yang sering membocorkan logika bisnis
	devComments = regexp.MustCompile(`(?i)//\s*(TODO|FIXME|HACK|BUG|XXX):.*`)

	// --- LEVEL 5: AUTH TOKENS & PII ---
	// Mencari string Base64 panjang (biasanya JWT atau Cookie)
	// Pola: eyJ (header JWT standar) diikuti karakter panjang
	jwtToken = regexp.MustCompile(`\beyJ[a-zA-Z0-9._\-]{30,}\b`)

	// Mencari format Email (bisa jadi email admin bocor)
	emailAddr = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
)

func LoadSignatures() []Signature {
	return []Signature{
		{Name: "AWS Access Key", Description: "CRITICAL: Cloud Infrastructure Access", Pattern: awsAccessKey},
		{Name: "Google API Key", Description: "Medium: API Quota / Maps Key", Pattern: googleApiKey},
		{Name: "Generic Secret", Description: "High: Hardcoded Password/Secret", Pattern: genericSecret},

		// New Rules
		{Name: "Internal IP Address", Description: "Low: Internal Network Disclosure", Pattern: internalIP},
		{Name: "AWS S3 Bucket", Description: "Medium: Potential Sensitive File Storage", Pattern: s3Bucket},
		{Name: "Dangerous JS Sink", Description: "High: Potential DOM-based XSS Vulnerability", Pattern: dangerousJS},
		{Name: "Dev Comment", Description: "Info: Leaked Developer Notes (TODO/FIXME)", Pattern: devComments},
		{Name: "JWT/Auth Token", Description: "High: Leaked Authentication Token", Pattern: jwtToken},
		{Name: "Email Address", Description: "Info: Leaked Email Address", Pattern: emailAddr},
	}
}
