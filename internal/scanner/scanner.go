package scanner

import (
	"math"
	"strings"

	"github.com/DrajatAkbarr/js-hunter/pkg/models"
	"github.com/DrajatAkbarr/js-hunter/pkg/signatures"
)

// LoadedSignatures di-cache agar tidak dimuat berulang kali
var loadedSignatures = signatures.LoadSignatures()

// ScanContent menganalisis byte content terhadap pola regex dengan FILTER CERDAS
func ScanContent(jsFileURL string, content []byte) []models.Finding {
	var findings []models.Finding
	contentStr := string(content)

	for _, sig := range loadedSignatures {
		// FindAllString mencari semua kecocokan
		matches := sig.Pattern.FindAllString(contentStr, -1)

		for _, match := range matches {
			// --- LEVEL 1: NOISE FILTER (Whitelisting) ---
			// Abaikan fungsi bawaan JS yang sering muncul tapi tidak berbahaya
			if isFalsePositive(match) {
				continue
			}

			// --- LEVEL 2: ENTROPY CHECK (Optional but recommended) ---
			// Jika deskripsinya "Generic Secret", kita cek apakah string-nya cukup "acak"
			// Ini untuk menghindari false positive seperti: api_key = "placeholder"
			if strings.Contains(sig.Name, "Generic") {
				if calculateShannonEntropy(match) < 2.5 {
					continue // Abaikan jika terlalu teratur (seperti kata-kata biasa)
				}
			}

			findings = append(findings, models.Finding{
				SourceFile:  jsFileURL,
				Description: sig.Description,
				Match:       match,
			})
		}
	}

	return findings
}

// isFalsePositive mendeteksi keyword yang sering jadi sampah
func isFalsePositive(match string) bool {
	lower := strings.ToLower(match)

	// Daftar kata yang "haram" dilaporkan karena terlalu umum
	noiseKeywords := []string{
		"settimeout", "setinterval", "innerhtml",
		"function", "return", "var ", "const ", "let ",
		"jquery", "node_modules", "react",
	}

	for _, noise := range noiseKeywords {
		if strings.Contains(lower, noise) {
			return true
		}
	}
	return false
}

// calculateShannonEntropy menghitung tingkat keacakan string
// Semakin tinggi nilainya, semakin acak string tersebut (ciri khas Password/Key)
func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	frequencies := make(map[rune]float64)
	for _, char := range s {
		frequencies[char]++
	}

	var entropy float64
	for _, count := range frequencies {
		p := count / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}
