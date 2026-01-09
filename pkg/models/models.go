package models

type Finding struct {
	SourceFile  string `json:"source_file"`
	Description string `json:"description"`
	Match       string `json:"match"`
}
