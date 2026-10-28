package audit

import "sort"

// Finding es un hallazgo de la auditoría web.
type Finding struct {
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

var severityOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

// SortBySeverity ordena hallazgos de mayor a menor severidad.
func SortBySeverity(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})
}
