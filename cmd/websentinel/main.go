package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"websentinel/internal/audit"
	"websentinel/internal/cookies"
	"websentinel/internal/exposure"
	"websentinel/internal/headers"
	"websentinel/internal/report"
	"websentinel/internal/tlscheck"
)

func main() {
	target := flag.String("target", "", "sitio a auditar (ej: example.com o https://example.com)")
	jsonOut := flag.String("json", "websentinel-report.json", "ruta del reporte JSON")
	htmlOut := flag.String("html", "websentinel-report.html", "ruta del reporte HTML")
	flag.Parse()

	if *target == "" {
		fmt.Println("Uso: websentinel -target <sitio>")
		fmt.Println("Flags opcionales: -json <ruta.json> -html <ruta.html>")
		os.Exit(1)
	}

	host := normalize(*target)
	fmt.Printf("WebSentinel — auditoría de postura web\n")
	fmt.Printf("Objetivo: %s\n\n", host)

	var findings []audit.Finding
	findings = append(findings, tlscheck.Check(host)...)
	findings = append(findings, headers.Check(host)...)
	findings = append(findings, cookies.Check(host)...)
	findings = append(findings, exposure.Check(host)...)
	audit.SortBySeverity(findings)

	if len(findings) == 0 {
		fmt.Println("✅ Sin hallazgos TLS: configuración sólida.")
		return
	}

	icons := map[string]string{"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
	for _, f := range findings {
		fmt.Printf("%s %s | [%s] %s\n", icons[f.Severity], f.Severity, f.Category, f.Title)
		if f.Detail != "" {
			fmt.Printf("   Detalle: %s\n", f.Detail)
		}
		fmt.Printf("   → %s\n\n", f.Recommendation)
	}

	// Generar reportes
	rep := report.New(host, findings)

	fmt.Printf("\n================ CALIFICACIÓN ================\n")
	fmt.Printf("Score: %d/100 | Grade: %s\n", rep.Score, rep.Grade)
	fmt.Printf("Resumen: %d CRITICAL · %d HIGH · %d MEDIUM · %d LOW\n",
		rep.Summary["CRITICAL"], rep.Summary["HIGH"], rep.Summary["MEDIUM"], rep.Summary["LOW"])

	if err := report.SaveJSON(rep, *jsonOut); err != nil {
		fmt.Println("Error guardando JSON:", err)
	} else {
		fmt.Printf("\n✅ Reporte JSON guardado en: %s\n", *jsonOut)
	}

	if err := report.SaveHTML(rep, *htmlOut); err != nil {
		fmt.Println("Error guardando HTML:", err)
	} else {
		fmt.Printf("✅ Reporte HTML guardado en: %s\n", *htmlOut)
	}
}

// normalize extrae el host limpio de una URL.
func normalize(t string) string {
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.Index(t, "/"); i >= 0 {
		t = t[:i]
	}
	return t
}
