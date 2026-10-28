package exposure

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"websentinel/internal/audit"
)

// Rutas que nunca deberían ser públicas.
var sensitivePaths = []string{
	"/.git/HEAD",
	"/.env",
	"/.svn/entries",
	"/.DS_Store",
	"/backup.zip",
	"/config.php",
	"/phpinfo.php",
	"/server-status",
	"/web.config",
	"/wp-config.php.bak",
}

var pathSeverity = map[string]string{
	"/.git/HEAD":         "HIGH",
	"/.env":              "HIGH",
	"/backup.zip":        "HIGH",
	"/wp-config.php.bak": "HIGH",
	"/.DS_Store":         "LOW",
}

// Check audita fugas de información: headers reveladores y rutas expuestas.
func Check(host string) []audit.Finding {
	var findings []audit.Finding
	client := &http.Client{Timeout: 10 * time.Second}

	// 1) Headers que revelan tecnología
	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err == nil {
		req.Header.Set("User-Agent", "WebSentinel/1.0 (Security Auditor)")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			if sv := resp.Header.Get("Server"); sv != "" {
				findings = append(findings, audit.Finding{
					Category:       "Exposure",
					Severity:       "LOW",
					Title:          fmt.Sprintf("El header Server revela software: %s", sv),
					Detail:         "La versión publicada ayuda a elegir exploits conocidos.",
					Recommendation: "Elimina o generaliza el header Server en el servidor/CDN.",
				})
			}
			if xp := resp.Header.Get("X-Powered-By"); xp != "" {
				findings = append(findings, audit.Finding{
					Category:       "Exposure",
					Severity:       "LOW",
					Title:          fmt.Sprintf("Header X-Powered-By presente: %s", xp),
					Detail:         "Revela el stack de backend.",
					Recommendation: "Elimina el header X-Powered-By.",
				})
			}
		}
	}

	// 2) Control soft-404: comportamiento "normal" del sitio
	control := fmt.Sprintf("/websentinel-control-%d", rand.Intn(1000000))
	if resp, err := client.Get("https://" + host + control); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return append(findings, audit.Finding{
				Category:       "Exposure",
				Severity:       "INFO",
				Title:          "Soft-404 detectado: el sitio responde 200 a rutas inexistentes (chequeo de rutas omitido)",
				Detail:         "Típico de SPAs (React/Vue); sin este control habría falsos positivos.",
				Recommendation: "Configura 404 reales para rutas desconocidas si es posible.",
			})
		}
	}

	// 3) Barrido concurrente de rutas sensibles (goroutines + WaitGroup + channel)
	type result struct {
		path   string
		status int
	}
	results := make(chan result, len(sensitivePaths))
	var wg sync.WaitGroup

	for _, p := range sensitivePaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			resp, err := client.Get("https://" + host + path)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			results <- result{path: path, status: resp.StatusCode}
		}(p)
	}

	wg.Wait()
	close(results)

	for r := range results {
		if r.status == http.StatusOK {
			sev, ok := pathSeverity[r.path]
			if !ok {
				sev = "MEDIUM"
			}
			findings = append(findings, audit.Finding{
				Category:       "Exposure",
				Severity:       sev,
				Title:          fmt.Sprintf("Recurso sensible expuesto públicamente: %s", r.path),
				Detail:         fmt.Sprintf("HTTP %d: el recurso es accesible sin autenticación.", r.status),
				Recommendation: recommendationFor(r.path),
			})
		}
	}

	return findings
}

func recommendationFor(path string) string {
	switch path {
	case "/.git/HEAD", "/.svn/entries":
		return "Elimina el directorio de control de versiones del web root; despliega solo artefactos de build."
	case "/.env", "/config.php", "/wp-config.php.bak":
		return "Elimina el archivo del web root; los secretos viven en variables de entorno, nunca en archivos servidos."
	default:
		return "Bloquea el acceso público a este recurso en el servidor o CDN (regla de WAF o location deny)."
	}
}
