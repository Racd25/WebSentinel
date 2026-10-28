package cookies

import (
	"fmt"
	"net/http"
	"time"

	"websentinel/internal/audit"
)

// Check audita los flags de las cookies que el sitio define.
func Check(host string) []audit.Finding {
	var findings []audit.Finding

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "WebSentinel/1.0 (Security Auditor)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return nil // el sitio no define cookies en la portada: nada que auditar
	}

	for _, c := range cookies {
		if !c.Secure {
			findings = append(findings, audit.Finding{
				Category:       "Cookies",
				Severity:       "HIGH",
				Title:          fmt.Sprintf("Cookie sin flag Secure: %s", c.Name),
				Detail:         "La cookie podría enviarse por conexiones HTTP sin cifrar.",
				Recommendation: "Define todas las cookies con el atributo Secure (obligatorio en cookies de sesión).",
			})
		}
		if !c.HttpOnly {
			findings = append(findings, audit.Finding{
				Category:       "Cookies",
				Severity:       "MEDIUM",
				Title:          fmt.Sprintf("Cookie sin flag HttpOnly: %s", c.Name),
				Detail:         "JavaScript puede leerla; un XSS permitiría robar la sesión.",
				Recommendation: "Define HttpOnly en toda cookie que no necesite leerse desde JS.",
			})
		}
		if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode {
			findings = append(findings, audit.Finding{
				Category:       "Cookies",
				Severity:       "MEDIUM",
				Title:          fmt.Sprintf("Cookie sin SameSite estricto: %s", c.Name),
				Detail:         "SameSite ausente o None amplía la superficie de ataques CSRF.",
				Recommendation: "Usa SameSite=Lax (o Strict) salvo necesidad explícita de cross-site.",
			})
		}
	}

	return findings
}
