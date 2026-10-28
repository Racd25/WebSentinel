package headers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"websentinel/internal/audit"
)

// Check audita los headers de seguridad HTTP de un sitio vía HTTPS.
func Check(host string) []audit.Finding {
	var findings []audit.Finding

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err != nil {
		return []audit.Finding{{
			Category: "Headers", Severity: "MEDIUM",
			Title: "Error construyendo petición HTTPS", Detail: err.Error(),
			Recommendation: "Verifica el hostname.",
		}}
	}
	req.Header.Set("User-Agent", "WebSentinel/1.0 (Security Auditor)")

	resp, err := client.Do(req)
	if err != nil {
		return []audit.Finding{{
			Category: "Headers", Severity: "HIGH",
			Title: "No se pudo conectar vía HTTPS", Detail: err.Error(),
			Recommendation: "Verifica que el sitio acepte conexiones HTTPS.",
		}}
	}
	defer resp.Body.Close()

	// 1) HSTS
	findings = append(findings, checkHSTS(resp.Header)...)

	// 2) CSP
	findings = append(findings, checkCSP(resp.Header)...)

	// 3) X-Frame-Options
	findings = append(findings, checkXFrameOptions(resp.Header)...)

	// 4) X-Content-Type-Options
	if v := resp.Header.Get("X-Content-Type-Options"); !strings.EqualFold(v, "nosniff") {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "MEDIUM",
			Title:          "Falta X-Content-Type-Options: nosniff",
			Detail:         "El navegador podría interpretar archivos con MIME incorrecto.",
			Recommendation: "Agrega: X-Content-Type-Options: nosniff",
		})
	}

	// 5) Referrer-Policy
	if v := resp.Header.Get("Referrer-Policy"); v == "" {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "MEDIUM",
			Title:          "Falta Referrer-Policy",
			Detail:         "El navegador envía la URL completa al navegar a otros sitios.",
			Recommendation: "Agrega: Referrer-Policy: strict-origin-when-cross-origin",
		})
	}

	// 6) Permissions-Policy
	if v := resp.Header.Get("Permissions-Policy"); v == "" {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "LOW",
			Title:          "Falta Permissions-Policy",
			Detail:         "No se restringe acceso a APIs sensibles del navegador (cámara, micro, geolocalización).",
			Recommendation: "Agrega: Permissions-Policy: camera=(), microphone=(), geolocation=()",
		})
	}

	return findings
}

// checkHSTS audita el header Strict-Transport-Security.
func checkHSTS(h http.Header) []audit.Finding {
	var findings []audit.Finding
	hsts := h.Get("Strict-Transport-Security")

	if hsts == "" {
		return append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "HIGH",
			Title:          "Falta Strict-Transport-Security (HSTS)",
			Detail:         "El navegador no forzará HTTPS en visitas futuras.",
			Recommendation: "Agrega: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		})
	}

	// Parsear max-age
	parts := strings.Split(hsts, ";")
	maxAge := 0
	hasIncludeSub := false
	hasPreload := false

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "max-age=") {
			if v, err := strconv.Atoi(strings.TrimPrefix(p, "max-age=")); err == nil {
				maxAge = v
			}
		}
		if strings.EqualFold(p, "includeSubDomains") {
			hasIncludeSub = true
		}
		if strings.EqualFold(p, "preload") {
			hasPreload = true
		}
	}

	if maxAge < 15768000 { // menos de 6 meses
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "MEDIUM",
			Title:          fmt.Sprintf("HSTS max-age demasiado corto: %d segundos", maxAge),
			Detail:         "Se recomienda mínimo 6 meses (15768000s), idealmente 1 año (31536000s).",
			Recommendation: "Aumenta max-age a 31536000.",
		})
	}
	if !hasIncludeSub {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "LOW",
			Title:          "HSTS sin includeSubDomains",
			Detail:         "Subdominios no están protegidos por HSTS.",
			Recommendation: "Agrega includeSubDomains al header HSTS.",
		})
	}
	if !hasPreload {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "LOW",
			Title:          "HSTS sin preload",
			Detail:         "El sitio no está en la lista HSTS precargada de los navegadores.",
			Recommendation: "Agrega preload y registra en hstspreload.org (requiere includeSubDomains).",
		})
	}

	return findings
}

// checkCSP audita el header Content-Security-Policy.
func checkCSP(h http.Header) []audit.Finding {
	var findings []audit.Finding
	csp := h.Get("Content-Security-Policy")

	if csp == "" {
		return append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "HIGH",
			Title:          "Falta Content-Security-Policy (CSP)",
			Detail:         "Sin CSP, un atacante que inyecte JavaScript malicioso (XSS) puede robar datos.",
			Recommendation: "Agrega: Content-Security-Policy: default-src 'self'; script-src 'self'",
		})
	}

	// Detectar configuraciones peligrosas
	lower := strings.ToLower(csp)
	if strings.Contains(lower, "'unsafe-inline'") {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "MEDIUM",
			Title:          "CSP permite unsafe-inline",
			Detail:         "Scripts inline pueden ejecutarse; esto debilita la protección XSS.",
			Recommendation: "Mueve scripts inline a archivos externos o usa nonces/hashes.",
		})
	}
	if strings.Contains(lower, "'unsafe-eval'") {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "MEDIUM",
			Title:          "CSP permite unsafe-eval",
			Detail:         "Permite evaluar código dinámico (eval(), new Function()); alto riesgo.",
			Recommendation: "Evita uso de eval(); si es necesario, usa CSP con nonces estrictos.",
		})
	}
	if strings.Contains(lower, "data:") {
		findings = append(findings, audit.Finding{
			Category:       "Headers",
			Severity:       "LOW",
			Title:          "CSP permite data: URLs",
			Detail:         "Puede ser usado para evadir CSP en ataques XSS sofisticados.",
			Recommendation: "Restringe data: solo a tipos necesarios (ej: data: image/*).",
		})
	}

	return findings
}

// checkXFrameOptions audita el header X-Frame-Options.
func checkXFrameOptions(h http.Header) []audit.Finding {
	v := h.Get("X-Frame-Options")
	if v == "" {
		return []audit.Finding{{
			Category:       "Headers",
			Severity:       "HIGH",
			Title:          "Falta X-Frame-Options",
			Detail:         "El sitio puede ser embebido en iframes maliciosos (clickjacking).",
			Recommendation: "Agrega: X-Frame-Options: DENY (o SAMEORIGIN si necesitas iframes internos).",
		}}
	}
	upper := strings.ToUpper(v)
	if upper != "DENY" && upper != "SAMEORIGIN" {
		return []audit.Finding{{
			Category:       "Headers",
			Severity:       "MEDIUM",
			Title:          fmt.Sprintf("X-Frame-Options con valor no estándar: %s", v),
			Detail:         "Solo DENY y SAMEORIGIN son valores ampliamente respetados.",
			Recommendation: "Usa DENY o SAMEORIGIN.",
		}}
	}
	return nil
}
