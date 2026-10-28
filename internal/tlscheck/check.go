package tlscheck

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"websentinel/internal/audit"
)

// Check audita la configuración TLS del host (puerto 443 por defecto).
func Check(host string) []audit.Finding {
	var findings []audit.Finding

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// Conexión "sin juzgar": queremos VER el cert aunque sea inválido
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return append(findings, audit.Finding{
			Category:       "TLS",
			Severity:       "CRITICAL",
			Title:          "Sin HTTPS: el sitio no acepta conexiones TLS",
			Detail:         err.Error(),
			Recommendation: "Habilita HTTPS con certificado válido (Let's Encrypt) y redirige todo el tráfico HTTP.",
		})
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// 1) Versión del protocolo
	switch {
	case state.Version < tls.VersionTLS12:
		findings = append(findings, audit.Finding{
			Category:       "TLS",
			Severity:       "CRITICAL",
			Title:          fmt.Sprintf("Versión de TLS obsoleta: %s", versionName(state.Version)),
			Detail:         "TLS 1.0/1.1 tienen vulnerabilidades conocidas (BEAST, POODLE).",
			Recommendation: "Deshabilita TLS 1.0/1.1; exige TLS 1.2+ en el servidor o CDN.",
		})
	case state.Version == tls.VersionTLS12:
		findings = append(findings, audit.Finding{
			Category:       "TLS",
			Severity:       "LOW",
			Title:          "TLS 1.2 en uso (correcto, pero TLS 1.3 está disponible)",
			Detail:         versionName(state.Version),
			Recommendation: "Habilita TLS 1.3 si el servidor/CDN lo soporta: menos round-trips y cifrado más moderno.",
		})
	case state.Version == tls.VersionTLS13:
		// TLS 1.3 es perfecto, no reportamos nada
	}

	// 2) Certificado: expiración, cadena y cifrado
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)

		switch {
		case days < 0:
			findings = append(findings, audit.Finding{
				Category:       "TLS",
				Severity:       "CRITICAL",
				Title:          fmt.Sprintf("Certificado EXPIRADO hace %d días", -days),
				Detail:         fmt.Sprintf("Emisor: %s · Sujeto: %s", cert.Issuer.CommonName, cert.Subject.CommonName),
				Recommendation: "Renueva el certificado ya; automatiza con ACME (Let's Encrypt).",
			})
		case days < 14:
			findings = append(findings, audit.Finding{
				Category:       "TLS",
				Severity:       "HIGH",
				Title:          fmt.Sprintf("Certificado por vencer en %d días", days),
				Detail:         fmt.Sprintf("Expira: %s", cert.NotAfter.Format("2006-01-02")),
				Recommendation: "Renueva antes del vencimiento y configura monitoreo de expiración.",
			})
		case days < 30:
			findings = append(findings, audit.Finding{
				Category:       "TLS",
				Severity:       "MEDIUM",
				Title:          fmt.Sprintf("Certificado por vencer en %d días", days),
				Detail:         fmt.Sprintf("Expira: %s", cert.NotAfter.Format("2006-01-02")),
				Recommendation: "Planifica la renovación del certificado.",
			})
		}

		// Cadena confiable: leaf + intermediarios contra las raíces del sistema
		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		if _, verr := cert.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates}); verr != nil {
			findings = append(findings, audit.Finding{
				Category:       "TLS",
				Severity:       "HIGH",
				Title:          "Cadena de certificado no confiable o dominio no cubierto",
				Detail:         verr.Error(),
				Recommendation: "Usa un certificado de CA pública válida que cubra el dominio (SAN).",
			})
		}
	}

	// 3) Suite criptográfica débil
	cipher := tls.CipherSuiteName(state.CipherSuite)
	for _, weak := range []string{"RC4", "3DES", "MD5", "EXPORT", "NULL"} {
		if strings.Contains(strings.ToUpper(cipher), weak) {
			findings = append(findings, audit.Finding{
				Category:       "TLS",
				Severity:       "HIGH",
				Title:          fmt.Sprintf("Suite criptográfica débil: %s", cipher),
				Detail:         "Algoritmos con vulnerabilidades prácticas conocidas.",
				Recommendation: "Restringe el servidor a suites modernas (AES-GCM / CHACHA20 con TLS 1.2+).",
			})
			break
		}
	}

	// 4) Redirección HTTP → HTTPS
	findings = append(findings, checkRedirect(host)...)

	return findings
}

// checkRedirect observa el 301 de HTTP sin seguirlo.
func checkRedirect(host string) []audit.Finding {
	client := &http.Client{
		Timeout: 15 * time.Second, // aumentado de 10s
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // detenerse: solo observar
		},
	}

	// Construir URL correctamente
	url := "http://" + host + "/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []audit.Finding{{
			Category:       "TLS",
			Severity:       "MEDIUM",
			Title:          "Error construyendo petición HTTP",
			Detail:         err.Error(),
			Recommendation: "Verifica que el hostname sea válido.",
		}}
	}

	// Agregar User-Agent para evitar bloqueos
	req.Header.Set("User-Agent", "WebSentinel/1.0 (Security Auditor)")

	resp, err := client.Do(req)
	if err != nil {
		// Timeout o error de conexión = probablemente no hay HTTP
		return []audit.Finding{{
			Category:       "TLS",
			Severity:       "LOW",
			Title:          "Puerto 80 no responde o timeout",
			Detail:         err.Error(),
			Recommendation: "Verifica si el sitio tiene puerto HTTP abierto; si no, considera habilitar redirect HTTP→HTTPS.",
		}}
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(loc, "https://") {
		return nil // PASS ✔
	}
	return []audit.Finding{{
		Category:       "TLS",
		Severity:       "HIGH",
		Title:          fmt.Sprintf("HTTP no redirige a HTTPS (status %d)", resp.StatusCode),
		Detail:         "Quien entre por http:// quedaría en tráfico sin cifrar.",
		Recommendation: "Agrega redirect 301 permanente HTTP → HTTPS (en Vercel/Cloudflare es una línea).",
	}}
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
