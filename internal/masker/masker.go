package masker

import (
	"regexp"
	"strings"
)

type rule struct {
	re   *regexp.Regexp
	tmpl string        // replacement template using ${1}, ${2} etc.; used when fn is nil
	fn   func(string) string // custom replacement; takes precedence over tmpl
}

func (r rule) apply(s string) string {
	if r.fn != nil {
		return r.re.ReplaceAllStringFunc(s, r.fn)
	}
	return r.re.ReplaceAllString(s, r.tmpl)
}

var sensitiveQueryParams = map[string]bool{
	"access_token":  true,
	"token":         true,
	"id_token":      true,
	"refresh_token": true,
	"auth":          true,
	"authorization": true,
	"api_key":       true,
	"apikey":        true,
	"api-key":       true,
	"key":           true,
	"secret":        true,
	"password":      true,
	"passwd":        true,
	"signature":     true,
	"sig":           true,
	"session":       true,
}

func redactSegment(seg string) string {
	if len(seg) < 2 || !strings.Contains(seg, "=") {
		return seg
	}
	prefix := string(seg[0])
	parts := strings.Split(seg[1:], "&")
	for i, p := range parts {
		eq := strings.Index(p, "=")
		if eq == -1 || eq == len(p)-1 {
			continue
		}
		key := p[:eq]
		if sensitiveQueryParams[strings.ToLower(strings.TrimSpace(key))] {
			parts[i] = key + "=<REDACTED_URL_PARAM>"
		}
	}
	return prefix + strings.Join(parts, "&")
}

func redactURL(raw string) string {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd == -1 {
		return raw
	}
	scheme := raw[:schemeEnd+3]
	rest := raw[schemeEnd+3:]

	authorityEnd := len(rest)
	for i, c := range rest {
		if c == '/' || c == '?' || c == '#' {
			authorityEnd = i
			break
		}
	}
	authority := rest[:authorityEnd]
	tail := rest[authorityEnd:]

	if at := strings.LastIndex(authority, "@"); at != -1 {
		userinfo := authority[:at]
		host := authority[at+1:]
		if colon := strings.Index(userinfo, ":"); colon != -1 {
			authority = userinfo[:colon] + ":<REDACTED_PASSWORD>@" + host
		} else {
			authority = "<REDACTED_PASSWORD>@" + host
		}
	}

	qIdx := strings.Index(tail, "?")
	hIdx := strings.Index(tail, "#")
	switch {
	case qIdx != -1 && (hIdx == -1 || qIdx < hIdx):
		before := tail[:qIdx]
		after := tail[qIdx:]
		if h := strings.Index(after, "#"); h == -1 {
			tail = before + redactSegment(after)
		} else {
			tail = before + redactSegment(after[:h]) + redactSegment(after[h:])
		}
	case hIdx != -1:
		tail = tail[:hIdx] + redactSegment(tail[hIdx:])
	}

	return scheme + authority + tail
}

var rules []rule

func init() {
	rules = []rule{
		// Private key blocks — run first to avoid leaking partial key material.
		{
			re:   regexp.MustCompile(`(?is)-----BEGIN\s+(?:(?:RSA|EC|DSA)\s+)?(?:ENCRYPTED\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:(?:RSA|EC|DSA)\s+)?(?:ENCRYPTED\s+)?PRIVATE\s+KEY-----`),
			tmpl: "<REDACTED_PRIVATE_KEY_BLOCK>",
		},
		{
			re:   regexp.MustCompile(`(?s)-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----`),
			tmpl: "<REDACTED_PRIVATE_KEY_BLOCK>",
		},

		// GitHub
		{re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b`), tmpl: "<REDACTED_GITHUB_TOKEN>"},
		{re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`), tmpl: "<REDACTED_GITHUB_TOKEN>"},

		// Slack
		{re: regexp.MustCompile(`\bxox(?:b|p|a|s|r)-[A-Za-z0-9-]{10,250}\b`), tmpl: "<REDACTED_SLACK_TOKEN>"},
		{re: regexp.MustCompile(`\bxapp-[0-9]-[A-Za-z0-9-]{10,250}\b`), tmpl: "<REDACTED_SLACK_TOKEN>"},

		// NPM
		{re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), tmpl: "<REDACTED_NPM_TOKEN>"},
		{re: regexp.MustCompile(`(?i)(:_authToken\s*=\s*)[^\s\r\n]+`), tmpl: "${1}<REDACTED_NPM_TOKEN>"},

		// PyPI
		{re: regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{85,200}\b`), tmpl: "<REDACTED_PYPI_TOKEN>"},

		// SendGrid
		{re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), tmpl: "<REDACTED_SENDGRID_KEY>"},

		// OpenAI
		{re: regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`), tmpl: "<REDACTED_OPENAI_KEY>"},
		{re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{48}\b`), tmpl: "<REDACTED_OPENAI_KEY>"},

		// Anthropic
		{re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), tmpl: "<REDACTED_ANTHROPIC_KEY>"},

		// JWT
		{re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), tmpl: "<REDACTED_JWT>"},

		// Google OAuth
		{re: regexp.MustCompile(`\bya29\.[A-Za-z0-9._-]+\b`), tmpl: "<REDACTED_OAUTH_TOKEN>"},

		// Bearer token (Authorization header)
		{re: regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._-]+\b`), tmpl: "Bearer <REDACTED_TOKEN>"},

		// AWS
		{re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16,20}\b`), tmpl: "<REDACTED_AWS_KEY>"},
		{
			re:   regexp.MustCompile(`(?i)((?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secretAccessKey|awsSecretAccessKey)\s*[:=]\s*["']?)[A-Za-z0-9\/+=]{40}(["']?)`),
			tmpl: "${1}<REDACTED_AWS_SECRET>${2}",
		},

		// Stripe
		{re: regexp.MustCompile(`\bsk_(?:test|live)_[A-Za-z0-9]{16,}\b`), tmpl: "<REDACTED_STRIPE_KEY>"},

		// DB connection strings
		{
			re:   regexp.MustCompile(`(?i)((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|sqlserver)://[^:\s]+:)[^@\s]+(@)`),
			tmpl: "${1}<REDACTED_PASSWORD>${2}",
		},

		// x-api-key header — must run before the generic api_key rule.
		{re: regexp.MustCompile(`(?i)(["']?x-api-key["']?\s*:\s*["']?)[A-Za-z0-9_\-]{16,}(["']?)`), tmpl: "${1}<REDACTED_API_KEY>${2}"},

		// Generic api_key / api-key / apiKey — handles JSON ("apiKey": "val") and shell (api_key=val).
		{
			re:   regexp.MustCompile(`(?i)(["']?api[_-]?key["']?\s*[:=]\s*["']?)[A-Za-z0-9_\-]{16,}(["']?)`),
			tmpl: "${1}<REDACTED_API_KEY>${2}",
		},

		// Generic token key — catches JSON {"token": "val"} and config token=val.
		{
			re:   regexp.MustCompile(`(?i)(["']?\btoken\b["']?\s*[:=]\s*["']?)[A-Za-z0-9_\-]{16,}(["']?)`),
			tmpl: "${1}<REDACTED_TOKEN>${2}",
		},

		// password= / password: (quoted or unquoted value)
		{
			re:   regexp.MustCompile(`(?i)(["']?password["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,}\]"'][^\s,}\]]*)`),
			tmpl: "${1}<REDACTED_PASSWORD>",
		},

		// URLs — run last; handles embedded credentials and sensitive query params.
		{
			re: regexp.MustCompile(`https?://[^\s]+`),
			fn: func(m string) string { return redactURL(m) },
		},
	}
}

// Mask replaces secrets in input with redaction placeholders.
func Mask(input string) string {
	result := input
	for _, r := range rules {
		result = r.apply(result)
	}
	return result
}
