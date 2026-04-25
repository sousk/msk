package masker

import "testing"

func TestMask(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "anthropic key",
			input: "key=sk-ant-" + "api03-abc123def456ghi789jkl",
			want:  "key=<REDACTED_ANTHROPIC_KEY>",
		},
		{
			name:  "openai key (48 chars)",
			input: "sk-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
			want:  "<REDACTED_OPENAI_KEY>",
		},
		{
			name:  "github token",
			input: "token ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			want:  "token <REDACTED_GITHUB_TOKEN>",
		},
		{
			name:  "slack token",
			input: "slack: xoxb-" + "123456789-abcdefghij",
			want:  "slack: <REDACTED_SLACK_TOKEN>",
		},
		{
			name:  "npm token",
			input: "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			want:  "<REDACTED_NPM_TOKEN>",
		},
		{
			name:  "jwt",
			input: "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			want:  "auth: <REDACTED_JWT>",
		},
		{
			name:  "bearer header",
			input: "Authorization: Bearer mytoken123abc",
			want:  "Authorization: Bearer <REDACTED_TOKEN>",
		},
		{
			name:  "aws access key",
			input: "AKIA" + "1234567890ABCDEF",
			want:  "<REDACTED_AWS_KEY>",
		},
		{
			name:  "aws secret key contextual",
			input: "AWS_SECRET_ACCESS_KEY=" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ABcd",
			want:  "AWS_SECRET_ACCESS_KEY=<REDACTED_AWS_SECRET>",
		},
		{
			name:  "stripe key",
			input: "sk_live_" + "ABCDEFGHIJKLMNOPabcdefgh",
			want:  "<REDACTED_STRIPE_KEY>",
		},
		{
			name:  "db url password",
			input: "postgres://user:mysecret@localhost:5432/db",
			want:  "postgres://user:<REDACTED_PASSWORD>@localhost:5432/db",
		},
		{
			name:  "api key header",
			input: "x-api-key: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			want:  "x-api-key: <REDACTED_API_KEY>",
		},
		{
			name:  "generic api_key assignment",
			input: "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			want:  "api_key=<REDACTED_API_KEY>",
		},
		{
			name:  "password assignment",
			input: "password=hunter2",
			want:  "password=<REDACTED_PASSWORD>",
		},
		{
			name:  "url with sensitive query param",
			input: "https://example.com/callback?token=abc123&foo=bar",
			want:  "https://example.com/callback?token=<REDACTED_URL_PARAM>&foo=bar",
		},
		{
			name:  "url with embedded credentials",
			input: "redis://user:pass@localhost:6379",
			want:  "redis://user:<REDACTED_PASSWORD>@localhost:6379",
		},
		{
			name:  "plain text passes through",
			input: "hello world 2026",
			want:  "hello world 2026",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Mask(tc.input)
			if got != tc.want {
				t.Errorf("Mask(%q)\n got  %q\n want %q", tc.input, got, tc.want)
			}
		})
	}
}
