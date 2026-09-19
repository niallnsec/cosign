// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/internal/ui"
)

func TestWarnIfIgnoringTlogWithTimestamp(t *testing.T) {
	stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
		warnIfIgnoringTlog(ctx, "signature", true)
	})

	for _, expected := range []string{
		"Transparency log verification is disabled for this signature",
		"A trusted RFC 3161 timestamp is required to establish signing time",
		"it does not provide Rekor transparency or auditability",
	} {
		if !strings.Contains(stderr, expected) {
			t.Fatalf("expected warning to contain %q, got %q", expected, stderr)
		}
	}
}

func TestWarnIfIgnoringTlogWithoutTimestamp(t *testing.T) {
	stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
		warnIfIgnoringTlog(ctx, "signature", false)
	})

	if !strings.Contains(stderr, "no Rekor transparency or auditability check will be performed") {
		t.Fatalf("expected warning to explain the omitted check, got %q", stderr)
	}
	if strings.Contains(stderr, "RFC 3161") {
		t.Fatalf("did not expect timestamp claim, got %q", stderr)
	}
}
