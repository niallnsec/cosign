// Copyright 2026 The Sigstore Authors
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

package options

import "testing"

func TestCertificateChainOnlyIdentities(t *testing.T) {
	options := CertVerifyOptions{CertificateChainOnly: true}

	identities, err := options.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 0 {
		t.Fatalf("expected no identities, got %d", len(identities))
	}
}

func TestCertificateChainOnlyRejectsIdentityConstraints(t *testing.T) {
	options := CertVerifyOptions{
		CertificateChainOnly: true,
		CertIdentity:         "signer@example.com",
	}

	if _, err := options.Identities(); err == nil {
		t.Fatal("expected certificate identity constraint to be rejected")
	}
}
