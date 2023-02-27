// Copyright 2022 The Sigstore Authors.
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

package clusterimagepolicies

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	. "knative.dev/pkg/configmap/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	// Just some public key that was laying around, only format matters.
	inlineKeyData = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J
RCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==
-----END PUBLIC KEY-----`
)

func TestDefaultsConfigurationFromFile(t *testing.T) {
	_, example := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	if _, err := NewImagePoliciesConfigFromConfigMap(example); err != nil {
		t.Error("NewImagePoliciesConfigFromConfigMap(example) =", err)
	}
}

func TestGetAuthorities(t *testing.T) {
	// TODO: Clean up this test to be table-driven with sub-tests, instead of one big test.
	getAuthority := func(t *testing.T, m map[string]webhookcip.ClusterImagePolicy, mp string) webhookcip.Authority {
		t.Helper()
		cip, found := m[mp]
		if !found {
			t.Fatalf("failed to find matching policy %q", mp)
		}
		if len(cip.Authorities) == 0 {
			t.Fatalf("no authorities for matching policy %q", mp)
		}
		return cip.Authorities[0]
	}

	_, example := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	defaults, err := NewImagePoliciesConfigFromConfigMap(example)
	if err != nil {
		t.Error("NewImagePoliciesConfigFromConfigMap(example) =", err)
	}
	c, err := defaults.GetMatchingPolicies("rando", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	matchedPolicy := "cluster-image-policy-0"
	want := inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Make sure UID and ResourceVersion are unserialized properly
	checkUIDAndResourceVersion(t, matchedPolicy, c[matchedPolicy])
	// Make sure glob matches 'randomstuff*'
	c, err = defaults.GetMatchingPolicies("randomstuffhere", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-1"
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Make sure UID and ResourceVersion are unserialized properly
	checkUIDAndResourceVersion(t, matchedPolicy, c[matchedPolicy])
	c, err = defaults.GetMatchingPolicies("rando3", "Pod", "v1", map[string]string{})
	matchedPolicy = "cluster-image-policy-2"
	checkGetMatches(t, c, err)
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Keyless.CACert.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	wantInsecureIgnoreSCT := true
	if got := getAuthority(t, c, matchedPolicy).Keyless.InsecureIgnoreSCT; *got != wantInsecureIgnoreSCT {
		t.Errorf("Did not get what I wanted %v, got %+v", wantInsecureIgnoreSCT, got)
	}
	want = "issuer"
	if got := getAuthority(t, c, matchedPolicy).Keyless.Identities[0].Issuer; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "subject"
	if got := getAuthority(t, c, matchedPolicy).Keyless.Identities[0].Subject; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "trustroot-tsa-ref"
	got := getAuthority(t, c, matchedPolicy)
	if got.RFC3161Timestamp.TrustRootRef != want {
		t.Errorf("Did not get the tsa what I wanted %q, got %+v", want, got)
	}
	// Make sure UID and ResourceVersion are unserialized properly
	checkUIDAndResourceVersion(t, matchedPolicy, c[matchedPolicy])

	// Make sure regex matches "regexstring*"
	c, err = defaults.GetMatchingPolicies("regexstringstuff", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-4"
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	checkPublicKey(t, getAuthority(t, c, matchedPolicy).Key.PublicKeys[0])
	// Make sure UID and ResourceVersion are unserialized properly
	checkUIDAndResourceVersion(t, matchedPolicy, c[matchedPolicy])

	// Test multiline yaml cert
	c, err = defaults.GetMatchingPolicies("inlinecert", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-3"
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	checkPublicKey(t, getAuthority(t, c, matchedPolicy).Key.PublicKeys[0])

	// Test multiline cert but json encoded
	c, err = defaults.GetMatchingPolicies("ghcr.io/example/foo", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	matchedPolicy = "cluster-image-policy-json"
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	checkPublicKey(t, getAuthority(t, c, matchedPolicy).Key.PublicKeys[0])

	// Test multiple matches
	c, err = defaults.GetMatchingPolicies("regexstringtoo", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	if len(c) != 2 {
		t.Errorf("Wanted two matches, got %d", len(c))
	}
	matchedPolicy = "cluster-image-policy-4"
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	checkPublicKey(t, getAuthority(t, c, matchedPolicy).Key.PublicKeys[0])

	matchedPolicy = "cluster-image-policy-5"
	want = inlineKeyData
	if got := getAuthority(t, c, matchedPolicy).Key.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}

	// Test attestations + top level policy
	c, err = defaults.GetMatchingPolicies("withattestations", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	if len(c) != 1 {
		t.Errorf("Wanted 1 match, got %d", len(c))
	}
	matchedPolicy = "cluster-image-policy-with-policy-attestations"
	want = "attestation-0"
	if got := getAuthority(t, c, matchedPolicy).Name; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	// Both top & authority policy is using cue
	want = "cue"
	if got := c[matchedPolicy].Policy.Type; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "cip level cue here"
	if got := c[matchedPolicy].Policy.Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "cue"
	if got := getAuthority(t, c, matchedPolicy).Attestations[0].Type; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}
	want = "test-cue-here"
	if got := getAuthority(t, c, matchedPolicy).Attestations[0].Data; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}

	// Test source oci
	matchedPolicy = "cluster-image-policy-source-oci"
	c, err = defaults.GetMatchingPolicies("sourceocionly", "Pod", "v1", map[string]string{})
	checkGetMatches(t, c, err)
	if len(c) != 1 {
		t.Errorf("Wanted 1 match, got %d", len(c))
	}

	checkSourceOCI(t, c[matchedPolicy].Authorities)
	want = "example.registry.com/alternative/signature"
	if got := getAuthority(t, c, matchedPolicy).Sources[0].OCI; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}

	// Test source signaturePullSecrets
	matchedPolicy = "cluster-image-policy-source-oci-signature-pull-secrets"
	c, err = defaults.GetMatchingPolicies("sourceocisignaturepullsecrets", "Pod", "v1", map[string]string{"match": "match"})
	checkGetMatches(t, c, err)
	if len(c) != 1 {
		t.Errorf("Wanted 1 match, got %d", len(c))
	}

	checkSourceOCI(t, c[matchedPolicy].Authorities)
	if got := len(getAuthority(t, c, matchedPolicy).Sources[0].SignaturePullSecrets); got != 1 {
		t.Errorf("Did not get what I wanted %d, got %d", 1, got)
	}
	want = "examplePullSecret"
	if got := getAuthority(t, c, matchedPolicy).Sources[0].SignaturePullSecrets[0].Name; got != want {
		t.Errorf("Did not get what I wanted %q, got %+v", want, got)
	}

	// Test resource matching
	c, err = defaults.GetMatchingPolicies("match-pods", "Pod", "v1", map[string]string{"match": "match"})
	checkGetMatches(t, c, err)
	if len(c) != 1 {
		t.Errorf("Wanted 1 match, got %d", len(c))
	}
	c, err = defaults.GetMatchingPolicies("match-pods", "Pod", "apps/v1", map[string]string{"match": "match"})
	if err != nil {
		t.Fatalf("GetMatchingPolicies() = %v", err)
	}
	if len(c) != 0 {
		t.Errorf("Wanted 0 matches, got %d", len(c))
	}
	c, err = defaults.GetMatchingPolicies("match-pods", "Pod", "blah/v1alpha1", map[string]string{"match": "match"})
	if err != nil {
		t.Fatalf("GetMatchingPolicies() = %v", err)
	}
	if len(c) != 0 {
		t.Errorf("Wanted 0 matches, got %d", len(c))
	}
}

func TestFailsToLoadInvalid(t *testing.T) {
	wantErr := "failed to parse the entry \"cluster-image-policy-0\""
	_, example := ConfigMapsFromTestFile(t, "config-invalid-image-policy")
	_, err := NewImagePoliciesConfigFromConfigMap(example)
	if err == nil {
		t.Error("Did not fail with invalid configmap")
	} else if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("Unexpected error, wanted to contain %s : got %v", wantErr, err)
	}
}

func checkGetMatches(t *testing.T, c map[string]webhookcip.ClusterImagePolicy, err error) {
	t.Helper()
	if err != nil {
		t.Error("GetMatches Failed =", err)
	}
	if len(c) == 0 {
		t.Error("Wanted a config, got none.")
	}
	for _, v := range c {
		if v.Authorities != nil || len(v.Authorities) > 0 {
			return
		}
	}
	t.Error("Wanted a config and non-zero authorities, got no authorities")
}

func checkPublicKey(t *testing.T, gotKey crypto.PublicKey) {
	t.Helper()

	derBytes, err := x509.MarshalPKIXPublicKey(gotKey)
	if err != nil {
		t.Error("Failed to Marshal Key =", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	// pem.EncodeToMemory has an extra newline at the end
	got := strings.TrimSuffix(string(pemBytes), "\n")
	if got != inlineKeyData {
		t.Errorf("Did not get what I wanted %s, got %s", inlineKeyData, string(pemBytes))
	}
}

func checkSourceOCI(t *testing.T, authority []webhookcip.Authority) {
	t.Helper()

	if got := len(authority); got != 1 {
		t.Errorf("Did not get what I wanted %d, got %d", 1, got)
	}
	if got := len(authority[0].Sources); got != 1 {
		t.Errorf("Did not get what I wanted %d, got %d", 1, got)
	}

	want := len(authority[0].Sources)
	if got := len(authority[0].RemoteOpts); got != want {
		t.Errorf("Did not get what I wanted %d, got %d", want, got)
	}
}

func checkUIDAndResourceVersion(t *testing.T, cipName string, cip webhookcip.ClusterImagePolicy) {
	t.Helper()
	wantUID := fmt.Sprintf("%s-uid", cipName)
	if wantUID != string(cip.UID) {
		t.Errorf("UID mismatch want: %s got: %s", wantUID, cip.UID)
	}
	wantResourceVersion := fmt.Sprintf("%s-resource-version", cipName)
	if wantResourceVersion != cip.ResourceVersion {
		t.Errorf("UID mismatch want: %s got: %s", wantResourceVersion, cip.ResourceVersion)
	}
}
