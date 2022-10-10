package webhook

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVerificationTuple(t *testing.T) {
	verTuple := VerificationTuple{
		Image:           "image@sha256:12345",
		ResourceVersion: "1",
		UID:             "123",
		Warnings:        []error{},
		Errors:          []error{},
		PolicyName:      "my-policy",
	}
	verTuple.AuthorityMatches = map[string]AuthorityMatch{
		"authority-0": {
			Attestations: map[string][]PolicyAttestation{
				"test-att": {{
					PolicySignature: PolicySignature{
						Subject: "https://github.com/distroless/static/.github/workflows/release.yaml@refs/heads/main",
						Issuer:  "https://token.actions.githubusercontent.com",
						GithubExtensions: GithubExtensions{
							WorkflowTrigger: "schedule",
							WorkflowSHA:     "7e7572e578de7c51a2f1a1791f025cf315503aa2",
							WorkflowName:    "Create Release",
							WorkflowRepo:    "distroless/static",
							WorkflowRef:     "refs/heads/main",
						},
					},
					PredicateType: "vuln",
				}},
			},
		},
	}
	want := `{"authorityMatches":{"authority-0":{"attestations":{"test-att":[{"subject":"https://github.com/distroless/static/.github/workflows/release.yaml@refs/heads/main","issuer":"https://token.actions.githubusercontent.com","githubWorkflowTrigger":"schedule","githubWorkflowSha":"7e7572e578de7c51a2f1a1791f025cf315503aa2","githubWorkflowName":"Create Release","githubWorkflowRepo":"distroless/static","githubWorkflowRef":"refs/heads/main","predicateType":"vuln"}]}}},"errors":[],"image":"image@sha256:12345","name":"my-policy","pass":false,"resourceVersion":"1","uid":"123","warnings":[]}`
	got, err := verTuple.MarshalJSON()
	if err != nil {
		t.Error("MarshalJSON Failed =", err)
	}
	if string(got) != want {
		t.Errorf("TestVerificationTuple() = %v, wanted %v", string(got), want)
	}
	var wantTuple VerificationTuple
	json.Unmarshal([]byte(want), &wantTuple)
	if err != nil {
		t.Error("Unmarshal Failed =", err)
	}
	if !cmp.Equal(verTuple, wantTuple) {
		t.Errorf("TestVerificationTuple() %s", cmp.Diff(verTuple, wantTuple))
	}
}
