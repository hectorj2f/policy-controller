package webhook

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
)

type VerificationTuple struct {
	PolicyResult
	PolicyName      string    `json:"name,omitempty"`
	Image           string    `json:"image,omitempty"`
	ResourceVersion string    `json:"resourceVersion,omitempty"`
	Errors          []error   `json:"errors,omitempty"`
	Warnings        []error   `json:"warnings,omitempty"`
	Pass            bool      `json:"pass,omitempty"`
	UID             types.UID `json:"uid,omitempty"`
}

func (v VerificationTuple) GenerateVerificationTupleID() string {
	// FIXME: @hectorj2f
	return fmt.Sprintf("%s-%s", "myimage", v.UID)
}

func (v VerificationTuple) MarshalJSON() ([]byte, error) {
	result := map[string]interface{}{
		"image":           v.Image,
		"name":            v.PolicyName,
		"resourceVersion": v.ResourceVersion,
		"errors":          v.Errors,
		"warnings":        v.Warnings,
		"pass":            v.Pass,
		"uid":             v.UID,
	}
	if len(v.AuthorityMatches) > 0 {
		result["authorityMatches"] = v.AuthorityMatches
	}

	return json.Marshal(result)
}
