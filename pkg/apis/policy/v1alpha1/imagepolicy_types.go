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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	"knative.dev/pkg/kmeta"
)

// ImagePolicy defines the images that go through verification
// and the authorities used for verification for a namespace
//
// +genclient
// +genclient:namespaced
// +genreconciler:krshapedlogic=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ImagePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Spec holds the desired state of the ImagePolicy (from the client).
	Spec ImagePolicySpec `json:"spec"`

	// Status represents the current state of the ImagePolicy.
	// This data may be out of date.
	// +optional
	Status ImagePolicyStatus `json:"status,omitempty"`
}

var (
	_ apis.Validatable   = (*ImagePolicy)(nil)
	_ apis.Defaultable   = (*ImagePolicy)(nil)
	_ kmeta.OwnerRefable = (*ImagePolicy)(nil)
	// Check that the type conforms to the duck Knative Resource shape.
	_ duckv1.KRShaped = (*ImagePolicy)(nil)
)

const (
	// ImagePolicyReady is set when the ImagePolicy has been
	// compiled into the underlying ConfigMap properly.
	ImagePolicyConditionReady = apis.ConditionReady
	// ImagePolicyConditionKeysInlined is set to True when all the Keys
	// have been (Secrets, KMS, etc.) resolved, fetched, validated, and inlined
	// into the compiled representation.
	// In failure cases, the Condition will describe the errors in detail.
	ImagePolicyConditionKeysInlined apis.ConditionType = "KeysInlined"
	// ImagePolicyConditionPoliciesInlined is set to True when all the
	// policies have been resolved, fetched, validated, and inlined into the
	// compiled representation.
	// In failure cases, the Condition will describe the errors in detail.
	ImagePolicyConditionPoliciesInlined apis.ConditionType = "PoliciesInlined"
	// ImagePolicyConditionCMUpdated	is set to True when the CIP has been
	// successfully added into the ConfigMap holding all the compiled CIPs.
	// In failure cases, the Condition will describe the errors in detail.
	ImagePolicyConditionCMUpdated apis.ConditionType = "ConfigMapUpdated"
)

// GetGroupVersionKind implements kmeta.OwnerRefable
func (c *ImagePolicy) GetGroupVersionKind() schema.GroupVersionKind {
	return SchemeGroupVersion.WithKind("ImagePolicy")
}

// ImagePolicySpec defines a list of images that should be verified
type ImagePolicySpec struct {
	// Images defines the patterns of image names that should be subject to this policy.
	Images []ImagePattern `json:"images"`
	// Authorities defines the rules for discovering and validating signatures.
	// +optional
	Authorities []Authority `json:"authorities,omitempty"`
	// Policy is an optional policy that can be applied against all the
	// successfully validated Authorities. If no authorities pass, this does
	// not even get evaluated, as the Policy is considered failed.
	// +optional
	Policy *Policy `json:"policy,omitempty"`
	// Mode controls whether a failing policy will be rejected (not admitted),
	// or if errors are converted to Warnings.
	// enforce - Reject (default)
	// warn - allow but warn
	// +optional
	Mode string `json:"mode,omitempty"`
	// Match allows selecting resources based on their properties.
	// +optional
	Match []MatchResource `json:"match,omitempty"`
}

// ImagePolicyStatus represents the current state of a
// ImagePolicy.
type ImagePolicyStatus struct {
	// inherits duck/v1 Status, which currently provides:
	// * ObservedGeneration - the 'Generation' of the Broker that was last processed by the controller.
	// * Conditions - the latest available observations of a resource's current state.
	duckv1.Status `json:",inline"`
}

// GetStatus retrieves the status of the ImagePolicy.
// Implements the KRShaped interface.
func (c *ImagePolicy) GetStatus() *duckv1.Status {
	return &c.Status.Status
}

// ImagePolicyList is a list of ImagePolicy resources
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ImagePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ImagePolicy `json:"items"`
}
