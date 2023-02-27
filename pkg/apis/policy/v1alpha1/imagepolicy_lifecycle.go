// Copyright 2023 The Sigstore Authors.
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
	"knative.dev/pkg/apis"
)

var ipCondSet = apis.NewLivingConditionSet(
	ImagePolicyConditionKeysInlined,
	ImagePolicyConditionPoliciesInlined,
	ImagePolicyConditionCMUpdated,
)

// GetConditionSet retrieves the condition set for this resource.
// Implements the KRShaped interface.
func (*ImagePolicy) GetConditionSet() apis.ConditionSet {
	return ipCondSet
}

// IsReady returns if the ImagePolicy was compiled successfully to
// ConfigMap.
func (c *ImagePolicy) IsReady() bool {
	cs := c.Status
	return cs.ObservedGeneration == c.Generation &&
		cs.GetCondition(ImagePolicyConditionReady).IsTrue()
}

// IsFailed returns true if the resource has observed
// the latest generation and ready is false.
func (c *ImagePolicy) IsFailed() bool {
	cs := c.Status
	return cs.ObservedGeneration == c.Generation &&
		cs.GetCondition(ImagePolicyConditionReady).IsFalse()
}

// InitializeConditions sets the initial values to the conditions.
func (cs *ImagePolicyStatus) InitializeConditions() {
	ipCondSet.Manage(cs).InitializeConditions()
}

// MarkInlineKeysFailed surfaces a failure that we were unable to inline
// the keys (from secrets or from KMS).
func (cs *ImagePolicyStatus) MarkInlineKeysFailed(msg string) {
	ipCondSet.Manage(cs).MarkFalse(ImagePolicyConditionKeysInlined, inlineKeysFailedReason, msg)
}

// MarkInlineKeysOk marks the status saying that the inlining of the keys
// had no errors.
func (cs *ImagePolicyStatus) MarkInlineKeysOk() {
	ipCondSet.Manage(cs).MarkTrue(ImagePolicyConditionKeysInlined)
}

// MarkInlinePoliciesFailed surfaces a failure that we were unable to inline
// the policies, either from ConfigMap or from URL.
func (cs *ImagePolicyStatus) MarkInlinePoliciesFailed(msg string) {
	ipCondSet.Manage(cs).MarkFalse(ImagePolicyConditionPoliciesInlined, inlinePoliciesFailedReason, msg)
}

// MarkInlinePoliciesdOk marks the status saying that the inlining of the
// policies had no errors.
func (cs *ImagePolicyStatus) MarkInlinePoliciesOk() {
	ipCondSet.Manage(cs).MarkTrue(ImagePolicyConditionPoliciesInlined)
}

// MarkCMUpdateFailed surfaces a failure that we were unable to reflect the
// CIP into the compiled ConfigMap.
func (cs *ImagePolicyStatus) MarkCMUpdateFailed(msg string) {
	ipCondSet.Manage(cs).MarkFalse(ImagePolicyConditionCMUpdated, updateCMFailedReason, msg)
}

// MarkCMUpdated marks the status saying that the ConfigMap has been updated.
func (cs *ImagePolicyStatus) MarkCMUpdatedOK() {
	ipCondSet.Manage(cs).MarkTrue(ImagePolicyConditionCMUpdated)
}
