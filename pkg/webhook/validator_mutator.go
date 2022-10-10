//
// Copyright 2021 The Sigstore Authors.
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

package webhook

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	corev1 "k8s.io/api/core/v1"

	"knative.dev/pkg/logging"
)

func (v *Validator) setValidationTuplePodSpec(ctx context.Context, namespace, kind, apiVersion string, labels map[string]string, ps *corev1.PodSpec, opt k8schain.Options) map[string]string {
	policyVerificationResults := make(map[string]string)

	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return policyVerificationResults
	}

	checkContainers := func(cs []corev1.Container, field string) {
		for _, c := range cs {
			// Check it one step before
			ref, _ := name.ParseReference(c.Image)
			config := config.FromContext(ctx)
			if config != nil {
				policies, err := config.ImagePolicyConfig.GetMatchingPolicies(ref.Name(), kind, apiVersion, labels)
				if err != nil {
					logging.FromContext(ctx).Errorf("Unable to get matching policies for image %s: %v", c.Image, err)
					continue
				}

				// If there is at least one policy that matches, that means it needs to generate the verification tuple.
				if len(policies) > 0 {
					generatePolicyTuples(ctx, namespace, ref, policies, policyVerificationResults, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))
				}
				logging.FromContext(ctx).Errorf("policies: for %v", policies)
			}
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return policyVerificationResults
}

func generatePolicyTuples(ctx context.Context, namespace string, ref name.Reference, policies map[string]webhookcip.ClusterImagePolicy, policyVerificationResults map[string]string, remoteOpts ...ociremote.Option) {
	results := make(chan VerificationTuple, len(policies))

	var evaluatedPoliciesCount int
	for cipName, cip := range policies {
		// Due to running in gofunc
		cipName := cipName
		cip := cip
		result := VerificationTuple{PolicyName: cipName, ResourceVersion: cip.ResourceVersion, Image: ref.String(), UID: cip.UID}

		// Skip if it has been already evaluated for a previous image
		if _, ok := policyVerificationResults[result.GenerateVerificationTupleID()]; ok {
			continue
		}
		evaluatedPoliciesCount++
		go func() {
			var policyResult *PolicyResult
			policyResult, result.Errors = ValidatePolicy(ctx, namespace, ref, cip, remoteOpts...)
			if policyResult != nil {
				result.AuthorityMatches = policyResult.AuthorityMatches
			}

			result.Pass = (len(result.Errors) == 0)
			results <- result
		}()
	}

	for i := 0; i < evaluatedPoliciesCount; i++ {
		select {
		case result, ok := <-results:
			if !ok {
				result.Errors = append(result.Errors, fmt.Errorf("results channel failed to produce a result"))
				val, _ := result.MarshalJSON()
				policyVerificationResults[result.GenerateVerificationTupleID()] = string(val)
				continue
			}

			val, _ := result.MarshalJSON()
			policyVerificationResults[result.GenerateVerificationTupleID()] = string(val)
		}
	}
}
