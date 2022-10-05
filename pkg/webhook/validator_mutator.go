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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/policy"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	policyduckv1beta1 "github.com/sigstore/policy-controller/pkg/apis/duck/v1beta1"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"

	"knative.dev/pkg/logging"
)

// ValidatePodScalable implements policyduckv1beta1.PodScalableValidator
// It is very similar to ValidatePodSpecable, but allows for spec.replicas
// to be decremented. This allows for scaling down pods with non-compliant
// images that would otherwise be forbidden.
func (v *Validator) SetValidationTuplePodScalable(ctx context.Context, ps *policyduckv1beta1.PodScalable) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, ps.DeletionTimestamp) {
		return nil
	}

	// If we are being scaled down don't block it.
	if ps.IsScalingDown(ctx) {
		logging.FromContext(ctx).Debugf("Skipping validations due to scale down request %s/%s", &ps.ObjectMeta.Name, &ps.ObjectMeta.Namespace)
		return nil
	}

	imagePullSecrets := make([]string, 0, len(ps.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range ps.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	ns := getNamespace(ctx, ps.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: ps.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}

	annotations := v.setValidationTuplePodSpec(ctx, ns, ps.Kind, ps.APIVersion, ps.ObjectMeta.Labels, &ps.Spec.Template.Spec, opt)

	ps.Spec.Template.Annotations = annotations

	return nil
}

// ValidatePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) SetValidationTuplePodSpecable(ctx context.Context, wp *duckv1.WithPod) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, wp.DeletionTimestamp) {
		return nil
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	ns := getNamespace(ctx, wp.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	annotations := v.setValidationTuplePodSpec(ctx, ns, wp.Kind, wp.APIVersion, wp.ObjectMeta.Labels, &wp.Spec.Template.Spec, opt)

	wp.Spec.Template.Annotations = annotations

	return nil
}

// ValidatePod implements duckv1.PodValidator
func (v *Validator) SetValidationTuplePod(ctx context.Context, p *duckv1.Pod) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, p.DeletionTimestamp) {
		return nil
	}

	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	ns := getNamespace(ctx, p.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	annotations := v.setValidationTuplePodSpec(ctx, ns, p.Kind, p.APIVersion, p.ObjectMeta.Labels, &p.Spec, opt)

	p.Annotations = annotations

	return nil
}

// ValidateCronJob implements duckv1.CronJobValidator
func (v *Validator) SetValidationTupleCronJob(ctx context.Context, c *duckv1.CronJob) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, c.DeletionTimestamp) {
		return nil
	}

	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	ns := getNamespace(ctx, c.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}

	annotations := v.setValidationTuplePodSpec(ctx, ns, c.Kind, c.APIVersion, c.ObjectMeta.Labels, &c.Spec.JobTemplate.Spec.Template.Spec, opt)

	c.Spec.JobTemplate.Annotations = annotations

	return nil
}

func (v *Validator) setValidationTuplePodSpec(ctx context.Context, namespace, kind, apiVersion string, labels map[string]string, ps *corev1.PodSpec, opt k8schain.Options) map[string]string {
	annotations := map[string]string{}

	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return annotations
	}
	//var errs *apis.FieldError

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

				// If there is at least one policy that matches, that means it
				// has to be satisfied.
				if len(policies) > 0 {
					signatures := validatePoliciesTuple(ctx, namespace, ref, policies, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))

					if len(signatures) != len(policies) {
						// THIS MIGHT CHANGE

						logging.FromContext(ctx).Warnf("Failed to validate at least one policy for %s", ref.Name())
						// Do we really want to add all the error details here?
						// Seems like we can just say which policy failed, so
						// doing that for now.
						// Split the errors and warnings to their own
						// error levels.

						/*hasWarnings := false
						hasErrors := false
						for failingPolicy, policyErrs := range fieldErrors {
							errDetails := c.Image
							warnDetails := c.Image
							for _, policyErr := range policyErrs {
								var fe *apis.FieldError
								if errors.As(policyErr, &fe) {
									if fe.Filter(apis.WarningLevel) != nil {
										warnDetails = warnDetails + " " + fe.Message
										hasWarnings = true
									} else {
										errDetails = errDetails + " " + fe.Message
										hasErrors = true
									}
								} else {
									// Just a regular error.
									errDetails = errDetails + " " + policyErr.Error()
								}
							}
							if hasWarnings {
								warnField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
								warnField.Details = warnDetails
								errs = errs.Also(warnField).At(apis.WarningLevel)
							}
							if hasErrors {
								errorField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
								errorField.Details = errDetails
								errs = errs.Also(errorField)
							}
						}*/
						// Because there was at least one policy that was
						// supposed to be validated, but it failed, then fail
						// this image. It should not fall through to the
						// traditional secret checking so it does not slip
						// through the policy cracks, and also to reduce noise
						// in the errors returned to the user.
						continue
					}
				}
				logging.FromContext(ctx).Errorf("policies: for %v", policies)
			}
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return annotations
}

// validatePolicies will go through all the matching Policies and their
// Authorities for a given image. Returns the map of policy=>Validated
// signatures. From the map you can see the number of matched policies along
// with the signatures that were verified.
// If there's a policy that did not match, it will be returned in the errors map
// along with all the errors that caused it to fail.
// Note that if an image does not match any policies, it's perfectly
// reasonable that the return value is 0, nil since there were no errors, but
// the image was not validated against any matching policy and hence authority.
func validatePoliciesTuple(ctx context.Context, namespace string, ref name.Reference, policies map[string]webhookcip.ClusterImagePolicy, remoteOpts ...ociremote.Option) map[string]*VerificationTuple {

	results := make(chan VerificationTuple, len(policies))

	// For each matching policy it must validate at least one Authority within
	// it.
	// From the Design document, the part about multiple Policies matching:
	// "If multiple policies match a particular image, then ALL of those
	// policies must be satisfied for the image to be admitted."
	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. If one passes, do not return the errors.
	for cipName, cip := range policies {
		// Due to running in gofunc
		cipName := cipName
		cip := cip
		logging.FromContext(ctx).Debugf("Checking Policy: %s", cipName)
		go func() {
			result := VerificationTuple{PolicyName: cipName, ResourceVersion: cip.ResourceVersion, Image: ref.String()}

			result.PolicyResult, result.Errors = ValidatePolicyMutate(ctx, namespace, ref, cip, remoteOpts...)

			result.Pass = (len(result.Errors) == 0)
			results <- result
		}()
	}
	// Gather all validated policies here.
	policyVerificationResults := make(map[string]*VerificationTuple)
	// For a policy that does not pass at least one authority, gather errors
	// here so that we can give meaningful errors to the user.
	ret := map[string][]error{}

	for i := 0; i < len(policies); i++ {
		select {
		case result, ok := <-results:
			if !ok {
				ret["internalerror"] = append(ret["internalerror"])
				policyVerificationResults[result.PolicyName].Errors = append(policyVerificationResults[result.PolicyName].Errors, fmt.Errorf("results channel failed to produce a result"))
				continue
			}
			switch {
			// Return AuthorityMatches before errors, since even if there
			// are errors, if there are 0 or more authorities that match,
			// it will pass the Policy. Of course, a CIP level policy can
			// override this behaviour, but that has been checked above and
			// if it failed, it will nil out the policyResult.
			case result.PolicyResult != nil:
				policyVerificationResults[result.PolicyName] = &result
			case len(result.Errors) > 0:
				policyVerificationResults[result.PolicyName].Errors = result.Errors
			default:
				policyVerificationResults[result.PolicyName].Errors = append(policyVerificationResults[result.PolicyName].Errors, fmt.Errorf("failed to process policy: %s", result.PolicyName))
			}
		}
	}

	return policyVerificationResults
}

// ValidatePolicy will go through all the Authorities for a given image/policy
// and return validated authorities if at least one of the Authorities
// validated the signatures OR attestations if atttestations were specified.
// Returns PolicyResult if one or more authorities matched, otherwise nil.
// In any case returns all errors encountered if none of the authorities
// passed.
func ValidatePolicyMutate(ctx context.Context, namespace string, ref name.Reference, cip webhookcip.ClusterImagePolicy, remoteOpts ...ociremote.Option) (*PolicyResult, []error) {
	// Each gofunc creates and puts one of these into a results channel.
	// Once each gofunc finishes, we go through the channel and pull out
	// the results.
	type retChannelType struct {
		name         string
		static       bool
		attestations map[string][]PolicyAttestation
		signatures   []PolicySignature
		err          error
	}
	results := make(chan retChannelType, len(cip.Authorities))
	for _, authority := range cip.Authorities {
		authority := authority // due to gofunc
		logging.FromContext(ctx).Debugf("Checking Authority: %s", authority.Name)

		go func() {
			result := retChannelType{name: authority.Name}
			// Assignment for appendAssign lint error
			authorityRemoteOpts := remoteOpts
			authorityRemoteOpts = append(authorityRemoteOpts, authority.RemoteOpts...)

			signaturePullSecretsOpts, err := authority.SourceSignaturePullSecretsOpts(ctx, namespace)
			if err != nil {
				result.err = err
				results <- result
				return
			}
			authorityRemoteOpts = append(authorityRemoteOpts, signaturePullSecretsOpts...)

			switch {
			case authority.Static != nil:
				if authority.Static.Action == "fail" {
					result.err = cosign.NewVerificationError("disallowed by static policy")
					results <- result
					return
				}
				result.static = true

			case len(authority.Attestations) > 0:
				// We're doing the verify-attestations path, so validate (.att)
				result.attestations, result.err = ValidatePolicyAttestationsForAuthority(ctx, ref, authority, authorityRemoteOpts...)

			default:
				result.signatures, result.err = ValidatePolicySignaturesForAuthority(ctx, ref, authority, authorityRemoteOpts...)
			}
			results <- result
		}()
	}

	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. Even if there are errors, return the matched
	// authoritypolicies.
	authorityErrors := make([]error, 0, len(cip.Authorities))
	// We collect all the successfully satisfied Authorities into this and
	// return it.
	policyResult := &PolicyResult{
		AuthorityMatches: make(map[string]AuthorityMatch, len(cip.Authorities)),
	}
	for range cip.Authorities {
		select {
		case <-ctx.Done():
			authorityErrors = append(authorityErrors, fmt.Errorf("%w before validation completed", ctx.Err()))

		case result, ok := <-results:
			if !ok {
				authorityErrors = append(authorityErrors, errors.New("results channel closed before all results were sent"))
				continue
			}
			switch {
			case result.err != nil:
				// We only wrap actual policy failures as FieldErrors with the
				// possibly Warn level. Other things imho should be still
				// be considered errors.
				authorityErrors = append(authorityErrors, asFieldError(cip.Mode == "warn", result.err))

			case len(result.signatures) > 0:
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{Signatures: result.signatures}

			case len(result.attestations) > 0:
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{Attestations: result.attestations}

			case result.static:
				// This happens when we encounter a policy with:
				//   static:
				//     action: "pass"
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{
					Static: true,
				}

			default:
				authorityErrors = append(authorityErrors, fmt.Errorf("failed to process authority: %s", result.name))
			}
		}
	}
	// Even if there are errors, return the policies, since as per the
	// spec, we just need one authority to pass checks. If more than
	// one are required, that is enforced at the CIP policy level.
	// If however there are no authorityMatches, return nil so we don't have
	// to keep checking the length on the returned calls.
	if len(policyResult.AuthorityMatches) == 0 {
		return nil, authorityErrors
	}
	// Ok, there's at least one valid authority that matched. If there's a CIP
	// level policy, validate it here before returning.
	if cip.Policy != nil {
		logging.FromContext(ctx).Info("Validating CIP level policy")
		policyJSON, err := json.Marshal(policyResult)
		if err != nil {
			return nil, append(authorityErrors, err)
		}
		err = policy.EvaluatePolicyAgainstJSON(ctx, "ClusterImagePolicy", cip.Policy.Type, cip.Policy.Data, policyJSON)
		if err != nil {
			logging.FromContext(ctx).Warnf("Failed to validate CIP level policy against %s", string(policyJSON))
			return nil, append(authorityErrors, asFieldError(cip.Mode == "warn", err))
		}
	}
	return policyResult, authorityErrors
}
