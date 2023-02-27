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
	"context"

	"github.com/sigstore/policy-controller/pkg/apis/policy/common"
	"github.com/sigstore/policy-controller/pkg/apis/signaturealgo"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"knative.dev/pkg/apis"

	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
)

// Validate implements apis.Validatable
func (c *ImagePolicy) Validate(ctx context.Context) *apis.FieldError {
	// If we're doing status updates, do not validate the spec.
	if apis.IsInStatusUpdate(ctx) {
		return nil
	}
	return c.Spec.Validate(ctx).ViaField("spec")
}

func (spec *ImagePolicySpec) Validate(ctx context.Context) (errors *apis.FieldError) {
	// Check what the configuration is and act accordingly.
	pcConfig := policycontrollerconfig.FromContextOrDefaults(ctx)

	if len(spec.Images) == 0 {
		errors = errors.Also(apis.ErrMissingField("images"))
	}
	for i, image := range spec.Images {
		errors = errors.Also(image.Validate(ctx).ViaFieldIndex("images", i))
	}
	// Check if PolicyControllerConfig is configured to fail when having empty authorities
	if len(spec.Authorities) == 0 && pcConfig.FailOnEmptyAuthorities {
		errors = errors.Also(apis.ErrMissingField("authorities"))
	}
	for i, authority := range spec.Authorities {
		errors = errors.Also(authority.ValidateNamespacedAuthority(ctx).ViaFieldIndex("authorities", i))
	}
	if spec.Mode != "" && !common.ValidModes.Has(spec.Mode) {
		errors = errors.Also(apis.ErrInvalidValue(spec.Mode, "mode", "unsupported mode"))
	}
	for i, m := range spec.Match {
		errors = errors.Also(m.Validate(ctx).ViaFieldIndex("match", i))
	}
	// Note that we're within Spec here so that we can validate that the policy
	// FetchConfigFile is only set within Spec.Policy.
	errors = errors.Also(spec.Policy.Validate(apis.WithinSpec(ctx)))
	return
}

func (authority *Authority) ValidateNamespacedAuthority(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError
	if authority.Key == nil && authority.Keyless == nil && authority.Static == nil {
		errs = errs.Also(apis.ErrMissingOneOf("key", "keyless", "static"))
		// Instead of returning all the missing subfields, just return here
		// to give a more concise and arguably a more meaningful error message.
		return errs
	}
	if (authority.Key != nil && authority.Keyless != nil) ||
		(authority.Key != nil && authority.Static != nil) ||
		(authority.Keyless != nil && authority.Static != nil) {
		errs = errs.Also(apis.ErrMultipleOneOf("key", "keyless", "static"))
		// Instead of returning all the missing subfields, just return here
		// to give a more concise and arguably a more meaningful error message.
		return errs
	}

	if authority.Key != nil {
		errs = errs.Also(authority.Key.ValidateNamespacedKeyRef(ctx).ViaField("key"))
	}
	if authority.Keyless != nil {
		errs = errs.Also(authority.Keyless.Validate(ctx).ViaField("keyless"))
	}
	if authority.Static != nil {
		errs = errs.Also(authority.Static.Validate(ctx).ViaField("static"))
		// Attestations, Sources, RFC3161Timestamp, or CTLog do not make sense with static policy.
		if len(authority.Attestations) > 0 {
			errs = errs.Also(apis.ErrMultipleOneOf("static", "attestations"))
		}
		if len(authority.Sources) > 0 {
			errs = errs.Also(apis.ErrMultipleOneOf("static", "source"))
		}
		if authority.CTLog != nil {
			errs = errs.Also(apis.ErrMultipleOneOf("static", "ctlog"))
		}
		if authority.RFC3161Timestamp != nil {
			errs = errs.Also(apis.ErrMultipleOneOf("static", "rfc3161timestamp"))
		}
	}

	if len(authority.Sources) > 1 {
		errs = errs.Also(apis.ErrInvalidValue("source", "source", "only single source is supported"))
	} else {
		// If there are multiple sources, don't complain about each of them.
		for i, source := range authority.Sources {
			errs = errs.Also(source.Validate(ctx).ViaFieldIndex("source", i))
		}
	}

	for _, att := range authority.Attestations {
		errs = errs.Also(att.Validate(ctx).ViaField("attestations"))
	}

	return errs
}

func (key *KeyRef) ValidateNamespacedKeyRef(ctx context.Context) *apis.FieldError {
	var errs *apis.FieldError

	if key.Data == "" && key.KMS == "" && key.SecretRef == nil {
		errs = errs.Also(apis.ErrMissingOneOf("data", "kms", "secretref"))
	}

	if key.HashAlgorithm != "" {
		_, err := signaturealgo.HashAlgorithm(key.HashAlgorithm)
		if err != nil {
			errs = errs.Also(apis.ErrInvalidValue(key.HashAlgorithm, "hashAlgorithm"))
		}
	}

	if key.Data != "" {
		if key.KMS != "" || key.SecretRef != nil {
			errs = errs.Also(apis.ErrMultipleOneOf("data", "kms", "secretref"))
		}
		publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(key.Data))
		if err != nil || publicKey == nil {
			errs = errs.Also(apis.ErrInvalidValue(key.Data, "data"))
		}
	} else if key.KMS != "" && key.SecretRef != nil {
		errs = errs.Also(apis.ErrMultipleOneOf("data", "kms", "secretref"))
	}
	if key.KMS != "" {
		errs = errs.Also(common.ValidateKMS(key.KMS).ViaField("kms"))
	}
	if key.SecretRef != nil && key.SecretRef.Namespace == "" {
		errs = errs.Also(apis.ErrInvalidValue(key.SecretRef.Namespace, "secretref.namespace", "secretref.namespace is invalid."))
	}
	return errs
}
