//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1beta1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	apis "knative.dev/pkg/apis"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Attestation) DeepCopyInto(out *Attestation) {
	*out = *in
	if in.Policy != nil {
		in, out := &in.Policy, &out.Policy
		*out = new(Policy)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Attestation.
func (in *Attestation) DeepCopy() *Attestation {
	if in == nil {
		return nil
	}
	out := new(Attestation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Authority) DeepCopyInto(out *Authority) {
	*out = *in
	if in.Key != nil {
		in, out := &in.Key, &out.Key
		*out = new(KeyRef)
		(*in).DeepCopyInto(*out)
	}
	if in.Keyless != nil {
		in, out := &in.Keyless, &out.Keyless
		*out = new(KeylessRef)
		(*in).DeepCopyInto(*out)
	}
	if in.Static != nil {
		in, out := &in.Static, &out.Static
		*out = new(StaticRef)
		**out = **in
	}
	if in.Sources != nil {
		in, out := &in.Sources, &out.Sources
		*out = make([]Source, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.CTLog != nil {
		in, out := &in.CTLog, &out.CTLog
		*out = new(TLog)
		(*in).DeepCopyInto(*out)
	}
	if in.RFC3161Timestamp != nil {
		in, out := &in.RFC3161Timestamp, &out.RFC3161Timestamp
		*out = new(RFC3161Timestamp)
		(*in).DeepCopyInto(*out)
	}
	if in.Attestations != nil {
		in, out := &in.Attestations, &out.Attestations
		*out = make([]Attestation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Authority.
func (in *Authority) DeepCopy() *Authority {
	if in == nil {
		return nil
	}
	out := new(Authority)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterImagePolicy) DeepCopyInto(out *ClusterImagePolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterImagePolicy.
func (in *ClusterImagePolicy) DeepCopy() *ClusterImagePolicy {
	if in == nil {
		return nil
	}
	out := new(ClusterImagePolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterImagePolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterImagePolicyList) DeepCopyInto(out *ClusterImagePolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ClusterImagePolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterImagePolicyList.
func (in *ClusterImagePolicyList) DeepCopy() *ClusterImagePolicyList {
	if in == nil {
		return nil
	}
	out := new(ClusterImagePolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterImagePolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterImagePolicySpec) DeepCopyInto(out *ClusterImagePolicySpec) {
	*out = *in
	if in.Images != nil {
		in, out := &in.Images, &out.Images
		*out = make([]ImagePattern, len(*in))
		copy(*out, *in)
	}
	if in.Authorities != nil {
		in, out := &in.Authorities, &out.Authorities
		*out = make([]Authority, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Policy != nil {
		in, out := &in.Policy, &out.Policy
		*out = new(Policy)
		(*in).DeepCopyInto(*out)
	}
	if in.Match != nil {
		in, out := &in.Match, &out.Match
		*out = make([]MatchResource, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterImagePolicySpec.
func (in *ClusterImagePolicySpec) DeepCopy() *ClusterImagePolicySpec {
	if in == nil {
		return nil
	}
	out := new(ClusterImagePolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConfigMapReference) DeepCopyInto(out *ConfigMapReference) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConfigMapReference.
func (in *ConfigMapReference) DeepCopy() *ConfigMapReference {
	if in == nil {
		return nil
	}
	out := new(ConfigMapReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Identity) DeepCopyInto(out *Identity) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Identity.
func (in *Identity) DeepCopy() *Identity {
	if in == nil {
		return nil
	}
	out := new(Identity)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImagePattern) DeepCopyInto(out *ImagePattern) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImagePattern.
func (in *ImagePattern) DeepCopy() *ImagePattern {
	if in == nil {
		return nil
	}
	out := new(ImagePattern)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyRef) DeepCopyInto(out *KeyRef) {
	*out = *in
	if in.SecretRef != nil {
		in, out := &in.SecretRef, &out.SecretRef
		*out = new(v1.SecretReference)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyRef.
func (in *KeyRef) DeepCopy() *KeyRef {
	if in == nil {
		return nil
	}
	out := new(KeyRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeylessRef) DeepCopyInto(out *KeylessRef) {
	*out = *in
	if in.URL != nil {
		in, out := &in.URL, &out.URL
		*out = new(apis.URL)
		(*in).DeepCopyInto(*out)
	}
	if in.Identities != nil {
		in, out := &in.Identities, &out.Identities
		*out = make([]Identity, len(*in))
		copy(*out, *in)
	}
	if in.CACert != nil {
		in, out := &in.CACert, &out.CACert
		*out = new(KeyRef)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeylessRef.
func (in *KeylessRef) DeepCopy() *KeylessRef {
	if in == nil {
		return nil
	}
	out := new(KeylessRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MatchResource) DeepCopyInto(out *MatchResource) {
	*out = *in
	out.GroupVersionResource = in.GroupVersionResource
	if in.ResourceSelector != nil {
		in, out := &in.ResourceSelector, &out.ResourceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MatchResource.
func (in *MatchResource) DeepCopy() *MatchResource {
	if in == nil {
		return nil
	}
	out := new(MatchResource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Policy) DeepCopyInto(out *Policy) {
	*out = *in
	if in.URL != nil {
		in, out := &in.URL, &out.URL
		*out = new(apis.URL)
		(*in).DeepCopyInto(*out)
	}
	if in.ConfigMapRef != nil {
		in, out := &in.ConfigMapRef, &out.ConfigMapRef
		*out = new(ConfigMapReference)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Policy.
func (in *Policy) DeepCopy() *Policy {
	if in == nil {
		return nil
	}
	out := new(Policy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RFC3161Timestamp) DeepCopyInto(out *RFC3161Timestamp) {
	*out = *in
	if in.CertChain != nil {
		in, out := &in.CertChain, &out.CertChain
		*out = new(KeyRef)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RFC3161Timestamp.
func (in *RFC3161Timestamp) DeepCopy() *RFC3161Timestamp {
	if in == nil {
		return nil
	}
	out := new(RFC3161Timestamp)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Source) DeepCopyInto(out *Source) {
	*out = *in
	if in.SignaturePullSecrets != nil {
		in, out := &in.SignaturePullSecrets, &out.SignaturePullSecrets
		*out = make([]v1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Source.
func (in *Source) DeepCopy() *Source {
	if in == nil {
		return nil
	}
	out := new(Source)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StaticRef) DeepCopyInto(out *StaticRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StaticRef.
func (in *StaticRef) DeepCopy() *StaticRef {
	if in == nil {
		return nil
	}
	out := new(StaticRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLog) DeepCopyInto(out *TLog) {
	*out = *in
	if in.URL != nil {
		in, out := &in.URL, &out.URL
		*out = new(apis.URL)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLog.
func (in *TLog) DeepCopy() *TLog {
	if in == nil {
		return nil
	}
	out := new(TLog)
	in.DeepCopyInto(out)
	return out
}
