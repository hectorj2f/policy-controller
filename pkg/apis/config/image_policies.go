//
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

package imagepolicies

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sigstore/policy-controller/pkg/apis/glob"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metalabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

const (
	// ImagePoliciesConfigName is the name of ConfigMap created by the
	// reconciler and consumed by the admission webhook.
	ImagePoliciesConfigName = "config-image-policies"
)

type ImagePolicyConfig struct {
	// This is the list of ImagePolicies that a admission controller uses
	// to make policy decisions.
	Policies map[string]webhookcip.ClusterImagePolicy

	NamespacedPolicies map[string]webhookcip.ImagePolicy
}

// NewImagePoliciesConfigFromMap creates an ImagePolicyConfig from the supplied
// Map
func NewImagePoliciesConfigFromMap(data map[string]string) (*ImagePolicyConfig, error) {
	ret := &ImagePolicyConfig{Policies: make(map[string]webhookcip.ClusterImagePolicy, len(data))}
	// Spin through the ConfigMap. Each key will point to resolved
	// ImagePatterns.
	for k, v := range data {
		// This is the example that we use to document / test the ConfigMap.
		if k == "_example" {
			continue
		}
		if v == "" {
			return nil, fmt.Errorf("configmap has an entry %q but no value", k)
		}
		clusterImagePolicy := &webhookcip.ClusterImagePolicy{}
		imagePolicy := &webhookcip.ImagePolicy{}
		cip, ip, err := parseEntry(v, clusterImagePolicy, imagePolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the entry %q : %q : %w", k, v, err)
		}
		if cip != nil {
			ret.Policies[k] = *clusterImagePolicy
		}
		if ip != nil {
			ret.NamespacedPolicies[k] = *imagePolicy
		}
	}
	return ret, nil
}

// NewImagePoliciesConfigFromConfigMap creates a Features from the supplied ConfigMap
func NewImagePoliciesConfigFromConfigMap(config *corev1.ConfigMap) (*ImagePolicyConfig, error) {
	return NewImagePoliciesConfigFromMap(config.Data)
}

func parseEntry(entry string, out interface{}) error {
	j, err := yaml.YAMLToJSON([]byte(entry))
	if err != nil {
		return fmt.Errorf("config's value could not be converted to JSON: %w : %s", err, entry)
	}
	return json.Unmarshal(j, &out)
}

// GetMatchingPolicies returns all matching Policies and their Authorities that
// need to be matched for the given kind, version and labels (if provided) to then match the Image.
// Returned map contains the name of the CIP as the key, and a normalized
// ClusterImagePolicy for it.
func (p *ImagePolicyConfig) GetMatchingPolicies(image string, kind, apiVersion string, labels map[string]string, namespace string) (map[string]webhookcip.ClusterImagePolicy, map[string]webhookcip.ImagePolicy, error) {
	if p == nil {
		return nil, errors.New("config is nil")
	}

	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	// While unsafe, this is correct (safe!) for everything we care about.
	gvr, _ := meta.UnsafeGuessKindToResource(gv.WithKind(kind))

	var lastError error
	ret := make(map[string]webhookcip.ClusterImagePolicy)

	// TODO(vaikas): this is very inefficient, we should have a better
	// way to go from image to Authorities, but just seeing if this is even
	// workable so fine for now.
	for k, v := range p.Policies {
		if len(v.Match) > 0 {
			foundMatch := false
			for _, matchResource := range v.Match {
				if matchResource.Resource != gvr.Resource {
					// Resource doesn't match.
					continue
				}
				if matchResource.Version != gvr.Version && matchResource.Version != "*" {
					// Version doesn't match exactly or wildcard.
					continue
				}
				if matchResource.Group != gvr.Group {
					// Group doesn't match.
					continue
				}

				if matchResource.ResourceSelector != nil {
					selector, err := metav1.LabelSelectorAsSelector(matchResource.ResourceSelector)
					if err != nil {
						return nil, errors.New("policy with wrong match label selector")
					}
					if !selector.Matches(metalabels.Set(labels)) {
						continue
					}
				}
				// We found a set of match criteria that this resource satisfies
				foundMatch = true
				break
			}
			if !foundMatch {
				// We didn't find any match with the current resource types, so we continue looking for policies
				continue
			}
		}

		for _, pattern := range v.Images {
			if pattern.Glob != "" {
				if matched, err := glob.Match(pattern.Glob, image); err != nil {
					lastError = err
				} else if matched {
					ret[k] = v
				}
			}
		}
	}
	return ret, lastError
}
