package admissionpolicygenerator

import (
	"testing"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/ptr"
)

// podsMatchConstraints matches Pod CREATE requests only, which makes a policy eligible for pod
// controllers autogen.
func podsMatchConstraints() *admissionregistrationv1.MatchResources {
	return &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
			RuleWithOperations: admissionregistrationv1.RuleWithOperations{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"pods"},
				},
			},
		}},
	}
}

func vapGenEnabled() *policiesv1beta1.ValidatingPolicyAutogenConfiguration {
	return &policiesv1beta1.ValidatingPolicyAutogenConfiguration{
		ValidatingAdmissionPolicy: &policiesv1beta1.VapGenerationConfiguration{Enabled: ptr.To(true)},
	}
}

// TestVapGenerationSkipReason covers the decision of whether a ValidatingAdmissionPolicy may be
// generated for a ValidatingPolicy. Pod controllers autogen must be derived from the spec: the
// status is filled in asynchronously by the policy status controller, so a newly created policy
// has an empty status.autogen and used to get a VAP despite autogen being enabled.
func TestVapGenerationSkipReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		policy     *policiesv1beta1.ValidatingPolicy
		wantReason string
	}{
		{
			name:       "generation not enabled",
			policy:     &policiesv1beta1.ValidatingPolicy{},
			wantReason: "skip generating ValidatingAdmissionPolicy: not enabled.",
		},
		{
			name: "generation enabled, not eligible for autogen",
			policy: &policiesv1beta1.ValidatingPolicy{
				Spec: policiesv1beta1.ValidatingPolicySpec{AutogenConfiguration: vapGenEnabled()},
			},
		},
		{
			name: "generation enabled, autogen from spec while status is still empty",
			policy: &policiesv1beta1.ValidatingPolicy{
				Spec: policiesv1beta1.ValidatingPolicySpec{
					MatchConstraints:     podsMatchConstraints(),
					AutogenConfiguration: vapGenEnabled(),
					Validations:          []admissionregistrationv1.Validation{{Expression: "true"}},
				},
			},
			wantReason: "skip generating ValidatingAdmissionPolicy: pod controllers autogen is enabled.",
		},
		{
			// An explicitly empty controllers list disables autogen, so a VAP is still generated.
			name: "generation enabled, pod controllers autogen explicitly disabled",
			policy: &policiesv1beta1.ValidatingPolicy{
				Spec: policiesv1beta1.ValidatingPolicySpec{
					MatchConstraints: podsMatchConstraints(),
					AutogenConfiguration: &policiesv1beta1.ValidatingPolicyAutogenConfiguration{
						PodControllers:            &policiesv1beta1.PodControllersGenerationConfiguration{Controllers: []string{}},
						ValidatingAdmissionPolicy: &policiesv1beta1.VapGenerationConfiguration{Enabled: ptr.To(true)},
					},
					Validations: []admissionregistrationv1.Validation{{Expression: "true"}},
				},
			},
		},
		{
			name: "stale status claiming autogen is ignored",
			policy: &policiesv1beta1.ValidatingPolicy{
				Spec: policiesv1beta1.ValidatingPolicySpec{AutogenConfiguration: vapGenEnabled()},
				Status: policiesv1beta1.ValidatingPolicyStatus{
					Autogen: policiesv1beta1.ValidatingPolicyAutogenStatus{
						Configs: map[string]policiesv1beta1.ValidatingPolicyAutogen{"deployments": {}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reason, err := vapGenerationSkipReason(tt.policy)
			require.NoError(t, err)
			assert.Equal(t, tt.wantReason, reason)
		})
	}
}
