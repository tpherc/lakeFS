package auth

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
)

func TestPreparedConditionsStringOperators(t *testing.T) {
	t.Parallel()
	operators := []string{OperatorNameStringEquals, OperatorNameStringNotEquals, OperatorNameStringLike, OperatorNameStringNotLike}
	tests := []struct {
		name     string
		values   []string
		actual   string
		tags     principaltags.Tags
		expected [4]bool
	}{
		{"matching tag", []string{"${aws:PrincipalTag/team}"}, "research", principaltags.Tags{"team": "research"}, [4]bool{true, false, true, false}},
		{"different tag", []string{"${aws:PrincipalTag/team}"}, "finance", principaltags.Tags{"team": "research"}, [4]bool{false, true, false, true}},
		{"case folded key", []string{"${AWS:PRINCIPALTAG/TEAM}"}, "research", principaltags.Tags{"Team": "research"}, [4]bool{true, false, true, false}},
		{"case sensitive value", []string{"${aws:PrincipalTag/team}"}, "Research", principaltags.Tags{"team": "research"}, [4]bool{false, true, false, true}},
		{"embedded reference", []string{"home/${aws:PrincipalTag/team}/*"}, "home/research/file", principaltags.Tags{"team": "research"}, [4]bool{false, true, true, false}},
		{"literal wildcard", []string{"team-*"}, "team-a", nil, [4]bool{false, true, true, false}},
		{"present empty", []string{"${aws:PrincipalTag/team}"}, "", principaltags.Tags{"team": ""}, [4]bool{true, false, true, false}},
		{"missing reference", []string{"${aws:PrincipalTag/team}"}, "research", nil, [4]bool{}},
		{"missing reference after matching literal", []string{"research", "${aws:PrincipalTag/team}"}, "research", nil, [4]bool{}},
		{"missing reference before matching literal", []string{"${aws:PrincipalTag/team}", "research"}, "research", nil, [4]bool{}},
		{"negation after OR", []string{"finance", "${aws:PrincipalTag/team}"}, "research", principaltags.Tags{"team": "research"}, [4]bool{true, false, true, false}},
		{"reversed OR", []string{"${aws:PrincipalTag/team}", "finance"}, "research", principaltags.Tags{"team": "research"}, [4]bool{true, false, true, false}},
		{"empty candidates", nil, "research", nil, [4]bool{false, true, false, true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index, operator := range operators {
				t.Run(operator, func(t *testing.T) {
					ctx := NewConditionContextWithFields(map[string]string{"object-team": test.actual})
					ctx.AddPrincipalTags(test.tags)
					conditions := map[string]map[string][]string{operator: {"object-team": test.values}}
					matched, err := EvaluateConditions(conditions, ctx)
					require.NoError(t, err)
					require.Equal(t, test.expected[index], matched)
				})
			}
		})
	}
}

func TestPreparedConditionsMissingLeftHandSide(t *testing.T) {
	t.Parallel()
	for _, operator := range []string{OperatorNameStringEquals, OperatorNameStringNotEquals, OperatorNameStringLike, OperatorNameStringNotLike} {
		t.Run(operator, func(t *testing.T) {
			ctx := NewConditionContextWithFields(nil)
			ctx.AddPrincipalTags(principaltags.Tags{"team": "research"})
			matched, err := EvaluateConditions(map[string]map[string][]string{operator: {"missing": {"${aws:PrincipalTag/team}"}}}, ctx)
			require.NoError(t, err)
			require.False(t, matched)
		})
	}
}

func TestPreparedConditionsRejectInvalidPolicyBeforeEvaluation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		conditions map[string]map[string][]string
		err        error
	}{
		{"empty field", map[string]map[string][]string{OperatorNameStringLike: {"": {"*"}}}, ErrMissingFieldName},
		{"variable field", map[string]map[string][]string{OperatorNameStringLike: {"${aws:PrincipalTag/team}": {"*"}}}, policytemplate.ErrInvalidTemplate},
		{"user reference", map[string]map[string][]string{OperatorNameStringEquals: {"field": {"${user}"}}}, policytemplate.ErrInvalidTemplate},
		{"IP reference", map[string]map[string][]string{OperatorNameIpAddress: {"SourceIp": {"${aws:PrincipalTag/ip}"}}}, policytemplate.ErrInvalidTemplate},
		{"invalid IP after valid IP", map[string]map[string][]string{OperatorNameIpAddress: {"SourceIp": {"192.0.2.1", "invalid"}}}, ErrInvalidIPCIDRFormat},
		{"unknown operator", map[string]map[string][]string{"Unsupported": {"field": {"value"}}}, ErrUnsupportedConditionOperator},
		{"malformed after matching candidate", map[string]map[string][]string{OperatorNameStringLike: {"field": {"*", "${aws:PrincipalTag/team"}}}, policytemplate.ErrInvalidTemplate},
		{"malformed alongside failing operator", map[string]map[string][]string{OperatorNameStringEquals: {"field": {"no-match"}}, OperatorNameStringNotLike: {"field": {"${aws:PrincipalTag/team"}}}, policytemplate.ErrInvalidTemplate},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := NewConditionContextWithFields(map[string]string{"field": "value", "SourceIp": "192.0.2.1"})
			matched, err := EvaluateConditions(test.conditions, ctx)
			require.ErrorIs(t, err, test.err)
			require.False(t, matched)
		})
	}
}

func TestPreparedConditionsBindingErrorsOutrankUnresolved(t *testing.T) {
	t.Parallel()
	const secret = "sensitive-tag-value*"
	for _, values := range [][]string{
		{"${aws:PrincipalTag/missing}", "${aws:PrincipalTag/unsafe}"},
		{"${aws:PrincipalTag/unsafe}", "${aws:PrincipalTag/missing}"},
		{"matched", "${aws:PrincipalTag/unsafe}"},
	} {
		for _, operator := range []string{OperatorNameStringEquals, OperatorNameStringNotEquals, OperatorNameStringLike, OperatorNameStringNotLike} {
			ctx := NewConditionContextWithFields(map[string]string{"field": "matched"})
			ctx.AddPrincipalTags(principaltags.Tags{"unsafe": secret})
			matched, err := EvaluateConditions(map[string]map[string][]string{operator: {"field": values}}, ctx)
			require.ErrorIs(t, err, policytemplate.ErrWildcardValue)
			require.NotContains(t, err.Error(), secret)
			require.False(t, matched)
		}
	}
	ctx := NewConditionContextWithFields(nil)
	ctx.AddPrincipalTags(principaltags.Tags{"unsafe": secret})
	matched, err := EvaluateConditions(map[string]map[string][]string{
		OperatorNameStringNotEquals: {"a": {"${aws:PrincipalTag/missing}"}, "z": {"${aws:PrincipalTag/unsafe}"}},
	}, ctx)
	require.ErrorIs(t, err, policytemplate.ErrWildcardValue)
	require.False(t, matched)
}

func TestPreparedConditionsUseTrustedLookup(t *testing.T) {
	t.Parallel()
	ctx := NewConditionContextWithFields(map[string]string{
		"object-team":           "research",
		"aws:PrincipalTag/team": "research",
	})
	conditions := map[string]map[string][]string{OperatorNameStringEquals: {"object-team": {"${aws:PrincipalTag/team}"}}}
	matched, err := EvaluateConditions(conditions, ctx)
	require.NoError(t, err)
	require.False(t, matched, "public fields cannot provide a trusted PrincipalTag")
	ctx.AddPrincipalTags(principaltags.Tags{"team": "finance"})
	matched, err = EvaluateConditions(conditions, ctx)
	require.NoError(t, err)
	require.False(t, matched)
}

func TestPreparedConditionsBindOnceAndIsolatePolicy(t *testing.T) {
	t.Parallel()
	conditions := map[string]map[string][]string{
		OperatorNameStringEquals: {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}},
		OperatorNameIpAddress:    {"SourceIp": {" 192.0.2.0/24 "}},
	}
	compiled, err := compileConditions(conditions)
	require.NoError(t, err)
	conditions[OperatorNameStringEquals]["lakefs:ObjectMetadata/team"][0] = "changed"
	conditions[OperatorNameIpAddress]["SourceIp"][0] = "invalid"
	ctx := NewConditionContext("192.0.2.10")
	ctx.AddPrincipalTags(principaltags.Tags{"team": "research"})
	lookups := 0
	bound, err := compiled.bind(func(key string) (string, bool) {
		lookups++
		return ctx.Lookup(key)
	})
	require.NoError(t, err)
	require.Equal(t, 1, lookups)
	ctx.AddPrincipalTags(principaltags.Tags{"team": "finance"})
	ctx.objectMetadata = map[string]string{"team": "research"}
	matched, err := bound.evaluate(ctx)
	require.NoError(t, err)
	require.True(t, matched)
	ctx.objectMetadata["team"] = "finance"
	matched, err = bound.evaluate(ctx)
	require.NoError(t, err)
	require.False(t, matched)
	require.Equal(t, 1, lookups, "permission evaluation must not resolve variables again")
}

func TestPreparedConditionsConcurrentBindings(t *testing.T) {
	t.Parallel()
	compiled, err := compileConditions(map[string]map[string][]string{
		OperatorNameStringEquals: {"field": {"${aws:PrincipalTag/team}"}},
	})
	require.NoError(t, err)
	var workers sync.WaitGroup
	for _, team := range []string{"research", "finance", "engineering"} {
		workers.Go(func() {
			ctx := NewConditionContextWithFields(map[string]string{"field": team})
			ctx.AddPrincipalTags(principaltags.Tags{"team": team})
			bound, err := compiled.bind(ctx.Lookup)
			if err != nil {
				t.Error(err)
				return
			}
			matched, err := bound.evaluate(ctx)
			if err != nil || !matched {
				t.Errorf("binding for %s: matched=%v, error=%v", team, matched, err)
			}
		})
	}
	workers.Wait()
}

func TestStringOperatorValidationAndNilContext(t *testing.T) {
	t.Parallel()
	for _, name := range []string{OperatorNameStringEquals, OperatorNameStringNotEquals, OperatorNameStringLike, OperatorNameStringNotLike} {
		t.Run(name, func(t *testing.T) {
			operator, err := OperatorFactory(name)
			require.NoError(t, err)
			require.ErrorIs(t, operator.Validate(map[string][]string{"field": {"${user}"}}), policytemplate.ErrInvalidTemplate)
			_, err = operator.Evaluate(map[string][]string{"field": {"literal"}}, nil)
			require.ErrorIs(t, err, ErrInvalidConditionContext)
			matched, err := operator.Evaluate(nil, nil)
			require.NoError(t, err)
			require.True(t, matched)
		})
	}
	_, err := EvaluateConditions(map[string]map[string][]string{OperatorNameStringEquals: {"field": {"${user}"}}}, nil)
	require.ErrorIs(t, err, policytemplate.ErrInvalidTemplate, "compile before checking the request context")
}

func TestPreparedEmptyConditionRequiresContext(t *testing.T) {
	t.Parallel()
	for _, operator := range []string{OperatorNameStringEquals, OperatorNameStringNotEquals, OperatorNameStringLike, OperatorNameStringNotLike, OperatorNameIpAddress, OperatorNameNotIpAddress} {
		t.Run(operator, func(t *testing.T) {
			compiled, err := compileConditions(map[string]map[string][]string{operator: {}})
			require.NoError(t, err)
			bound, err := compiled.bind(nil)
			require.NoError(t, err)
			passed, err := bound.evaluate(nil)
			require.ErrorIs(t, err, ErrInvalidConditionContext)
			require.False(t, passed)
			passed, err = bound.evaluate(NewConditionContext(""))
			require.NoError(t, err)
			require.True(t, passed)
		})
	}
}
