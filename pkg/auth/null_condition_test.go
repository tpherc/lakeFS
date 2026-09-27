package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestNullOperator(t *testing.T) {
	t.Parallel()
	operator, err := OperatorFactory(OperatorNameNull)
	require.NoError(t, err)

	// AWS treats an empty string as a null dataset for this operator:
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Null
	for _, test := range []struct {
		name   string
		fields map[string]string
		null   bool
	}{
		{name: "absent", null: true},
		{name: "empty string", fields: map[string]string{"classification": ""}, null: true},
		{name: "populated", fields: map[string]string{"classification": "S"}},
		{name: "literal null is a value", fields: map[string]string{"classification": "null"}},
		{name: "literal false is a value", fields: map[string]string{"classification": "false"}},
		{name: "whitespace is a value", fields: map[string]string{"classification": " "}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := NewConditionContextWithFields(test.fields)
			for _, candidate := range []struct {
				values []string
				want   bool
			}{
				{values: []string{"true"}, want: test.null},
				{values: []string{"false"}, want: !test.null},
				{values: []string{"true", "false"}, want: true},
			} {
				fields := map[string][]string{"classification": candidate.values}
				require.NoError(t, operator.Validate(fields))
				matched, err := operator.Evaluate(fields, ctx)
				require.NoError(t, err)
				require.Equal(t, candidate.want, matched, "values %v", candidate.values)
			}
		})
	}

	matched, err := operator.Evaluate(map[string][]string{"classification": {"true"}}, nil)
	require.ErrorIs(t, err, ErrInvalidConditionContext)
	require.False(t, matched)
}

func TestNullOperatorValidation(t *testing.T) {
	t.Parallel()
	operator := &NullOperator{}
	for _, test := range []struct {
		name   string
		field  string
		values []string
		err    error
	}{
		{name: "missing field", values: []string{"true"}, err: ErrMissingFieldName},
		{name: "variable field", field: "${aws:PrincipalTag/clr}", values: []string{"true"}, err: policytemplate.ErrInvalidTemplate},
		{name: "nil value list", field: "classification", err: ErrInvalidNullConditionValue},
		{name: "empty value list", field: "classification", values: []string{}, err: ErrInvalidNullConditionValue},
		{name: "empty value", field: "classification", values: []string{""}, err: ErrInvalidNullConditionValue},
		{name: "uppercase value", field: "classification", values: []string{"TRUE"}, err: ErrInvalidNullConditionValue},
		{name: "surrounding whitespace", field: "classification", values: []string{" false "}, err: ErrInvalidNullConditionValue},
		{name: "number", field: "classification", values: []string{"1"}, err: ErrInvalidNullConditionValue},
		{name: "variable value", field: "classification", values: []string{"${aws:PrincipalTag/clr}"}, err: ErrInvalidNullConditionValue},
		{name: "invalid alternative", field: "classification", values: []string{"true", "invalid"}, err: ErrInvalidNullConditionValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := map[string][]string{test.field: test.values}
			require.ErrorIs(t, operator.Validate(fields), test.err)
			matched, err := operator.Evaluate(fields, NewConditionContextWithFields(nil))
			require.ErrorIs(t, err, test.err)
			require.False(t, matched)
			policy := &model.Policy{Statement: model.Statements{{
				Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction},
				Resource:  permissions.ObjectArn("repo", "*"),
				Condition: map[string]map[string][]string{OperatorNameNull: fields},
			}}}
			require.ErrorIs(t, ValidatePolicyTemplates(policy), model.ErrValidationError)
		})
	}
}

func TestNullOperatorTrustedNamespacesAndBinding(t *testing.T) {
	t.Parallel()
	conditions := map[string]map[string][]string{OperatorNameNull: {
		"AWS:PRINCIPALTAG/CLR":          {"false"},
		"lakefs:ObjectMetadata/dcs:cls": {"false"},
	}}
	compiled, err := compileConditions(conditions)
	require.NoError(t, err)
	bound, err := compiled.bind(func(string) (string, bool) {
		t.Fatal("Null must not resolve variables or capture resource attributes when binding")
		return "", false
	})
	require.NoError(t, err)

	for _, test := range []struct {
		name     string
		tags     principaltags.Tags
		metadata map[string]string
		want     bool
	}{
		{name: "only public fields cannot spoof attributes"},
		{name: "both trusted namespaces present", tags: principaltags.Tags{"clr": "S"}, metadata: map[string]string{"dcs:cls": "S"}, want: true},
		{name: "principal key ignores case", tags: principaltags.Tags{"Clr": "S"}, metadata: map[string]string{"dcs:cls": "S"}, want: true},
		{name: "metadata key preserves case", tags: principaltags.Tags{"clr": "S"}, metadata: map[string]string{"DCS:CLS": "S"}},
		{name: "empty metadata is null", tags: principaltags.Tags{"clr": "S"}, metadata: map[string]string{"dcs:cls": ""}},
		{name: "missing metadata", tags: principaltags.Tags{"clr": "S"}},
		{name: "empty tag is null", tags: principaltags.Tags{"clr": ""}, metadata: map[string]string{"dcs:cls": "S"}},
		{name: "missing tag", metadata: map[string]string{"dcs:cls": "S"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := NewConditionContextWithFields(map[string]string{
				"AWS:PRINCIPALTAG/CLR": "S", "lakefs:ObjectMetadata/dcs:cls": "S",
			})
			ctx.AddPrincipalTags(test.tags)
			ctx.objectMetadata = test.metadata
			matched, err := bound.evaluate(ctx)
			require.NoError(t, err)
			require.Equal(t, test.want, matched)
		})
	}
}

func TestNullOperatorDenyOverridesAllow(t *testing.T) {
	t.Parallel()
	resource := permissions.ObjectArn("repo", "report.txt")
	for _, field := range []string{"aws:PrincipalTag/clr", "lakefs:ObjectMetadata/dcs:cls"} {
		t.Run(field, func(t *testing.T) {
			policies := []*model.Policy{{Statement: model.Statements{
				{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: resource},
				{
					Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: resource,
					Condition: map[string]map[string][]string{OperatorNameNull: {field: {"true"}}},
				},
			}}}
			for _, test := range []struct {
				name    string
				value   string
				present bool
				want    CheckResult
			}{
				{name: "missing denied", want: CheckDeny},
				{name: "empty denied", present: true, want: CheckDeny},
				{name: "classified allowed", value: "S", present: true, want: CheckAllow},
			} {
				t.Run(test.name, func(t *testing.T) {
					metadata := map[string]string{}
					tags := principaltags.Tags{}
					if test.present {
						metadata["dcs:cls"] = test.value
						tags["clr"] = test.value
					}
					ctx := WithPrincipalTags(context.Background(), tags)
					node := permissions.Node{Permission: permissions.Permission{
						Action: permissions.ReadObjectAction, Resource: resource, ObjectMetadata: metadata,
					}}
					audit := &MissingPermissions{}
					require.Equal(t, test.want, CheckPermissions(ctx, node, "alice", policies, audit))
					if test.want == CheckDeny {
						require.Equal(t, []string{permissions.ReadObjectAction}, audit.Denied)
					}
				})
			}
		})
	}
}

func TestNullDoesNotChangeOtherOperatorsMissingKeyBehavior(t *testing.T) {
	t.Parallel()
	for _, operator := range []string{OperatorNameStringLike, OperatorNameStringNotLike, OperatorNameStringEquals, OperatorNameStringNotEquals} {
		t.Run(operator, func(t *testing.T) {
			conditions := map[string]map[string][]string{
				OperatorNameNull: {"classification": {"true"}},
				operator:         {"classification": {"S"}},
			}
			matched, err := EvaluateConditions(conditions, NewConditionContextWithFields(nil))
			require.NoError(t, err)
			require.False(t, matched)
		})
	}
}
