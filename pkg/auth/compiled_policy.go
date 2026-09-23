package auth

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/auth/wildcard"
)

var ErrInvalidPolicyTemplate = errors.New("invalid policy template")

type compiledResource struct {
	legacy   string
	prefix   string
	template *policytemplate.Template
}

type compiledStatement struct {
	effect     string
	actions    []string
	resources  []compiledResource
	conditions *compiledConditions
}

type compiledPolicies struct {
	statements []compiledStatement
}

type boundResource struct {
	pattern  string
	resolved bool
}

type boundStatement struct {
	effect     string
	actions    []string
	resources  []boundResource
	conditions *boundConditions
}

// boundPolicies belongs to one request. It never changes shared policy models.
type boundPolicies struct {
	statements []boundStatement
}

// ValidatePolicyTemplates validates all template syntax and allowed positions,
// including conditions on statements that would not match the current request.
// It complements the policy store's action, effect and identifier validation.
func ValidatePolicyTemplates(policy *model.Policy) error {
	_, err := compilePolicies([]*model.Policy{policy})
	if err != nil {
		return fmt.Errorf("%w: %w", model.ErrValidationError, err)
	}
	return nil
}

func compilePolicies(policies []*model.Policy) (*compiledPolicies, error) {
	compiled := &compiledPolicies{}
	for policyIndex, policy := range policies {
		if policy == nil {
			return nil, fmt.Errorf("%w: nil policy at index %d", ErrInvalidPolicyTemplate, policyIndex)
		}
		for statementIndex, statement := range policy.Statement {
			prepared, err := compileStatement(statement)
			if err != nil {
				return nil, fmt.Errorf("policy %d statement %d: %w", policyIndex, statementIndex, err)
			}
			compiled.statements = append(compiled.statements, prepared)
		}
	}
	return compiled, nil
}

func compileStatement(statement model.Statement) (compiledStatement, error) {
	for _, action := range statement.Action {
		if strings.Contains(action, "${") {
			return compiledStatement{}, fmt.Errorf("%w: variables are not allowed in actions", ErrInvalidPolicyTemplate)
		}
	}
	if strings.Contains(statement.Effect, "${") {
		return compiledStatement{}, fmt.Errorf("%w: variables are not allowed in effects", ErrInvalidPolicyTemplate)
	}
	conditions, err := compileConditions(statement.Condition)
	if err != nil {
		return compiledStatement{}, err
	}
	resources, err := ParsePolicyResourceAsList(statement.Resource)
	if err != nil {
		return compiledStatement{}, err
	}
	compiled := compiledStatement{
		effect: statement.Effect, actions: slices.Clone(statement.Action),
		conditions: conditions, resources: make([]compiledResource, 0, len(resources)),
	}
	for i, resource := range resources {
		prepared, err := compileResource(resource)
		if err != nil {
			return compiledStatement{}, fmt.Errorf("resource %d: %w", i, err)
		}
		compiled.resources = append(compiled.resources, prepared)
	}
	return compiled, nil
}

func compileResource(source string) (compiledResource, error) {
	// Preserve literal placeholders and whole-ARN ${user} replacement in legacy
	// resources, including usernames that contain wildcard characters.
	if !hasPrincipalTagReference(source) {
		return compiledResource{legacy: source}, nil
	}
	if len(source) > policytemplate.MaxSourceBytes {
		return compiledResource{}, policytemplate.ErrLimitExceeded
	}
	arn, err := ParseARN(source)
	if err != nil {
		return compiledResource{}, err
	}
	prefix := source[:len(source)-len(arn.ResourceID)]
	if strings.Contains(prefix, "${") {
		return compiledResource{}, fmt.Errorf("%w: a PrincipalTag resource requires a static ARN header", ErrInvalidPolicyTemplate)
	}
	template, err := policytemplate.Compile(arn.ResourceID)
	if err != nil {
		return compiledResource{}, err
	}
	return compiledResource{prefix: prefix, template: template}, nil
}

// Inspect reference names without allocating a folded copy of the entire ARN.
func hasPrincipalTagReference(source string) bool {
	for {
		_, rest, found := strings.Cut(source, "${")
		if !found {
			return false
		}
		name := rest
		if end := strings.IndexAny(name, "/},${"); end >= 0 {
			name = name[:end]
		}
		if strings.EqualFold(name, "aws:PrincipalTag") {
			return true
		}
		source = rest
	}
}

func (p *compiledPolicies) bind(username string, conditionCtx *ConditionContext) (*boundPolicies, error) {
	lookup := func(key string) (string, bool) {
		if key == "user" {
			return username, true
		}
		if conditionCtx == nil {
			return "", false
		}
		return conditionCtx.Lookup(key)
	}
	bound := &boundPolicies{statements: make([]boundStatement, 0, len(p.statements))}
	for i, statement := range p.statements {
		conditions, err := statement.conditions.bind(lookup)
		if err != nil {
			return nil, fmt.Errorf("statement %d conditions: %w", i, err)
		}
		prepared := boundStatement{
			effect: statement.effect, actions: statement.actions, conditions: conditions,
			resources: make([]boundResource, 0, len(statement.resources)),
		}
		for j, resource := range statement.resources {
			value, err := resource.bind(username, lookup)
			if err != nil {
				return nil, fmt.Errorf("statement %d resource %d: %w", i, j, err)
			}
			prepared.resources = append(prepared.resources, value)
		}
		bound.statements = append(bound.statements, prepared)
	}
	return bound, nil
}

func (r *compiledResource) bind(username string, lookup policytemplate.Lookup) (boundResource, error) {
	if r.template == nil {
		return boundResource{pattern: interpolateUser(r.legacy, username), resolved: true}, nil
	}
	value, resolved, err := r.template.Resolve(lookup)
	if err != nil {
		return boundResource{}, err
	}
	if len(value) > policytemplate.MaxResolvedBytes-len(r.prefix) {
		return boundResource{}, policytemplate.ErrLimitExceeded
	}
	return boundResource{pattern: r.prefix + value, resolved: resolved}, nil
}

func preparePolicies(username string, policies []*model.Policy, conditionCtx *ConditionContext) (*boundPolicies, error) {
	compiled, err := compilePolicies(policies)
	if err != nil {
		return nil, err
	}
	return compiled.bind(username, conditionCtx)
}

func (s *boundStatement) matchesResource(resourceARN string) bool {
	for _, resource := range s.resources {
		if resource.resolved && ArnMatch(resource.pattern, resourceARN) {
			return true
		}
	}
	return false
}

func (s *boundStatement) matchingAction(action string) (string, bool) {
	for _, pattern := range s.actions {
		if wildcard.Match(pattern, action) {
			return pattern, true
		}
	}
	return "", false
}

func (p *boundPolicies) canAuthorize(resourceARN, action string) bool {
	for _, statement := range p.statements {
		if statement.effect != model.StatementEffectAllow || !statement.matchesResource(resourceARN) {
			continue
		}
		if _, matches := statement.matchingAction(action); matches {
			return true
		}
	}
	return false
}

func cloneConditionContext(source *ConditionContext) *ConditionContext {
	if source == nil {
		return nil
	}
	return &ConditionContext{
		Fields: maps.Clone(source.Fields), principalTags: maps.Clone(source.principalTags),
		objectMetadata: maps.Clone(source.objectMetadata),
	}
}

// PermissionChecker reuses request-bound policies and a private attribute
// snapshot across repository filtering. It does not cache authorization results.
type PermissionChecker struct {
	policies     *boundPolicies
	conditionCtx *ConditionContext
}

func PreparePermissionChecker(username string, policies []*model.Policy, conditionCtx *ConditionContext) (*PermissionChecker, error) {
	conditionCtx = cloneConditionContext(conditionCtx)
	prepared, err := preparePolicies(username, policies, conditionCtx)
	if err != nil {
		return nil, err
	}
	return &PermissionChecker{policies: prepared, conditionCtx: conditionCtx}, nil
}

// Check evaluates one resource against the request snapshot, including all
// conditions and Deny statements. Errors never grant access.
func (c *PermissionChecker) Check(resourceARN, action string) (bool, error) {
	result, _, err := c.policies.checkPermission(resourceARN, action, c.conditionCtx)
	return result == CheckAllow && err == nil, err
}
