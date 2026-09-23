package auth

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/auth/wildcard"
)

// compiledConditions owns policy syntax; it never contains request attributes.
type compiledConditions struct {
	requiresContext bool
	strings         []compiledStringCondition
	ips             []ipCondition
}

// boundConditions owns the resolved RHS values for one principal snapshot.
// Resource attributes are read only when evaluate is called for a permission.
type boundConditions struct {
	requiresContext bool
	strings         []boundStringCondition
	ips             []ipCondition
}

type stringCondition struct {
	field   string
	compare func(pattern, value string) bool
	negate  bool
}

type compiledStringCondition struct {
	stringCondition
	templates []*policytemplate.Template
}

type boundStringCondition struct {
	stringCondition
	values     []string
	unresolved bool
}

type ipCondition struct {
	field    string
	networks []*net.IPNet
	ips      []net.IP
	negate   bool
}

func compileConditions(conditions map[string]map[string][]string) (*compiledConditions, error) {
	compiled := &compiledConditions{requiresContext: len(conditions) > 0}
	for _, name := range slices.Sorted(maps.Keys(conditions)) {
		operator, err := OperatorFactory(name)
		if err != nil {
			return nil, err
		}
		fields := conditions[name]
		switch operator := operator.(type) {
		case *IpAddressOperator:
			fields, err := compileIPConditions(fields, operator)
			if err != nil {
				return nil, err
			}
			compiled.ips = append(compiled.ips, fields...)
		case *StringMatchOperator:
			fields, err := compileStringConditions(fields, wildcardComparison, operator.negate)
			if err != nil {
				return nil, err
			}
			compiled.strings = append(compiled.strings, fields...)
		case *StringEqualsOperator:
			fields, err := compileStringConditions(fields, exactComparison, operator.negate)
			if err != nil {
				return nil, err
			}
			compiled.strings = append(compiled.strings, fields...)
		default:
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedConditionOperator, name)
		}
	}
	return compiled, nil
}

func validateConditionField(field string) error {
	if field == "" {
		return ErrMissingFieldName
	}
	if strings.Contains(field, "${") {
		return fmt.Errorf("condition field must be literal: %w", policytemplate.ErrInvalidTemplate)
	}
	return nil
}

func compileStringConditions(fields map[string][]string, compare func(string, string) bool, negate bool) ([]compiledStringCondition, error) {
	compiled := make([]compiledStringCondition, 0, len(fields))
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		if err := validateConditionField(field); err != nil {
			return nil, err
		}
		condition := compiledStringCondition{
			stringCondition: stringCondition{field: field, compare: compare, negate: negate},
			templates:       make([]*policytemplate.Template, 0, len(fields[field])),
		}
		for _, value := range fields[field] {
			template, err := policytemplate.Compile(value)
			if err != nil {
				return nil, fmt.Errorf("compile string condition: %w", err)
			}
			if template.UsesUser() {
				return nil, fmt.Errorf("user variable is limited to resources: %w", policytemplate.ErrInvalidTemplate)
			}
			condition.templates = append(condition.templates, template)
		}
		compiled = append(compiled, condition)
	}
	return compiled, nil
}

func compileIPConditions(fields map[string][]string, operator *IpAddressOperator) ([]ipCondition, error) {
	normalized := make(map[string][]string, len(fields))
	for field, values := range fields {
		if err := validateConditionField(field); err != nil {
			return nil, err
		}
		normalized[field] = make([]string, len(values))
		for index, value := range values {
			if strings.Contains(value, "${") {
				return nil, fmt.Errorf("IP condition values must be literal: %w", policytemplate.ErrInvalidTemplate)
			}
			normalized[field][index] = strings.TrimSpace(value)
		}
	}
	if err := operator.Validate(normalized); err != nil {
		return nil, err
	}
	compiled := make([]ipCondition, 0, len(fields))
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		condition := ipCondition{field: field, negate: operator.negate}
		for _, value := range normalized[field] {
			if _, network, err := net.ParseCIDR(value); err == nil {
				condition.networks = append(condition.networks, network)
			} else {
				condition.ips = append(condition.ips, net.ParseIP(value))
			}
		}
		compiled = append(compiled, condition)
	}
	return compiled, nil
}

func (c *compiledConditions) bind(lookup policytemplate.Lookup) (*boundConditions, error) {
	bound := &boundConditions{requiresContext: c.requiresContext, ips: c.ips, strings: make([]boundStringCondition, 0, len(c.strings))}
	for _, condition := range c.strings {
		field := boundStringCondition{
			stringCondition: condition.stringCondition,
			values:          make([]string, 0, len(condition.templates)),
		}
		for _, template := range condition.templates {
			value, present, err := template.Resolve(lookup)
			if err != nil {
				return nil, fmt.Errorf("resolve string condition: %w", err)
			}
			if !present {
				field.unresolved = true
				continue
			}
			field.values = append(field.values, value)
		}
		bound.strings = append(bound.strings, field)
	}
	return bound, nil
}

func (c *boundConditions) evaluate(ctx *ConditionContext) (bool, error) {
	if !c.requiresContext {
		return true, nil
	}
	if ctx == nil {
		return false, ErrInvalidConditionContext
	}
	passed := true
	for _, condition := range c.ips {
		matches, err := condition.evaluate(ctx)
		if err != nil {
			return false, err
		}
		passed = passed && matches
	}
	for _, condition := range c.strings {
		if !condition.evaluate(ctx) {
			passed = false
		}
	}
	return passed, nil
}

func (c boundStringCondition) evaluate(ctx *ConditionContext) bool {
	if c.unresolved {
		return false
	}
	value, present := ctx.Lookup(c.field)
	if !present {
		return false
	}
	matched := false
	for _, candidate := range c.values {
		if c.compare(candidate, value) {
			matched = true
			break
		}
	}
	return matched != c.negate
}

func (c ipCondition) evaluate(ctx *ConditionContext) (bool, error) {
	value, present := ctx.Lookup(c.field)
	if !present || value == "" {
		return false, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false, fmt.Errorf("%w in field %s", ErrInvalidIPFormat, c.field)
	}
	for _, network := range c.networks {
		if network.Contains(ip) {
			return !c.negate, nil
		}
	}
	for _, candidate := range c.ips {
		if candidate.Equal(ip) {
			return !c.negate, nil
		}
	}
	return c.negate, nil
}

func exactComparison(pattern, value string) bool {
	return pattern == value
}

func wildcardComparison(pattern, value string) bool {
	return wildcard.Match(pattern, value)
}
