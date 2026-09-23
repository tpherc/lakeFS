package auth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"strings"

	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/permissions"
)

const (
	OperatorNameIpAddress       = "IpAddress"
	OperatorNameNotIpAddress    = "NotIpAddress"
	OperatorNameStringLike      = "StringLike"
	OperatorNameStringNotLike   = "StringNotLike"
	OperatorNameStringEquals    = "StringEquals"
	OperatorNameStringNotEquals = "StringNotEquals"
)

var (
	ErrMissingFieldName             = errors.New("missing field name")
	ErrInvalidIPCIDRFormat          = errors.New("invalid IP/CIDR format")
	ErrInvalidConditionContext      = errors.New("invalid condition context")
	ErrInvalidIPFormat              = errors.New("invalid IP format")
	ErrUnsupportedConditionOperator = errors.New("unsupported condition operator")
)

// ConditionContext holds contextual information for condition evaluation
// Fields is a map of field names to their string values (e.g., {"SourceIp": "203.0.113.5", "VpcId": "vpc-123"})
type ConditionContext struct {
	Fields         map[string]string
	principalTags  principaltags.Tags
	objectMetadata map[string]string
}

// ConditionOperator defines the interface for different condition operators
type ConditionOperator interface {
	// Evaluate checks if the condition fields and values match the context
	// fields is a map of field names to arrays of values (e.g., {"SourceIp": ["10.0.0.0/8", "192.168.1.0/24"]})
	Evaluate(fields map[string][]string, conditionCtx *ConditionContext) (bool, error)
	// Validate checks if the condition fields and values are valid
	Validate(fields map[string][]string) error
}

// IpAddressOperator handles IP address matching with CIDR notation support
// Dynamically checks all field names that contain IP addresses in the condition
type IpAddressOperator struct {
	// negate determines whether to negate the matching result
	negate bool
}

// Validate implements ConditionOperator.
func (op *IpAddressOperator) Validate(fields map[string][]string) error {
	// Validate operator-specific constraints
	for field, values := range fields {
		// Field name can't be empty
		if field == "" {
			return ErrMissingFieldName
		}
		// Validate IP/CIDR format
		for _, value := range values {
			if _, _, err := net.ParseCIDR(value); err != nil {
				if net.ParseIP(value) == nil {
					return fmt.Errorf("%w in %s for '%s': %s",
						ErrInvalidIPCIDRFormat, OperatorNameIpAddress, field, value)
				}
			}
		}
	}
	return nil
}

// Evaluate checks if the client IP matches any of the IP fields in the condition
// It iterates over all field names and checks them against context
func (op *IpAddressOperator) Evaluate(fields map[string][]string, conditionCtx *ConditionContext) (bool, error) {
	// If no fields specified in condition, the condition passes
	if len(fields) == 0 {
		return true, nil
	}
	if conditionCtx == nil {
		return false, ErrInvalidConditionContext
	}

	// Check each field in the condition against context values (AND logic between fields)
	for fieldName, conditionValues := range fields {
		// No field or empty value for the field - condition fails
		contextValue, hasField := conditionCtx.Lookup(fieldName)
		if !hasField {
			return false, nil
		}
		if contextValue == "" {
			return false, nil
		}

		// Parse the context value as an IP address
		contextIP := net.ParseIP(contextValue)
		if contextIP == nil {
			return false, fmt.Errorf("%w in field %s", ErrInvalidIPFormat, fieldName)
		}

		// Check if context IP matches any of the condition values for this field (OR logic within field)
		fieldMatched := false
		for _, value := range conditionValues {
			value = strings.TrimSpace(value)

			// First try to parse as CIDR
			if _, ipNet, err := net.ParseCIDR(value); err == nil {
				if ipNet.Contains(contextIP) {
					fieldMatched = true
					break
				}
				continue
			}

			// Try to parse as a single IP address
			if singleIP := net.ParseIP(value); singleIP != nil {
				if contextIP.Equal(singleIP) {
					fieldMatched = true
					break
				}
				continue
			}

			// Invalid format
			return false, fmt.Errorf("%w in field %s: %s", ErrInvalidIPCIDRFormat, fieldName, value)
		}

		// For IpAddress: fail if field didn't match
		// For NotIpAddress: fail if field matched
		if fieldMatched == op.negate {
			return false, nil
		}
	}

	// All fields processed successfully - condition passes
	return true, nil
}

// StringMatchOperator implements string matching condition operators (StringLike, StringNotLike).
// Supports '*' for multi-character wildcards and '?' for single-character wildcards.
type StringMatchOperator struct {
	// negate determines whether to negate the matching result (for StringNotLike)
	negate bool
}

// Validate checks field names and policy variable syntax.
func (op *StringMatchOperator) Validate(fields map[string][]string) error {
	_, err := compileStringConditions(fields, wildcardComparison, op.negate)
	return err
}

// Evaluate combines candidates with OR, fields with AND, and negates each field once.
func (op *StringMatchOperator) Evaluate(fields map[string][]string, conditionCtx *ConditionContext) (bool, error) {
	if len(fields) == 0 {
		return true, nil
	}
	operatorName := OperatorNameStringLike
	if op.negate {
		operatorName = OperatorNameStringNotLike
	}
	return EvaluateConditions(map[string]map[string][]string{operatorName: fields}, conditionCtx)
}

// StringEqualsOperator compares strings literally, including '*' and '?'.
type StringEqualsOperator struct {
	negate bool
}

func (op *StringEqualsOperator) Validate(fields map[string][]string) error {
	_, err := compileStringConditions(fields, exactComparison, op.negate)
	return err
}

func (op *StringEqualsOperator) Evaluate(fields map[string][]string, conditionCtx *ConditionContext) (bool, error) {
	if len(fields) == 0 {
		return true, nil
	}
	operatorName := OperatorNameStringEquals
	if op.negate {
		operatorName = OperatorNameStringNotEquals
	}
	return EvaluateConditions(map[string]map[string][]string{operatorName: fields}, conditionCtx)
}

// OperatorFactory returns the appropriate operator for a given operator name
func OperatorFactory(operatorName string) (ConditionOperator, error) {
	switch operatorName {
	case OperatorNameIpAddress:
		return &IpAddressOperator{negate: false}, nil
	case OperatorNameNotIpAddress:
		return &IpAddressOperator{negate: true}, nil
	case OperatorNameStringLike:
		return &StringMatchOperator{negate: false}, nil
	case OperatorNameStringNotLike:
		return &StringMatchOperator{negate: true}, nil
	case OperatorNameStringEquals:
		return &StringEqualsOperator{negate: false}, nil
	case OperatorNameStringNotEquals:
		return &StringEqualsOperator{negate: true}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedConditionOperator, operatorName)
	}
}

// EvaluateConditions checks if all conditions in the map are satisfied
// conditions is a map where keys are operator names and values are maps of field names to value arrays
// AWS IAM format: {"IpAddress": {"SourceIp": ["203.0.113.0/24", "198.51.100.25/32"]}}
// Returns true only if all conditions pass (AND logic)
func EvaluateConditions(conditions map[string]map[string][]string, conditionCtx *ConditionContext) (bool, error) {
	compiled, err := compileConditions(conditions)
	if err != nil {
		return false, err
	}
	if len(conditions) == 0 {
		return true, nil
	}
	if conditionCtx == nil {
		return false, ErrInvalidConditionContext
	}
	bound, err := compiled.bind(conditionCtx.Lookup)
	if err != nil {
		return false, err
	}
	return bound.evaluate(conditionCtx)
}

// NewConditionContext creates a ConditionContext with the client IP in the SourceIp field
// This is the standard way to enrich context with client IP for IpAddress conditions
func NewConditionContext(clientIP string) *ConditionContext {
	return &ConditionContext{
		Fields: map[string]string{
			"SourceIp": clientIP,
		},
	}
}

// NewConditionContextWithFields creates a ConditionContext with custom field values
// This allows flexibility for future condition operators that may need different fields
func NewConditionContextWithFields(fields map[string]string) *ConditionContext {
	return &ConditionContext{
		Fields: fields,
	}
}

// AddPrincipalTags copies validated tags into a private, case-insensitive namespace.
// Keeping them separate from Fields prevents routine authorization logs from exposing values.
func (c *ConditionContext) AddPrincipalTags(tags principaltags.Tags) {
	c.principalTags = make(principaltags.Tags, len(tags))
	for key, value := range tags {
		c.principalTags[principaltags.FoldKey(key)] = value
	}
}

// Lookup reserves trusted attribute namespaces and folds only PrincipalTag keys.
func (c *ConditionContext) Lookup(fieldName string) (string, bool) {
	const prefix = "aws:PrincipalTag/"
	if namespace, key, found := strings.Cut(fieldName, "/"); found && strings.EqualFold(namespace+"/", prefix) {
		value, ok := c.principalTags[principaltags.FoldKey(key)]
		return value, ok
	}
	if key, found := strings.CutPrefix(fieldName, "lakefs:ObjectMetadata/"); found {
		value, ok := c.objectMetadata[key]
		return value, ok
	}
	value, ok := c.Fields[fieldName]
	return value, ok
}

// NewRequestConditionContext builds policy context from the authenticated principal snapshot.
func NewRequestConditionContext(ctx context.Context, clientIP string) *ConditionContext {
	conditionCtx := NewConditionContext(clientIP)
	if tags, ok := PrincipalTagsFromContext(ctx); ok {
		conditionCtx.AddPrincipalTags(tags)
	}
	return conditionCtx
}

// WithRequestConditionContext makes the request attributes available to CheckPermissions.
func WithRequestConditionContext(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, contextKeyConditionContext, NewRequestConditionContext(ctx, clientIP))
}

// permissionConditionContext isolates resource attributes to one permission leaf.
func permissionConditionContext(ctx context.Context, permission permissions.Permission) *ConditionContext {
	conditionCtx := &ConditionContext{}
	if requestCtx, ok := ctx.Value(contextKeyConditionContext).(*ConditionContext); ok && requestCtx != nil {
		conditionCtx.Fields = maps.Clone(requestCtx.Fields)
		conditionCtx.principalTags = maps.Clone(requestCtx.principalTags)
	}
	if permission.Action == permissions.ReadObjectAction {
		conditionCtx.objectMetadata = maps.Clone(permission.ObjectMetadata)
	}
	return conditionCtx
}
