package auth

import (
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/wildcard"
)

// HasActionOnAnyResource checks if a user has a specific action on ANY resource.
// This is used for list-type operations where we want to verify the user has
// some permission before filtering results, rather than requiring wildcard access.
// Returns true if the user has at least one allow statement for the action.
func HasActionOnAnyResource(policies []*model.Policy, action string) bool {
	for _, policy := range policies {
		for _, stmt := range policy.Statement {
			if stmt.Effect != model.StatementEffectAllow {
				continue
			}
			for _, stmtAction := range stmt.Action {
				if wildcard.Match(stmtAction, action) {
					return true
				}
			}
		}
	}
	return false
}

// HasPermissionOnResource checks if a user has at least one Allow statement
// matching the given action and resource ARN, ignoring conditions.
// This is useful for fast-fail gates where we want to know if the user has
// any policy granting access to this resource, regardless of conditions.
func HasPermissionOnResource(resourceArn, username string, policies []*model.Policy, action string, conditionCtx *ConditionContext) bool {
	prepared, err := preparePolicies(username, policies, conditionCtx)
	return err == nil && prepared.canAuthorize(resourceArn, action)
}

// CheckPermission evaluates a single resource. Repeated filtering should use
// PreparePermissionChecker so policy compilation and binding happen only once.
func CheckPermission(resourceArn, username string, policies []*model.Policy, action string, conditionCtx *ConditionContext) (bool, error) {
	checker, err := PreparePermissionChecker(username, policies, conditionCtx)
	if err != nil {
		return false, err
	}
	return checker.Check(resourceArn, action)
}
