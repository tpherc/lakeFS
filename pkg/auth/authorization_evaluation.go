package auth

import (
	"context"

	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
)

// CheckRequestPermissions reuses a prepared request's bound policy snapshot.
// Calls without a snapshot prepare once before traversing the permission tree.
func CheckRequestPermissions(ctx context.Context, req *AuthorizationRequest, policies []*model.Policy, audit *MissingPermissions) CheckResult {
	if snapshot := req.policySnapshot; snapshot != nil && snapshot.username == req.Username {
		conditionCtx := NewConditionContext(req.ClientIP)
		// This map is private and immutable; permission leaves copy it before use.
		conditionCtx.principalTags = snapshot.principalTags
		ctx = context.WithValue(ctx, contextKeyConditionContext, conditionCtx)
		return snapshot.bound.checkPermissions(ctx, req.RequiredPermissions, audit)
	}
	ctx = WithRequestConditionContext(ctx, req.ClientIP)
	return CheckPermissions(ctx, req.RequiredPermissions, req.Username, policies, audit)
}

// CheckPermissions prepares policy syntax and request values before any
// permission-tree or statement short circuit can hide invalid templates.
func CheckPermissions(ctx context.Context, node permissions.Node, username string, policies []*model.Policy, audit *MissingPermissions) CheckResult {
	conditionCtx, _ := ctx.Value(contextKeyConditionContext).(*ConditionContext)
	if conditionCtx == nil {
		conditionCtx = NewRequestConditionContext(ctx, "")
		ctx = context.WithValue(ctx, contextKeyConditionContext, conditionCtx)
	}
	bound, err := preparePolicies(username, policies, conditionCtx)
	if err != nil {
		logging.FromContext(ctx).WithError(err).Warn("Failed to prepare authorization policies")
		return CheckDeny
	}
	return bound.checkPermissions(ctx, node, audit)
}

func (p *boundPolicies) checkPermission(resourceARN, action string, conditionCtx *ConditionContext) (CheckResult, string, error) {
	result := CheckNeutral
	for _, statement := range p.statements {
		passed, err := statement.conditions.evaluate(conditionCtx)
		if err != nil {
			return CheckDeny, "", err
		}
		if !passed || !statement.matchesResource(resourceARN) {
			continue
		}
		pattern, matches := statement.matchingAction(action)
		if !matches {
			continue
		}
		if statement.effect == model.StatementEffectDeny {
			return CheckDeny, pattern, nil
		}
		result = CheckAllow
	}
	return result, "", nil
}

func (p *boundPolicies) checkPermissions(ctx context.Context, node permissions.Node, audit *MissingPermissions) CheckResult {
	switch node.Type {
	case permissions.NodeTypeNode:
		conditionCtx := permissionConditionContext(ctx, node.Permission)
		result, deniedAction, err := p.checkPermission(node.Permission.Resource, node.Permission.Action, conditionCtx)
		if err != nil {
			log := logging.FromContext(ctx)
			if len(conditionCtx.Fields) > 0 {
				log = log.WithField("fields", conditionCtx.Fields)
			}
			log.WithError(err).Warn("Failed to evaluate conditions")
			return CheckDeny
		}
		switch result {
		case CheckDeny:
			audit.Denied = append(audit.Denied, deniedAction)
		case CheckNeutral:
			audit.Unauthorized = append(audit.Unauthorized, node.Permission.Action)
		}
		return result
	case permissions.NodeTypeOr:
		result := CheckNeutral
		for _, child := range node.Nodes {
			childResult := p.checkPermissions(ctx, child, audit)
			if childResult == CheckDeny {
				return CheckDeny
			}
			if childResult == CheckAllow {
				result = CheckAllow
			}
		}
		return result
	case permissions.NodeTypeAnd:
		for _, child := range node.Nodes {
			if result := p.checkPermissions(ctx, child, audit); result != CheckAllow {
				return result
			}
		}
		return CheckAllow
	default:
		logging.FromContext(ctx).Error("unknown permission node type")
		return CheckDeny
	}
}
