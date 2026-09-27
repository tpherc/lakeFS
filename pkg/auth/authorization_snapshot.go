package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type policyAuthorizer interface {
	Authorizer
	ListEffectivePolicies(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error)
}

type authorizationPolicySnapshot struct {
	username      string
	policies      []*model.Policy
	bound         *boundPolicies
	principalTags principaltags.Tags
}

// PreparedAuthorization shares one policy snapshot between a candidate check and final authorization.
// It belongs to one request and user; it is not an authorization-result cache.
type PreparedAuthorization struct {
	authorizer Authorizer
	username   string
	snapshot   *authorizationPolicySnapshot
}

// PrepareAuthorization loads effective policies once without evaluating resource conditions.
func PrepareAuthorization(ctx context.Context, service policyAuthorizer, username string) (*PreparedAuthorization, error) {
	policies, _, err := service.ListEffectivePolicies(ctx, username, &model.PaginationParams{Amount: -1})
	if err != nil && !errors.Is(err, ErrNotImplemented) {
		return nil, err
	}
	prepared := &PreparedAuthorization{authorizer: service, username: username}
	if err == nil {
		// Effective policies are immutable service results, also shared by the existing policy cache.
		conditionCtx := NewRequestConditionContext(ctx, "")
		bound, err := preparePolicies(username, policies, conditionCtx)
		if err != nil {
			return nil, err
		}
		prepared.snapshot = &authorizationPolicySnapshot{username: username, policies: policies, bound: bound, principalTags: conditionCtx.principalTags}
	}
	return prepared, nil
}

// CanAuthorize rejects requests with no matching Allow candidate. A true result still requires Authorize.
// Conditions and Deny statements are evaluated only by final authorization with the resource attributes.
func (p *PreparedAuthorization) CanAuthorize(node permissions.Node) bool {
	if p.snapshot == nil {
		// Services such as BasicAuth cannot list policies; preserve their normal authorizer.
		return true
	}
	switch node.Type {
	case permissions.NodeTypeNode:
		return p.snapshot.bound.canAuthorize(node.Permission.Resource, node.Permission.Action)
	case permissions.NodeTypeAnd:
		for _, child := range node.Nodes {
			if !p.CanAuthorize(child) {
				return false
			}
		}
		return true
	case permissions.NodeTypeOr:
		for _, child := range node.Nodes {
			if p.CanAuthorize(child) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// Authorize delegates to the original authorizer with the policies loaded for this request.
func (p *PreparedAuthorization) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	if req == nil || req.Username != p.username {
		return nil, fmt.Errorf("prepared authorization belongs to another user: %w", ErrInvalidRequest)
	}
	preparedRequest := *req
	preparedRequest.policySnapshot = p.snapshot
	if p.snapshot != nil {
		ctx = WithPrincipalTags(ctx, p.snapshot.principalTags)
	}
	return p.authorizer.Authorize(ctx, &preparedRequest)
}

// AuthorizationPolicies uses a prepared snapshot only for the user it was loaded for.
func AuthorizationPolicies(ctx context.Context, req *AuthorizationRequest, list func(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error)) ([]*model.Policy, error) {
	if snapshot := req.policySnapshot; snapshot != nil && snapshot.username == req.Username {
		return snapshot.policies, nil
	}
	policies, _, err := list(ctx, req.Username, &model.PaginationParams{Amount: -1})
	return policies, err
}
