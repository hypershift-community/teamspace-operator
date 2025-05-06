package controllers

import (
	"context"
	"fmt"
	"strings"

	hypershiftv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// controlplaneNamespaceReconciler reconciles namespaces, RBAC and other resources for the team control plane namespaces
type controlplaneNamespaceReconciler struct {
	*TeamspaceReconciler
}

// TeamspaceReconciler is a generic struct to embed within specific Reconcilers.
type TeamspaceReconciler struct {
	client.Client
	InfraJSONPath string
	IAMJSONPath   string
	APIServerHost string
}

// Reconcile handles namespace creation for team workspaces
func (r *controlplaneNamespaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling")

	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, req.NamespacedName, namespace); err != nil {
		if apierrors.IsNotFound(err) {
			// Namespace not found, likely deleted, nothing to do
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get namespace: %w", err)
	}

	_, ok := namespace.Labels["hypershift.openshift.io/hosted-control-plane"]
	if !ok {
		// Not a teamspace namespace, nothing to do
		return ctrl.Result{}, nil
	}

	teamNamespace, err := r.getTeamNamespace(ctx, namespace.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get teamspace: %w", err)
	}
	if teamNamespace == "" {
		// No teamspace found, nothing to do
		logger.Info("No team namespace found, nothing to do", "controplane-namespace", namespace.Name)
		return ctrl.Result{}, nil
	}

	sa := teamNamespace

	// Create a RoleBinding to grant team access
	roleBinding := &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-admin", teamNamespace),
			Namespace: namespace.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa,
				Namespace: teamNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "admin",
		},
	}

	// Create or update the role binding using server-side apply
	if err := r.Patch(ctx, roleBinding, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create/update role binding: %w", err)
	}

	logger.Info("Successfully reconciled teamspace controlplane namespace")
	return ctrl.Result{}, nil
}

func (r *controlplaneNamespaceReconciler) getTeamNamespace(ctx context.Context, controlplaneNamespace string) (string, error) {
	logger := log.FromContext(ctx)

	hcpList := &hypershiftv1.HostedControlPlaneList{}
	if err := r.List(ctx, hcpList, client.InNamespace(controlplaneNamespace)); err != nil {
		return "", fmt.Errorf("failed to list hosted control planes: %w", err)
	}

	if len(hcpList.Items) == 0 {
		return "", fmt.Errorf("no hosted control planes found in namespace")
	}

	// Use the first HCP
	hcp := hcpList.Items[0]
	cluster, ok := hcp.Annotations["hypershift.openshift.io/cluster"]
	if !ok {
		return "", nil
	}
	// Split the cluster annotation value to extract the team name
	// Format is expected to be "team/environment" (e.g., "ingress-team/dev")
	parts := strings.Split(cluster, "/")
	if len(parts) < 2 {
		logger.Info("Invalid cluster annotation format", "cluster", cluster)
		return "", nil
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: parts[0],
		},
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(ns), ns); err != nil {
		return "", fmt.Errorf("failed to get team namespace: %w", err)
	}

	if ns.Labels["teamspace"] != "true" {
		return "", nil
	}

	return ns.Name, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TeamspaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	controlplaneNamespaceReconciler := &controlplaneNamespaceReconciler{
		TeamspaceReconciler: r,
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("controlplane-namespace-controller").
		For(&corev1.Namespace{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			namespace := obj.(*corev1.Namespace)
			return namespace.Labels["hypershift.openshift.io/hosted-control-plane"] == "true"
		})).
		Complete(controlplaneNamespaceReconciler); err != nil {
		return fmt.Errorf("failed to complete controlplane namespace reconciler: %w", err)
	}

	teamNamespaceReconciler := &teamNamespaceReconciler{
		TeamspaceReconciler: r,
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("team-namespace-controller").
		For(&corev1.Namespace{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			namespace := obj.(*corev1.Namespace)
			return namespace.Labels["teamspace"] == "true"
		})).
		Complete(teamNamespaceReconciler)
}
