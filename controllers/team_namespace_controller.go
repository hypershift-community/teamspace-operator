package controllers

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"encoding/base64"
	"encoding/json"

	hypershiftv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
	ipnet "github.com/openshift/hypershift/api/util/ipnet"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ptr "k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// teamNamespaceReconciler reconciles namespaces, RBAC and other resources for team higher level namespace
type teamNamespaceReconciler struct {
	*TeamspaceReconciler
}

func (r *teamNamespaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling team namespace")

	// Get the namespace
	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, req.NamespacedName, namespace); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get namespace: %w", err)
	}

	// Check if this is a teamspace namespace
	if namespace.Labels["teamspace"] != "true" {
		return ctrl.Result{}, nil
	}

	teamspace := namespace.Name
	saName := teamspace
	secretName := fmt.Sprintf("%s-token", teamspace)
	kubeconfigSecretName := fmt.Sprintf("%s-kubeconfig", teamspace)
	clusterName := fmt.Sprintf("%s-cluster", teamspace)
	userName := fmt.Sprintf("%s-user", teamspace)
	contextName := fmt.Sprintf("%s-context", teamspace)
	roleName := fmt.Sprintf("%s-hypershift-role", teamspace)
	roleBindingHS := fmt.Sprintf("%s-hypershift-binding", teamspace)
	roleBindingAdmin := fmt.Sprintf("%s-admin-binding", teamspace)
	kubePublicRole := fmt.Sprintf("%s-kube-public-reader", teamspace)
	kubePublicBinding := fmt.Sprintf("%s-kube-public-binding", teamspace)
	nsPatchRole := fmt.Sprintf("%s-namespace-patch", teamspace)
	nsPatchBinding := fmt.Sprintf("%s-namespace-patch-binding", teamspace)

	// Create ServiceAccount
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: teamspace,
		},
	}
	if err := r.Patch(ctx, sa, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create service account: %w", err)
	}

	// Create token secret
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: teamspace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": saName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
	if err := r.Patch(ctx, secret, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create token secret: %w", err)
	}

	// Create Hypershift Role
	hypershiftRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: teamspace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"hypershift.openshift.io"},
				Resources: []string{"*"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
		},
	}
	if err := r.Patch(ctx, hypershiftRole, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create hypershift role: %w", err)
	}

	// Create Hypershift RoleBinding
	hypershiftBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingHS,
			Namespace: teamspace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: teamspace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
	}
	if err := r.Patch(ctx, hypershiftBinding, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create hypershift role binding: %w", err)
	}

	// Create Admin RoleBinding
	adminBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingAdmin,
			Namespace: teamspace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: teamspace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "admin",
		},
	}
	if err := r.Patch(ctx, adminBinding, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create admin role binding: %w", err)
	}

	// Create kube-public Role
	kubePublicRoleObj := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubePublicRole,
			Namespace: "kube-public",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	if err := r.Patch(ctx, kubePublicRoleObj, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create kube-public role: %w", err)
	}

	// Create kube-public RoleBinding
	kubePublicBindingObj := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubePublicBinding,
			Namespace: "kube-public",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: teamspace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     kubePublicRole,
		},
	}
	if err := r.Patch(ctx, kubePublicBindingObj, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create kube-public role binding: %w", err)
	}

	// Create namespace patch Role
	nsPatchRoleObj := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsPatchRole,
			Namespace: teamspace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"namespaces"},
				ResourceNames: []string{teamspace},
				Verbs:         []string{"patch"},
			},
		},
	}
	if err := r.Patch(ctx, nsPatchRoleObj, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create namespace patch role: %w", err)
	}

	// Create namespace patch RoleBinding
	nsPatchBindingObj := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsPatchBinding,
			Namespace: teamspace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: teamspace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     nsPatchRole,
		},
	}
	if err := r.Patch(ctx, nsPatchBindingObj, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create namespace patch role binding: %w", err)
	}

	// Wait for token secret to be ready
	var tokenSecret *corev1.Secret
	tokenSecret = &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: teamspace}, tokenSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get token secret: %w", err)
	}

	if tokenSecret == nil || len(tokenSecret.Data["token"]) == 0 || len(tokenSecret.Data["ca.crt"]) == 0 {
		return ctrl.Result{RequeueAfter: time.Second * 5}, fmt.Errorf("token secret not ready")
	}

	// Get the server URL from the current context
	config, err := ctrl.GetConfig()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	// Create kubeconfig secret
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    token: %s
contexts:
- name: %s
  context:
    cluster: %s
    user: %s
    namespace: %s
current-context: %s
`, clusterName, config.Host, base64.StdEncoding.EncodeToString(tokenSecret.Data["ca.crt"]),
		userName, string(tokenSecret.Data["token"]),
		contextName, clusterName, userName, teamspace,
		contextName)

	kubeconfigSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubeconfigSecretName,
			Namespace: teamspace,
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(kubeconfig),
		},
	}
	if err := r.Patch(ctx, kubeconfigSecret, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create kubeconfig secret: %w", err)
	}

	iamConfig, err := r.getIAMConfig()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get IAM config: %w", err)
	}

	infraConfig, err := r.getInfraConfig()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get infra config: %w", err)
	}

	if err := r.createHypershiftCluster(ctx, iamConfig, infraConfig, teamspace); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create Hosted Cluster: %w", err)
	}

	logger.Info("Successfully reconciled team namespace", "namespace", teamspace)
	return ctrl.Result{}, nil
}

type IAMConfig struct {
	Region             string      `json:"region"`
	ProfileName        string      `json:"profileName"`
	InfraID            string      `json:"infraID"`
	IssuerURL          string      `json:"issuerURL"`
	Roles              AWSRolesRef `json:"roles"`
	KMSKeyARN          string      `json:"kmsKeyARN"`
	KMSProviderRoleARN string      `json:"kmsProviderRoleARN"`

	SharedIngressRoleARN      string `json:"sharedIngressRoleARN,omitempty"`
	SharedControlPlaneRoleARN string `json:"sharedControlPlaneRoleARN,omitempty"`

	KarpenterRoleARN string `json:"karpenterRoleARN,omitempty"`
}
type AWSRolesRef struct {
	IngressARN              string `json:"ingressARN"`
	ImageRegistryARN        string `json:"imageRegistryARN"`
	StorageARN              string `json:"storageARN"`
	NetworkARN              string `json:"networkARN"`
	KubeCloudControllerARN  string `json:"kubeCloudControllerARN"`
	NodePoolManagementARN   string `json:"nodePoolManagementARN"`
	ControlPlaneOperatorARN string `json:"controlPlaneOperatorARN"`
}

func (r *teamNamespaceReconciler) getIAMConfig() (*IAMConfig, error) {
	rawIAM, err := os.ReadFile(filepath.Join(r.IAMJSONPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read infra: %w", err)
	}

	iamConfig := &IAMConfig{}
	if err = json.Unmarshal(rawIAM, iamConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshall infra: %w", err)
	}
	return iamConfig, nil
}

type InfraConfig struct {
	Region             string                   `json:"region"`
	Zone               string                   `json:"zone"`
	InfraID            string                   `json:"infraID"`
	MachineCIDR        string                   `json:"machineCIDR"`
	VPCID              string                   `json:"vpcID"`
	Zones              []*CreateInfraOutputZone `json:"zones"`
	Name               string                   `json:"Name"`
	BaseDomain         string                   `json:"baseDomain"`
	BaseDomainPrefix   string                   `json:"baseDomainPrefix"`
	PublicZoneID       string                   `json:"publicZoneID"`
	PrivateZoneID      string                   `json:"privateZoneID"`
	LocalZoneID        string                   `json:"localZoneID"`
	ProxyAddr          string                   `json:"proxyAddr"`
	SecureProxyAddr    string                   `json:"secureProxyAddr"`
	ProxyPrivateSSHKey string                   `json:"proxyPrivateSSHKey"`
	PublicOnly         bool                     `json:"publicOnly"`
	ProxyCA            string                   `json:"proxyCA"`

	// Fields related to shared VPCs
	VPCCreatorAccountID string `json:"vpcCreatorAccountID"`
	ClusterAccountID    string `json:"clusterAccountID"`
}

type CreateInfraOutputZone struct {
	Name     string `json:"name"`
	SubnetID string `json:"subnetID"`
}

func (r *teamNamespaceReconciler) getInfraConfig() (*InfraConfig, error) {
	rawIAM, err := os.ReadFile(filepath.Join(r.InfraJSONPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read infra: %w", err)
	}

	infraCondig := &InfraConfig{}
	if err = json.Unmarshal(rawIAM, infraCondig); err != nil {
		return nil, fmt.Errorf("failed to unmarshall infra: %w", err)
	}
	return infraCondig, nil
}

func (r *teamNamespaceReconciler) createHypershiftCluster(ctx context.Context, iamConfig *IAMConfig, infraConfig *InfraConfig, namespace string) error {
	if err := r.reconcileTeamspacesSecrets(ctx, namespace); err != nil {
		return fmt.Errorf("failed to reconcile teamspaces secrets: %w", err)
	}

	hc := &hypershiftv1.HostedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dev",
			Namespace: namespace,
		},
		Spec: hypershiftv1.HostedClusterSpec{
			Autoscaling:                  hypershiftv1.ClusterAutoscaling{},
			Configuration:                &hypershiftv1.ClusterConfiguration{},
			ControllerAvailabilityPolicy: hypershiftv1.SingleReplica,
			DNS: hypershiftv1.DNSSpec{
				BaseDomain:    infraConfig.Name + "." + infraConfig.BaseDomain,
				PrivateZoneID: infraConfig.PrivateZoneID,
				PublicZoneID:  infraConfig.PublicZoneID,
			},
			Etcd: hypershiftv1.EtcdSpec{
				ManagementType: hypershiftv1.Managed,
				Managed: &hypershiftv1.ManagedEtcdSpec{
					Storage: hypershiftv1.ManagedEtcdStorageSpec{
						Type: hypershiftv1.PersistentVolumeEtcdStorage,
						PersistentVolume: &hypershiftv1.PersistentVolumeEtcdStorageSpec{
							Size:             ptr.To(resource.MustParse("8Gi")),
							StorageClassName: ptr.To("gp3-csi"),
						},
					},
				},
			},
			FIPS:      false,
			InfraID:   infraConfig.InfraID,
			IssuerURL: fmt.Sprintf("https://hypershift-ci-2-oidc.s3.us-east-1.amazonaws.com/%s", infraConfig.InfraID),
			Networking: hypershiftv1.ClusterNetworking{
				ClusterNetwork: []hypershiftv1.ClusterNetworkEntry{
					{CIDR: ipnet.IPNet{
						IP:   net.ParseIP("10.132.0.0"),
						Mask: net.CIDRMask(14, 32),
					}},
				},
				MachineNetwork: []hypershiftv1.MachineNetworkEntry{
					{CIDR: ipnet.IPNet{
						IP:   net.ParseIP(infraConfig.MachineCIDR),
						Mask: net.CIDRMask(32, 32),
					}},
				},
				NetworkType: hypershiftv1.OVNKubernetes,
				ServiceNetwork: []hypershiftv1.ServiceNetworkEntry{
					{CIDR: ipnet.IPNet{
						IP:   net.ParseIP("172.31.0.0"),
						Mask: net.CIDRMask(16, 32),
					}},
				},
			},
			OLMCatalogPlacement: hypershiftv1.ManagementOLMCatalogPlacement,
			Platform: hypershiftv1.PlatformSpec{
				Type: hypershiftv1.AWSPlatform,
				AWS: &hypershiftv1.AWSPlatformSpec{
					Region: infraConfig.Region,
					CloudProviderConfig: &hypershiftv1.AWSCloudProviderConfig{
						Subnet: &hypershiftv1.AWSResourceReference{
							ID: ptr.To(infraConfig.Zones[0].SubnetID),
						},
						VPC:  infraConfig.VPCID,
						Zone: infraConfig.Zones[0].Name,
					},
					EndpointAccess: hypershiftv1.Public,
					MultiArch:      false,
					RolesRef: hypershiftv1.AWSRolesRef{
						ControlPlaneOperatorARN: iamConfig.Roles.ControlPlaneOperatorARN,
						ImageRegistryARN:        iamConfig.Roles.ImageRegistryARN,
						IngressARN:              iamConfig.Roles.IngressARN,
						KubeCloudControllerARN:  iamConfig.Roles.KubeCloudControllerARN,
						NetworkARN:              iamConfig.Roles.NetworkARN,
						NodePoolManagementARN:   iamConfig.Roles.NodePoolManagementARN,
						StorageARN:              iamConfig.Roles.StorageARN,
					},
				},
			},
			Release: hypershiftv1.Release{
				Image: "quay.io/openshift-release-dev/ocp-release:4.19.0-ec.5-multi",
			},
			PullSecret: corev1.LocalObjectReference{
				Name: "dev-pull-secret",
			},
			ServiceAccountSigningKey: &corev1.LocalObjectReference{
				Name: "sa-signing-key",
			},
			SecretEncryption: &hypershiftv1.SecretEncryptionSpec{
				Type: hypershiftv1.AESCBC,
				AESCBC: &hypershiftv1.AESCBCSpec{
					ActiveKey: corev1.LocalObjectReference{
						Name: "dev-etcd-encryption-key",
					},
				},
			},
			SSHKey: corev1.LocalObjectReference{
				Name: "dev-ssh-key",
			},
			Services: []hypershiftv1.ServicePublishingStrategyMapping{
				{
					Service: hypershiftv1.APIServer,
					ServicePublishingStrategy: hypershiftv1.ServicePublishingStrategy{
						Type: hypershiftv1.LoadBalancer,
					},
				},
				{
					Service: hypershiftv1.Ignition,
					ServicePublishingStrategy: hypershiftv1.ServicePublishingStrategy{
						Type: hypershiftv1.Route,
					},
				},
				{
					Service: hypershiftv1.Konnectivity,
					ServicePublishingStrategy: hypershiftv1.ServicePublishingStrategy{
						Type: hypershiftv1.Route,
					},
				},
				{
					Service: hypershiftv1.OAuthServer,
					ServicePublishingStrategy: hypershiftv1.ServicePublishingStrategy{
						Type: hypershiftv1.Route,
					},
				},
			},
		},
	}

	if err := r.Patch(ctx, hc, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
		return fmt.Errorf("failed to apply HostedCluster: %w", err)
	}

	return nil

}

// reconcileTeamspacesSecrets fetches secrets from the teamspaces namespace and reconciles them into the team namespace
func (r *teamNamespaceReconciler) reconcileTeamspacesSecrets(ctx context.Context, teamNamespace string) error {
	logger := log.FromContext(ctx)
	secretsToCopy := []string{
		"dev-pull-secret",
		"dev-ssh-key",
		"dev-etcd-encryption-key",
		"sa-signing-key",
	}

	for _, secretName := range secretsToCopy {
		// Get the secret from teamspaces namespace
		sourceSecret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: "teamspaces"}, sourceSecret); err != nil {
			return fmt.Errorf("failed to get secret %s from teamspaces namespace: %w", secretName, err)
		}

		// Create a copy of the secret for the team namespace
		targetSecret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: teamNamespace,
			},
			Data: sourceSecret.Data,
			Type: sourceSecret.Type,
		}

		// Apply the secret to the team namespace
		if err := r.Patch(ctx, targetSecret, client.Apply, client.ForceOwnership, client.FieldOwner("teamspace-controller")); err != nil {
			return fmt.Errorf("failed to apply secret %s to team namespace: %w", secretName, err)
		}

		logger.Info("Successfully reconciled secret", "secret", secretName, "namespace", teamNamespace)
	}

	return nil
}
