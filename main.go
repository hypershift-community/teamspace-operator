package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	hypershiftv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
	"github.com/spf13/cobra"
	"github.com/teamspace-operator/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

type Options struct {
	InfraJSONPath string
	IAMJSONPath   string
	APIServerHost string
}

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = hypershiftv1.AddToScheme(scheme)
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	cmd := &cobra.Command{
		Use:   "teamspace-operator",
		Short: "Operator for managing team spaces",
		Long: `Teamspace Operator is a Kubernetes operator that manages team spaces,
including RBAC, service accounts, kubeconfig generation, HostedCluster CRs and more.`,
	}

	opts := Options{
		InfraJSONPath: "./files/infra.json",
		IAMJSONPath:   "./files/iam.json",
		APIServerHost: "",
	}

	cmd.Flags().StringVar(&opts.InfraJSONPath, "infra-json", "", "Path to the infrastructure JSON file")
	cmd.Flags().StringVar(&opts.IAMJSONPath, "iam-json", "", "Path to the IAM JSON file")
	cmd.Flags().StringVar(&opts.APIServerHost, "api-server-host", "", "API Server URL (e.g. https://api.example.com:6443)")

	cmd.MarkFlagRequired("infra-json")
	cmd.MarkFlagRequired("iam-json")
	cmd.MarkFlagRequired("api-server-host")

	cmd.Run = func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		go func() {
			<-sigs
			cancel()
		}()

		if err := run(ctx, opts); err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts Options) error {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:         scheme,
		Metrics:        server.Options{BindAddress: "0"},
		LeaderElection: false,
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	reconciler := &controllers.TeamspaceReconciler{
		Client:        mgr.GetClient(),
		InfraJSONPath: opts.InfraJSONPath,
		IAMJSONPath:   opts.IAMJSONPath,
		APIServerHost: opts.APIServerHost,
	}

	if err = reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}
