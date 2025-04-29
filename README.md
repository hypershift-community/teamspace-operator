# Teamspace Operator

Teamspace Operator is a Kubernetes operator that manages Teamspaces, including namespaces,  RBAC, service accounts, kubeconfig generation, HostedCluster CRs and more.

## Prerequisites

- Go 1.20 or higher
- Kubernetes cluster (for deployment)
- kubectl configured to access your cluster
- Docker (for building container images)

## Setup

### Build

Build the binary locally:

```bash
# Build the binary
make build

# The binary will be created at bin/teamspace-operator
```

### Configuration

The operator requires JSON configuration files for infrastructure and IAM settings:

- `iam.json`: Contains AWS IAM configuration for HyperShift clusters
- `infra.json`: Contains infrastructure configuration like VPC, subnets, etc.

Sample configuration files can be found in the `deploy/deployment.yaml` ConfigMap.

### Running Locally

```bash
# Create the infrastructure and IAM JSON files
mkdir -p files
# Copy your infrastructure and IAM configuration to these files
cp your-infra-config.json files/infra.json
cp your-iam-config.json files/iam.json

# Run the operator locally
./bin/teamspace-operator \
  --infra-json ./files/infra.json \
  --iam-json ./files/iam.json \
  --api-server-host https://your-kubernetes-api-server:6443
```
