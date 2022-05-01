# Install Ingress-nginx

Inspect the prerequisites and the main steps to perform for installing [ingress-nginx](https://docs.nginx.com/nginx-ingress-controller/intro/overview/) on Kubernetes.

## Prerequisites

* Kubectl version 1.20.0 is installed. Please refer to the [Kubernetes official website](https://v1-18.docs.kubernetes.io/docs/setup/release/notes/) for details.
* [Helm](https://helm.sh) version 3.6.0 is installed. Please refer to the [Helm page](https://github.com/helm/helm/releases/tag/v3.6.0) on GitHub for details.

## Installation

To install ingress-nginx, follow the steps below:

1. Create ingress-nginx namespace:

      kubectl create namespace ingress-nginx

2. Add a chart repository:

      helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
      helm repo update

3. Install Ingress-nginx:

      helm install ingress ingress-nginx/ingress-nginx \
      --version 3.23.0 \
      --values values.yaml \
      --namespace ingress-nginx

   Check out the *values.yaml* file sample of the Ingress-nginx customization:

<details>
<summary><b>View: values.yaml</b></summary>

```yaml
controller:
  addHeaders:
    X-Content-Type-Options: nosniff
    X-Frame-Options: SAMEORIGIN
  resources:
    limits:
      memory: "256Mi"
    requests:
      cpu: "50m"
      memory: "128M"
  config:
    ssl-redirect: 'true'
    client-header-buffer-size: '64k'
    http2-max-field-size: '64k'
    http2-max-header-size: '64k'
    large-client-header-buffers: '4 64k'
    upstream-keepalive-timeout: '120'
    keep-alive: '10'
    use-forwarded-headers: 'true'
    proxy-real-ip-cidr: '172.32.0.0/16'
    proxy-buffer-size: '8k'

  service:
    type: NodePort
    nodePorts:
      http: 32080
      https: 32443
  updateStrategy:
    rollingUpdate:
      maxUnavailable: 1
    type: RollingUpdate
  metrics:
    enabled: true
defaultBackend:
  enabled: true
serviceAccount:
  create: true
  name: nginx-ingress-service-account
```

</details>

!!! note
    Align value **controller.config.proxy-real-ip-cidr** with [AWS VPC CIDR](https://kubernetes.github.io/ingress-nginx/user-guide/miscellaneous/#source-ip-address).