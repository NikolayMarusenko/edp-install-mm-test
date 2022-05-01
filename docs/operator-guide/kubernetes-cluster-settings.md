# Set Up Kubernetes

Make sure the cluster meets the following conditions:

1. Kubernetes cluster is installed with minimum 2 worker nodes with total capacity 32 Cores and 8Gb RAM;

2. Machine with [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) is installed with a cluster-admin access to the Kubernetes cluster;

3. Ingress controller is installed in a cluster, for example [ingress-nginx](./install-ingress-nginx.md);

4. Ingress controller is configured with the disabled HTTP/2 protocol and header size of 64k support;

  Example of Config Map for Nginx ingress controller:

      kind: ConfigMap
      apiVersion: v1
      metadata:
        name: nginx-configuration
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      data:
        client-header-buffer-size: 64k
        large-client-header-buffers: 4 64k
        use-http2: "false"

5. Load balancer (if any exists in front of ingress controller) is configured with session stickiness, disabled HTTP/2 protocol and header size of 32k support;

6. Cluster nodes and pods have access to the cluster via external URLs. For instance, add in AWS the VPC NAT gateway elastic IP to the cluster external load balancers security group);

7. Keycloak instance is installed. To get accurate information on how to install Keycloak, please refer to the [Install Keycloak](install-keycloak.md) instruction;

8. Helm 3.1 or higher is installed on the installation machine with the help of the [Installing Helm](https://v3.helm.sh/docs/intro/install/) instruction;

9. A storage class is used with the [Retain Reclaim Policy](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#retain). See the example below.

  Storage class template with the Retain Reclaim Policy:

        kind: StorageClass
        apiVersion: storage.k8s.io/v1
        metadata:
          name: gp2-retain
        provisioner: kubernetes.io/aws-ebs
        parameters:
          fsType: ext4
          type: gp2
        reclaimPolicy: Retain
        volumeBindingMode: WaitForFirstConsumer


## Related Articles

* [Install Ingress-nginx](install-ingress-nginx.md)
* [Install Keycloak](install-keycloak.md)