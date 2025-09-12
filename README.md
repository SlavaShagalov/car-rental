# car-rental

Бэкенд сервиса аренды машин

# Deploy

## Used charts

### Postgres

Chart - https://artifacthub.io/packages/helm/bitnami/postgresql

Config - https://github.com/bitnami/charts/blob/main/bitnami/postgresql/values.yaml

```shell
helm upgrade postgres oci://registry-1.docker.io/bitnamicharts/postgresql -f k8s/deployments/postgres/values.yaml --install --wait --atomic
```

### Kafka

Chart - https://artifacthub.io/packages/helm/bitnami/kafka

Config - https://github.com/bitnami/charts/blob/main/bitnami/kafka/values.yaml

### Keycloak

Документация - https://www.keycloak.org/getting-started/getting-started-kube

Chart - https://artifacthub.io/packages/helm/bitnami/keycloak

Config - https://github.com/bitnami/charts/blob/main/bitnami/keycloak/values.yaml

```shell
helm upgrade keycloak oci://registry-1.docker.io/bitnamicharts/keycloak -f k8s/deployments/keycloak/values.yaml --install --wait --atomic
```

```shell
kubectl port-forward svc/keycloak 8080:80
```

```shell
kubectl get secret keycloak -o jsonpath='{.data.admin-password}' | base64 --decode

# Log in: user=user, password=<from command>
```

1. Создать realm car-rental-realm
2. Создать клиент car-rental-client
3. 

### API Services

Chart - https://github.com/gruntwork-io/helm-kubernetes-services

Config - https://github.com/gruntwork-io/helm-kubernetes-services/blob/main/charts/k8s-service/values.yaml

Preparation

```shell
helm repo add gruntwork https://helmcharts.gruntwork.io
helm repo update
```

```shell
helm upgrade cars-api gruntwork/k8s-service -f k8s/deployments/api-services/cars.yaml --install --wait --atomic
```

```shell
helm upgrade rental-api gruntwork/k8s-service -f k8s/deployments/api-services/rental.yaml --install --wait --atomic
```

```shell
helm upgrade payment-api gruntwork/k8s-service -f k8s/deployments/api-services/payment.yaml --install --wait --atomic
```

```shell
helm upgrade gateway gruntwork/k8s-service -f k8s/deployments/api-services/gateway.yaml --install --wait --atomic
```

```shell
helm upgrade retryer gruntwork/k8s-service -f k8s/deployments/api-services/retryer.yaml --install --wait --atomic
```

Port Forward for gateway

```shell
kubectl -n default port-forward svc/gateway 8080:80
```

### Ingress Controller

```shell
# Install nginx ingress controller
minikube addons enable ingress
```

```shell
# Get url to do requests
minikube service ingress-nginx-controller --url -n ingress-nginx

# Or use
minikube tunnel
# And do requests to http://127.0.0.1
```

### Kubernetes Dashboard

Preparation

```shell
helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
helm repo update
```

Up

```shell
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard
```

Port Forward for dashboard

```shell
kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443
```

Get token

```shell
kubectl apply -f k8s/access-control/create-user.yaml
kubectl apply -f k8s/access-control/bind-user-to-role.yaml  
```

```shell
kubectl -n kubernetes-dashboard create token admin
```
