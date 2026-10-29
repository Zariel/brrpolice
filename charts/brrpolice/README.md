# brrpolice

Temporary peer enforcement for qBittorrent seeding nodes

Install the OCI chart:

```sh
helm install brrpolice oci://ghcr.io/zariel/charts/brrpolice \
  --namespace default \
  --set config.qbittorrent.base_url=http://qbittorrent.default.svc.cluster.local
```

The chart runs one instance with `Recreate` upgrades so enforcement and SQLite
writes never overlap. `replicaCount` accepts only `0` or `1`.

SQLite data uses a PVC by default. Set `persistence.existingClaim` to reuse an
existing database, and match `podSecurityContext` to the volume's ownership. A
disk-backed `emptyDir` is always mounted at `/tmp`: SQLite needs writable
temporary storage for large migrations and query sorts even when `/data` is
writable. The root filesystem stays read-only.

`config` is the application's native configuration, serialized as TOML. It
supports the policy, filters, retention, logging, and qBittorrent settings in the
[application README](../../README.md). Strings support Helm template expressions.
The ConfigMap checksum rolls out configuration changes.

Keep credentials in Kubernetes Secrets. For API-key authentication, for example:

```yaml
extraEnv:
  - name: BRRPOLICE_QBITTORRENT__API_KEY
    valueFrom:
      secretKeyRef:
        name: qbittorrent-auth
        key: api-key
```

For cookie authentication, set `config.qbittorrent.username` and
`config.qbittorrent.password_env` to the name of a Secret-backed environment
variable supplied through `extraEnv`. Do not put credentials in `config`.

Charts are published only as OCI artifacts. Release packages pin the container
image digest and use the application release version for both chart version
and `appVersion`. Pull requests validate charts without publishing them.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Scheduling affinity. |
| config.database.path | string | `"/data/brrpolice.sqlite"` | SQLite file within the mounted data directory. |
| config.http.host | string | `"0.0.0.0"` | HTTP bind address; must be reachable through the Service. |
| config.http.port | int | `9090` | Application HTTP port, also used by probes and metrics. |
| config.logging.format | string | `"json"` | Application log format. |
| config.logging.level | string | `"info"` | Application log level. |
| config.qbittorrent.base_url | required | `""` | qBittorrent Web API base URL. |
| envFrom | list | `[]` | Environment sources, such as existing Secrets containing BRRPOLICE_* keys. |
| extraEnv | list | `[]` | Additional environment variables, including Secret key references. |
| extraVolumeMounts | list | `[]` | Additional container volume mounts. |
| extraVolumes | list | `[]` | Additional volumes, for example a private CA bundle. |
| fullnameOverride | string | `""` | Override resource names. |
| image.digest | string | `""` | Image digest; overrides tag. OCI packages pin the released image digest. |
| image.pullPolicy | string | `"IfNotPresent"` | Container image pull policy. |
| image.repository | string | `"ghcr.io/zariel/brrpolice"` | Container image repository. |
| image.tag | string | `""` | Image tag; empty uses v followed by the chart appVersion. |
| imagePullSecrets | list | `[]` | Registry credentials for private mirrors. |
| livenessProbe | object | `{"httpGet":{"path":"/healthz","port":"http"},"periodSeconds":10,"timeoutSeconds":5}` | Liveness probe. |
| monitoring.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor; requires its CRD. |
| monitoring.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| monitoring.serviceMonitor.labels | object | `{}` | Additional ServiceMonitor labels. |
| monitoring.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| nameOverride | string | `""` | Override the application name. |
| nodeSelector | object | `{}` | Node selector. |
| persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes for a new PVC. |
| persistence.annotations | object | `{}` | Annotations for a new PVC. |
| persistence.enabled | bool | `true` | Keep SQLite state on a PVC. Disabling uses an emptyDir and loses state when the pod is replaced. |
| persistence.existingClaim | string | `""` | Reuse an existing PVC instead of creating one. |
| persistence.size | string | `"5Gi"` | Requested size of a new PVC. |
| persistence.storageClass | string | `nil` | StorageClass for a new PVC; null uses the cluster default, an empty string disables dynamic provisioning. |
| podAnnotations | object | `{}` | Additional pod annotations. |
| podSecurityContext | object | `{"fsGroup":65532,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. Match an existing volume's ownership when reusing data. |
| readinessProbe | object | `{"httpGet":{"path":"/readyz","port":"http"},"periodSeconds":10,"timeoutSeconds":5}` | Readiness probe; enforcement initialization must succeed. |
| replicaCount | int | `1` | One SQLite writer is supported. Set to 0 to pause enforcement. |
| resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}` | Pod resources. Temporary SQLite sort files use disk-backed emptyDir storage, not tmpfs. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container security context. Writable data and temporary storage are mounted separately. |
| service.port | int | `9090` | Service port; forwards to config.http.port. |
| service.type | string | `"ClusterIP"` | Kubernetes Service type. |
| serviceAccount.annotations | object | `{}` | ServiceAccount annotations. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount without API credentials mounted into the pod. |
| serviceAccount.name | string | `""` | Existing ServiceAccount name; defaults to the release name when creating one. |
| startupProbe | object | `{"failureThreshold":60,"httpGet":{"path":"/healthz","port":"http"},"periodSeconds":5}` | Startup probe allowing time for migrations before liveness checks begin. |
| terminationGracePeriodSeconds | int | `30` | Grace period for shutdown and committing SQLite writes. |
| tolerations | list | `[]` | Scheduling tolerations. |
