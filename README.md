# achilles-fleet-server

A collector and VDB snapshot host for [Achilles](https://github.com/crabnebula-dev/achilles) fleet agents, with a Helm chart.

Achilles can run as a background fleet agent: every few hours it inventories the apps on a device and POSTs the list to a collector, and it can fetch its vulnerability data from a trusted host instead of querying NVD, OSV and EUVD from every device. Achilles ships the agent only. Its docs describe what the server must accept ([`collector-schema.md`](https://github.com/crabnebula-dev/achilles/blob/main/docs/collector-schema.md), [`vdb-snapshot-schema.md`](https://github.com/crabnebula-dev/achilles/blob/main/docs/vdb-snapshot-schema.md)) and leave the server to you. This is that server.

## What it does

| Endpoint | Token | |
|---|---|---|
| `POST /v1/reports` | report token | Stores the latest inventory of each device. A report generated earlier than the stored one (a late retry) is acknowledged and dropped. |
| `GET /v1/vdb` | VDB token, or the report token if none is set | Serves the snapshot file. |
| `GET /v1/devices[?fleet_id=…]` | read token | Every device with its apps and runtime versions. Off unless a read token is set. The chart sets one, but its ingress exposes only the two agent endpoints. |
| `GET /healthz`, `GET /readyz` | none | Liveness; readiness checks the database. |

Errors are a one-line plain-text reason, because the agent shows the first 200 characters of a failed response to the user.

### Snapshots the agent would ignore are never served

As of Achilles `7469522`, the agent's downloader caches any snapshot whose `products` map is not empty. Its matcher is stricter: every advisory needs `id`, `source`, `summary`, `aliases` and `references`, and `source` and `severity` must be known values. A snapshot with one advisory that misses `aliases`, or has `"severity": "moderate"`, is cached and reported as fine, and then the matcher drops all of it and silently goes back to the public feeds.

So the server checks a snapshot against the matcher's rules before serving it. A file that fails is not served; if an update breaks a file that was good, the last good copy keeps being served and the error is logged. A snapshot older than `FLEET_VDB_MAX_AGE` (default 14 days, the agent's own default) is withheld with a 503: the agent only checks a snapshot's age when a download fails, so an old file served with a 200 would stay in use on every device.

## Run it

A tag `vX.Y.Z` publishes the image `ghcr.io/egezamb/achilles-fleet-server` (amd64 and arm64) and the chart `oci://ghcr.io/egezamb/charts/achilles-fleet-server`, both signed with keyless cosign. To build it yourself:

```sh
docker build -t achilles-fleet-server .
docker run -p 8080:8080 -e FLEET_REPORT_TOKEN=change-me -e FLEET_READ_TOKEN=change-me-too \
  -v fleet-data:/data achilles-fleet-server
```

In Achilles, open **Settings → Fleet reporting**, set the collector URL to `http://<host>:8080/v1/reports` and the token to `FLEET_REPORT_TOKEN`.

| Variable | Default | |
|---|---|---|
| `FLEET_REPORT_TOKEN` | (required) | |
| `FLEET_VDB_TOKEN` | the report token | |
| `FLEET_READ_TOKEN` | unset: read API off | |
| `FLEET_VDB_FILE` | unset: `/v1/vdb` off | Re-read when the file changes. |
| `FLEET_VDB_MAX_AGE` | `336h` | Go duration. `0` serves any age. |
| `FLEET_DB` | `fleet.db` (`/data/fleet.db` in the image) | SQLite file. |
| `FLEET_LISTEN` | `:8080` | |
| `FLEET_MAX_BODY` | `8388608` | Largest report, in bytes. |

## Helm

```sh
helm install fleet oci://ghcr.io/egezamb/charts/achilles-fleet-server -n fleet --create-namespace
kubectl -n fleet get secret fleet-achilles-fleet-server -o jsonpath='{.data.report-token}' | base64 -d
```

- **Tokens** are generated on install unless you set them or point `tokens.existingSecret` at your own Secret. They stay the same across upgrades and across uninstall and reinstall, because a changed token would cut off every enrolled device until someone retypes it on each one. Changing a token inside an existingSecret does not restart the pod; restart it yourself.
- **GitOps (Argo CD):** Argo CD renders charts with `helm template`, where the chart cannot look up the tokens already in the cluster, so a generated token would change on every sync. Create the Secret yourself and set `tokens.existingSecret`, or set `tokens.reportToken` and `tokens.readToken`. `helm install` and `helm upgrade`, and Flux, which uses them, are not affected.
- **Storage** is SQLite on a PersistentVolumeClaim, which is kept on uninstall (`persistence.keep`). The Deployment runs one replica with the Recreate strategy, because SQLite has a single writer and the volume is ReadWriteOnce; WAL mode needs a local filesystem, so no NFS. There is no backup: if the volume is lost, the inventory fills up again as devices report, within one reporting interval.
- **VDB snapshot**: put it in a ConfigMap and set `vdb.enabled=true` and `vdb.configMap.name`. Updates to the ConfigMap are picked up without a restart. A ConfigMap holds at most 1 MiB.
- **Ingress** routes only `/v1/reports` and `/v1/vdb`. `/v1/devices` lists every device and its app versions; reach it with `kubectl port-forward`.
- `networkPolicy.enabled` allows ingress to the HTTP port only and no egress, since the server opens no connections. The `helm test` pod is not covered by it.
- **Restarts** take the server away for a few seconds, because it runs one pod and the old one stops before the new one starts. An agent whose report fails then sends it again at its next scheduled run, six hours later by default.
- `helm test` posts an empty report with the release's token and expects the 400 that comes only after the token is accepted, so it writes nothing to the inventory.

## Tested

- `go test ./...`: the request examples from both Achilles docs, token checks, late, future-dated and replaced reports, clipped fields, concurrent writes, the body limit, and every snapshot rule the agent's matcher applies. The edge cases of those rules (nulls, repeated fields, key case, floats) were checked against serde_json in Achilles' `cve` crate. Seventeen mutants of the server, each removing one rule, are all caught.
- CI runs the tests with `-race`, `helm lint --strict`, kubeconform for Kubernetes 1.29 and 1.34, and on kind installs the chart with an image built from the commit: `helm test`, an upgrade, and an uninstall and reinstall that must keep the report token.
- On kind (Kubernetes 1.37, Helm 4.3): install, `helm test`, upgrade, uninstall and reinstall keep the token and the inventory; a broken ConfigMap update keeps the last good snapshot in service; a stale snapshot gets a 503. Removing the token `lookup` or the `keep` policy from the chart makes the token change on upgrade or reinstall.
- With [Helmbulance](https://github.com/Git-Hospital/helmbulance): `reinstall` passes. `gitops-render` fails with generated tokens, which is why the GitOps note above exists, and passes with the tokens set in values; `upgrade-without-values` passes the same way. `zero-downtime` fails: 1 or 2 of about 50 requests during a restart (two runs), the single-pod gap described above.

## Not yet

- Building snapshots. The server serves a file; producing it from NVD, OSV and EUVD is the next step.
- A web page for the inventory. The read API returns JSON.
- Postgres, for more than one replica.

## License

Apache-2.0
