#!/bin/bash
set -Eeuo pipefail

export KUBECONFIG=/etc/kubernetes/admin.conf
config=/data/cubesandbox-s55c-control/run-config.env
test -r "$config"
# The file is written only by the S5.5 controller-side setup command and
# contains fixed shell assignments for the next isolated run.
source "$config"
export RUN_ID="${RUN_ID:?RUN_ID is required}"
export MODE="${MODE:?MODE is required}"
export SERIAL_COUNT="${SERIAL_COUNT:-0}"
export ROUNDS="${ROUNDS:-0}"
export WIDTH="${WIDTH:-0}"
export BACKEND="${BACKEND:?BACKEND is required}"
export TRACE_MODE="${TRACE_MODE:?TRACE_MODE is required}"
export NODE_NAME="${NODE_NAME:-vm-200-13-ubuntu}"
export CUBE_COMMIT="${CUBE_COMMIT:-69b3f9b1503566171bb4a03cef56f0447a80b346}"
export CUBE_IMAGE="${CUBE_IMAGE:-mirror.ccs.tencentyun.com/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
export OUTPUT_ROOT="${OUTPUT_ROOT:-/data/cubesandbox-s55c-control}"
export OUTPUT_DIR="$OUTPUT_ROOT/$RUN_ID"
install -d -m 0755 "$OUTPUT_DIR"
cp "$0" "$OUTPUT_DIR/runner.sh"
cp "$config" "$OUTPUT_DIR/run-config.env"
sha256sum "$OUTPUT_DIR/runner.sh" "$OUTPUT_DIR/run-config.env" > "$OUTPUT_DIR/runner-assets.sha256"

python3 - <<'PY'
import codecs
import csv
import datetime
import json
import math
import os
import pathlib
import re
import statistics
import subprocess
import threading
import time

run_id = os.environ["RUN_ID"]
mode = os.environ["MODE"]
serial_count = int(os.environ["SERIAL_COUNT"])
rounds = int(os.environ["ROUNDS"])
width = int(os.environ["WIDTH"])
backend = os.environ["BACKEND"]
trace_mode = os.environ["TRACE_MODE"]
node = os.environ["NODE_NAME"]
commit = os.environ["CUBE_COMMIT"]
image = os.environ["CUBE_IMAGE"]
out = pathlib.Path(os.environ["OUTPUT_DIR"])
namespace = "cube-s55c-" + re.sub(r"[^a-z0-9-]", "-", run_id.lower())[:38]
label = "cubesandbox-s55c-run"
manifest_file = out / "workload-manifests.jsonl"

# A run ID may be retried after an interrupted invocation. All runner-owned
# outputs are authoritative for this invocation only; never append into an old
# run and silently double the sample inventory.
for output_name in (
    "workload-manifests.jsonl", "pods.csv", "summary.json", "metrics.prom",
    "formal-run-config.json",
):
    (out / output_name).write_text("")

(out / "formal-run-config.json").write_text(json.dumps({
    "run_id": run_id,
    "mode": mode,
    "serial_count": serial_count,
    "rounds": rounds,
    "width": width,
    "backend": backend,
    "trace_mode": trace_mode,
    "node": node,
    "commit": commit,
    "image": image,
    "runtime_class_name": "cube",
    "image_pull_policy": "Never",
    "percentile_method": "nearest-rank",
    "percentile_gate": "raw pods.csv is authoritative",
}, indent=2, sort_keys=True) + "\n")

def kubectl(*args, input_obj=None, check=True):
    data = None if input_obj is None else json.dumps(input_obj).encode()
    return subprocess.run(
        ["kubectl", *args], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=check,
    )

def percentile(values, q):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]

def rfc3339_ns(value):
    if not value:
        return None
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1_000_000_000)

def metrics():
    raw = kubectl("get", "--raw", f"/api/v1/nodes/{node}/proxy/metrics").stdout.decode()
    values = {}
    pattern = re.compile(r'^kubelet_runtime_operations_duration_seconds_(sum|count)\{([^}]*)\} ([0-9.eE+-]+)$')
    pod_pattern = re.compile(r'^kubelet_pod_start_duration_seconds_(sum|count) ([0-9.eE+-]+)$')
    for line in raw.splitlines():
        match = pattern.match(line)
        if match:
            op = re.search(r'operation_type="([^"]+)"', match.group(2))
            if op:
                values[f"runtime:{op.group(1)}:{match.group(1)}"] = float(match.group(3))
        match = pod_pattern.match(line)
        if match:
            values[f"pod_start:{match.group(1)}"] = float(match.group(2))
    (out / "metrics.prom").write_text(raw)
    return values

def pod_manifest(name):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {label: run_id, "cubesandbox-poc-owned": "true"},
            "annotations": {
                "cubesandbox.tencentcloud.com/s55c-run": run_id,
                "cubesandbox.tencentcloud.com/s55c-backend": backend,
                "cubesandbox.tencentcloud.com/s55c-trace": trace_mode,
            },
        },
        "spec": {
            "runtimeClassName": "cube",
            "nodeSelector": {"kubernetes.io/hostname": node},
            # The performance worker stays cordoned to isolate it from unrelated
            # cluster workloads. Keep scheduling explicit and tolerate only the
            # taint produced by `kubectl cordon`.
            "tolerations": [{
                "key": "node.kubernetes.io/unschedulable",
                "operator": "Exists",
                "effect": "NoSchedule",
            }],
            "terminationGracePeriodSeconds": 1,
            "containers": [{
                "name": "idle",
                "image": image,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c", "echo cube-s55c-ready; sleep 600"],
            }],
        },
    }

node_label = kubectl("get", "node", node, "-o", "jsonpath={.metadata.labels.kubernetes\\.io/hostname}").stdout.decode()
if node_label != node:
    raise SystemExit(f"node hostname label mismatch: node={node!r} label={node_label!r}")

namespace_obj = {
    "apiVersion": "v1", "kind": "Namespace",
    "metadata": {"name": namespace, "labels": {"cubesandbox-poc-owned": "true", label: run_id}},
}
kubectl("create", "-f", "-", input_obj=namespace_obj)

state = {}
condition = threading.Condition()
watch_errors = []
watcher = subprocess.Popen(
    ["kubectl", "get", "pods", "-n", namespace, "-l", f"{label}={run_id}",
     "--watch-only", "-o", "json"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)

def watch_loop():
    decoder = json.JSONDecoder()
    utf8 = codecs.getincrementaldecoder("utf-8")()
    buffer = ""
    try:
        while watcher.poll() is None:
            chunk = os.read(watcher.stdout.fileno(), 65536)
            if not chunk:
                break
            buffer += utf8.decode(chunk)
            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break
                try:
                    obj, offset = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    break
                buffer = buffer[offset:]
                metadata = obj.get("metadata", {})
                name = metadata.get("name")
                if not name:
                    continue
                conditions = {x.get("type"): x for x in obj.get("status", {}).get("conditions", [])}
                now_mono = time.monotonic_ns()
                now_wall = time.time_ns()
                with condition:
                    entry = state.setdefault(name, {"name": name})
                    entry.setdefault("uid", metadata.get("uid", ""))
                    entry["node"] = obj.get("spec", {}).get("nodeName", "")
                    entry["phase"] = obj.get("status", {}).get("phase", "")
                    scheduled_condition = conditions.get("PodScheduled", {})
                    ready_condition = conditions.get("Ready", {})
                    if scheduled_condition.get("status") == "True":
                        entry.setdefault("scheduled_ns", now_mono)
                        entry.setdefault("scheduled_observed_wall_ns", now_wall)
                        entry.setdefault("scheduled_transition_time", scheduled_condition.get("lastTransitionTime", ""))
                        entry.setdefault("scheduled_transition_wall_ns", rfc3339_ns(scheduled_condition.get("lastTransitionTime")))
                    if ready_condition.get("status") == "True":
                        entry.setdefault("ready_ns", now_mono)
                        entry.setdefault("ready_observed_wall_ns", now_wall)
                        entry.setdefault("ready_transition_time", ready_condition.get("lastTransitionTime", ""))
                        entry.setdefault("ready_transition_wall_ns", rfc3339_ns(ready_condition.get("lastTransitionTime")))
                    condition.notify_all()
    except Exception as error:
        with condition:
            watch_errors.append(repr(error))
            condition.notify_all()

thread = threading.Thread(target=watch_loop, daemon=True)
thread.start()
time.sleep(0.25)
before_metrics = metrics()
created = {}
results = []

def wait_ready(names, timeout=120):
    deadline = time.monotonic() + timeout
    with condition:
        while True:
            if watch_errors:
                raise RuntimeError("watch failed: " + ";".join(watch_errors))
            if all(state.get(name, {}).get("ready_ns") for name in names):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting ready: {names}; state={state}")
            condition.wait(min(remaining, 1.0))
    for name in names:
        entry = dict(state[name])
        entry["create_begin_ns"] = created[name][0]
        entry["create_ack_ns"] = created[name][1]
        scheduled = entry.get("scheduled_ns")
        ready = entry.get("ready_ns")
        if not scheduled or not ready or ready < scheduled:
            raise RuntimeError(f"invalid watch timing for {name}: {entry}")
        if entry.get("node") != node:
            raise RuntimeError(f"pod {name} landed on {entry.get('node')}, expected {node}")
        entry["scheduled_to_ready_ms"] = (ready - scheduled) / 1_000_000
        entry["create_ack_to_ready_ms"] = (ready - entry["create_ack_ns"]) / 1_000_000
        if entry.get("scheduled_transition_wall_ns"):
            entry["scheduled_publish_to_observed_ms"] = (
                entry["scheduled_observed_wall_ns"] - entry["scheduled_transition_wall_ns"]
            ) / 1_000_000
        if entry.get("ready_transition_wall_ns"):
            entry["ready_publish_to_observed_ms"] = (
                entry["ready_observed_wall_ns"] - entry["ready_transition_wall_ns"]
            ) / 1_000_000
        results.append(entry)

def create_group(names):
    manifest = {"apiVersion": "v1", "kind": "List", "items": [pod_manifest(name) for name in names]}
    with manifest_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"names": names, "manifest": manifest}, sort_keys=True, separators=(",", ":")) + "\n")
    begin = time.monotonic_ns()
    kubectl("create", "-f", "-", input_obj=manifest)
    ack = time.monotonic_ns()
    for name in names:
        created[name] = (begin, ack)
    wait_ready(names)

def delete_group(names):
    kubectl("delete", "pod", *names, "-n", namespace, "--wait=true", "--timeout=120s")
    time.sleep(1.0)

error = None
try:
    if mode == "serial":
        if serial_count <= 0:
            raise ValueError("SERIAL_COUNT must be positive")
        for index in range(serial_count):
            names = [f"serial-{index:03d}"]
            create_group(names)
            delete_group(names)
    elif mode == "concurrent":
        if rounds <= 0 or width <= 0:
            raise ValueError("ROUNDS and WIDTH must be positive")
        for round_index in range(rounds):
            names = [f"round-{round_index:02d}-pod-{index:02d}" for index in range(width)]
            create_group(names)
            delete_group(names)
            time.sleep(1.0)
    else:
        raise ValueError(f"unsupported MODE={mode}")
except Exception as caught:
    error = repr(caught)
finally:
    after_metrics = metrics()
    watcher.terminate()
    try:
        watcher.wait(timeout=5)
    except subprocess.TimeoutExpired:
        watcher.kill()
    kubectl("delete", "namespace", namespace, "--wait=true", "--timeout=180s", check=False)

columns = [
    "name", "uid", "node", "phase", "create_begin_ns", "create_ack_ns",
    "scheduled_ns", "ready_ns", "scheduled_observed_wall_ns", "ready_observed_wall_ns",
    "scheduled_transition_time", "ready_transition_time", "scheduled_transition_wall_ns",
    "ready_transition_wall_ns", "scheduled_publish_to_observed_ms", "ready_publish_to_observed_ms",
    "scheduled_to_ready_ms", "create_ack_to_ready_ms",
]
with (out / "pods.csv").open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(results)

metric_delta = {}
for key in sorted(set(before_metrics) | set(after_metrics)):
    delta = after_metrics.get(key, 0.0) - before_metrics.get(key, 0.0)
    if delta:
        metric_delta[key] = delta

latencies = [item["scheduled_to_ready_ms"] for item in results]
expected = serial_count if mode == "serial" else rounds * width
manifest_records = [json.loads(line) for line in manifest_file.read_text().splitlines() if line.strip()]
manifest_names = [name for record in manifest_records for name in record.get("names", [])]
observed_names = [item.get("name", "") for item in results]
pod_uids = [item.get("uid", "") for item in results]
inventory = {
    "expected": expected,
    "manifest_record_count": len(manifest_records),
    "manifest_name_count": len(manifest_names),
    "unique_manifest_name_count": len(set(manifest_names)),
    "observed_name_count": len(observed_names),
    "unique_observed_name_count": len(set(observed_names)),
    "pod_uid_count": len(pod_uids),
    "unique_pod_uid_count": len(set(pod_uids)),
}
inventory["valid"] = (
    inventory["manifest_name_count"] == expected
    and inventory["unique_manifest_name_count"] == expected
    and inventory["observed_name_count"] == expected
    and inventory["unique_observed_name_count"] == expected
    and inventory["pod_uid_count"] == expected
    and inventory["unique_pod_uid_count"] == expected
    and all(pod_uids)
    and set(manifest_names) == set(observed_names)
)
summary = {
    "run_id": run_id,
    "mode": mode,
    "backend": backend,
    "trace_mode": trace_mode,
    "commit": commit,
    "node": node,
    "image": image,
    "expected": expected,
    "observed": len(results),
    "success": error is None and inventory["valid"],
    "error": error,
    "method": {"percentile": "nearest-rank"},
    "inventory": inventory,
    "scheduled_to_ready_ms": {
        "p50": percentile(latencies, 0.50),
        "p95": percentile(latencies, 0.95),
        "p99": percentile(latencies, 0.99),
        "max": max(latencies) if latencies else 0,
        "mean": statistics.fmean(latencies) if latencies else 0,
    },
    "metric_delta": metric_delta,
}
(out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print("S55C_STARTUP_SUMMARY " + json.dumps(summary, sort_keys=True, separators=(",", ":")))
for item in results:
    print("S55C_POD name=%s uid=%s scheduled_to_ready_ms=%.3f create_ack_to_ready_ms=%.3f" % (
        item["name"], item.get("uid", ""), item["scheduled_to_ready_ms"], item["create_ack_to_ready_ms"],
    ))
if not summary["success"]:
    raise SystemExit(1)
PY
