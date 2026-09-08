#!/usr/bin/env python3

import argparse
import csv
import json
import pathlib

import kubernetes_runtime_trace_analyze as trace


def require_one(events, identity, component, operation, phase):
    selected = [
        event
        for event in events
        if event.get("component") == component
        and event.get("operation") == operation
        and event.get("phase") == phase
    ]
    if len(selected) != 1:
        raise ValueError(
            f"event inventory for {identity} {component}/{operation}/{phase} "
            f"is {len(selected)}, expected 1"
        )
    return selected[0]


def select_successful_attempts(containerd_events, pod_uids, shim_events):
    started_sandboxes = {
        event.get("sandbox_id", "")
        for event in shim_events
        if event.get("component") == "shim"
        and event.get("operation") == "start"
        and event.get("phase") == "start-vm-begin"
    }
    selected = []
    inventory = []
    for uid in sorted(pod_uids):
        events = sorted(
            [event for event in containerd_events if event.get("pod_uid") == uid],
            key=lambda event: event["ts_mono_us"],
        )
        attempts = []
        current = None
        for event in events:
            if (
                event.get("operation") == "run-pod-sandbox"
                and event.get("phase") == "cri-receive"
            ):
                current = []
                attempts.append(current)
            if current is not None:
                current.append(event)
        rows = []
        successful = []
        for attempt in attempts:
            sandbox_ids = {
                event.get("sandbox_id", "")
                for event in attempt
                if event.get("sandbox_id", "")
            }
            if len(sandbox_ids) != 1:
                raise ValueError(
                    f"attempt sandbox inventory for {uid} is {sorted(sandbox_ids)}"
                )
            sandbox_id = next(iter(sandbox_ids))
            started = sandbox_id in started_sandboxes
            rows.append(
                {
                    "sandbox_id": sandbox_id,
                    "started_vm": started,
                    "receive_mono_us": attempt[0]["ts_mono_us"],
                    "return_mono_us": max(
                        (
                            event["ts_mono_us"]
                            for event in attempt
                            if event.get("phase") == "cri-return"
                        ),
                        default=None,
                    ),
                }
            )
            if started:
                successful.append(attempt)
        if len(successful) != 1:
            raise ValueError(
                f"successful RunPodSandbox attempt inventory for {uid} is "
                f"{len(successful)}, expected 1"
            )
        selected.extend(successful[0])
        inventory.append(
            {
                "pod_uid": uid,
                "attempt_count": len(attempts),
                "attempts": rows,
            }
        )
    return selected, inventory


def durable_samples(
    containerd_events, shim_events, base_samples, process_by_sandbox, pod_names
):
    containerd_by_uid = {}
    for event in containerd_events:
        uid = event.get("pod_uid", "")
        if uid in pod_names:
            containerd_by_uid.setdefault(uid, []).append(event)

    samples = []
    for base in base_samples:
        uid = base["pod_uid"]
        sandbox_id = base["sandbox_id"]
        identity = f"{uid}/{sandbox_id}"
        containerd = containerd_by_uid.get(uid, [])
        sandbox_events = [
            event for event in shim_events if event.get("sandbox_id") == sandbox_id
        ]
        create = require_one(sandbox_events, identity, "shim", "create", "ttrpc-total")
        start_vm = require_one(
            sandbox_events, identity, "shim", "start", "start-vm-begin"
        )
        receive = require_one(
            containerd, identity, "containerd", "run-pod-sandbox", "cri-receive"
        )
        create_duration = trace.require_duration(create, identity)
        create_begin = create["ts_mono_us"] - create_duration
        start_vm_ts = start_vm["ts_mono_us"]
        receive_ts = receive["ts_mono_us"]
        if not receive_ts <= create_begin <= start_vm_ts:
            raise ValueError(
                f"non-monotonic durable create timeline for {identity}: "
                f"receive={receive_ts} create={create_begin} start_vm={start_vm_ts}"
            )

        process = process_by_sandbox.get(sandbox_id)
        if process is None:
            raise ValueError(f"missing process inventory for {identity}")
        shim_pid = process["shim_pid"]
        persistence = [
            event
            for event in shim_events
            if event.get("component") == "shim"
            and event.get("operation") == "persist"
            and create_begin <= event.get("ts_mono_us", 0) <= start_vm_ts
            and event.get("emitter_pid") == str(shim_pid)
            and event.get("target", "").startswith("/data/cubelet/shim-lifecycle/")
        ]
        atomic = [event for event in persistence if event.get("phase") == "atomic-write-json"]
        failed_atomic = [event for event in atomic if event.get("success") != "true"]
        for event in atomic:
            trace.require_duration(event, identity)
        directory_fsync = [
            event for event in persistence if event.get("phase") == "directory-fsync"
        ]
        for event in directory_fsync:
            trace.require_duration(event, identity)

        def atomic_for(filename):
            return [event for event in atomic if event.get("target", "").endswith(filename)]

        host_owner = atomic_for("/host-cgroup-owner.json")
        runtime_owner = atomic_for("/runtime-resource-owner.json")
        record = atomic_for("/record.json")
        name = pod_names[uid]
        round_name = name.split("-pod-", 1)[0] if "-pod-" in name else None
        samples.append(
            {
                "name": name,
                "round": round_name,
                "pod_uid": uid,
                "sandbox_id": sandbox_id,
                "shim_pid": shim_pid,
                "worker_pid": process["worker_pid"],
                "cri_receive_mono_us": receive_ts,
                "shim_create_begin_mono_us": create_begin,
                "start_vm_begin_mono_us": start_vm_ts,
                "cri_to_start_vm_us": start_vm_ts - receive_ts,
                "shim_create_to_start_vm_us": start_vm_ts - create_begin,
                "atomic_write_json_count": len(atomic),
                "atomic_write_json_us": sum(event["duration_us"] for event in atomic),
                "host_owner_atomic_write_count": len(host_owner),
                "host_owner_atomic_write_us": sum(
                    event["duration_us"] for event in host_owner
                ),
                "runtime_owner_atomic_write_count": len(runtime_owner),
                "record_atomic_write_count": len(record),
                "directory_fsync_count": len(directory_fsync),
                "directory_fsync_us": sum(
                    event["duration_us"] for event in directory_fsync
                ),
                "failed_atomic_write_count": len(failed_atomic),
            }
        )
    return samples


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--containerd-log", required=True)
    parser.add_argument("--shim-log", required=True)
    parser.add_argument("--pods-csv", required=True)
    parser.add_argument("--expected", required=True, type=int)
    parser.add_argument("--mode", choices=("serial", "concurrent"), required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--shim-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with pathlib.Path(args.pods_csv).open(newline="") as handle:
        pod_rows = list(csv.DictReader(handle))
    pod_names = {row.get("uid", ""): row.get("name", "") for row in pod_rows}
    if (
        len(pod_rows) != args.expected
        or len(pod_names) != args.expected
        or "" in pod_names
        or any(not name for name in pod_names.values())
    ):
        raise ValueError(
            f"pods.csv inventory rows={len(pod_rows)} unique_uids={len(pod_names)} "
            f"expected={args.expected}"
        )

    all_containerd_events = trace.read_events(args.containerd_log, "containerd")
    shim_events = []
    for component in ("shim", "bootstrap", "vmm-worker"):
        shim_events.extend(trace.read_events(args.shim_log, component))
    containerd_events, attempt_inventory = select_successful_attempts(
        all_containerd_events, pod_names, shim_events
    )
    base = trace.analyze(
        containerd_events,
        [event for event in shim_events if event.get("component") == "shim"],
        pod_names,
        args.mode,
    )
    process_inventory = trace.analyze_process_inventory(
        [event for event in shim_events if event.get("component") == "shim"],
        [event for event in shim_events if event.get("component") == "vmm-worker"],
        [sample["sandbox_id"] for sample in base["samples"]],
    )
    base_by_sid = {
        sample["sandbox_id"]: sample for sample in process_inventory["samples"]
    }
    samples = durable_samples(
        containerd_events, shim_events, base["samples"], base_by_sid, pod_names
    )

    metric_names = sorted(
        key
        for key, value in samples[0].items()
        if isinstance(value, int)
        and (key.endswith("_us") or key.endswith("_count"))
        and not key.endswith("_mono_us")
    )
    distributions = {
        key: trace.distribution([sample[key] for sample in samples])
        for key in metric_names
    }
    rounds = []
    for round_name in sorted(
        {sample["round"] for sample in samples if sample["round"] is not None}
    ):
        selected = [sample for sample in samples if sample["round"] == round_name]
        starts = [sample["start_vm_begin_mono_us"] for sample in selected]
        rounds.append(
            {
                "round": round_name,
                "count": len(selected),
                "start_vm_spread_us": max(starts) - min(starts),
            }
        )

    shim_target = 140_000 if args.mode == "serial" else 150_000
    cri_target = 220_000 if args.mode == "serial" else 300_000
    gates = {
        "correlated_expected": len(samples) == args.expected,
        "no_cri_retries": all(
            item["attempt_count"] == 1 for item in attempt_inventory
        ),
        "unique_pod_sandbox_shim_worker": (
            len({sample["pod_uid"] for sample in samples}) == args.expected
            and len({sample["sandbox_id"] for sample in samples}) == args.expected
            and len({sample["shim_pid"] for sample in samples}) == args.expected
            and len({sample["worker_pid"] for sample in samples}) == args.expected
            and not (
                {sample["shim_pid"] for sample in samples}
                & {sample["worker_pid"] for sample in samples}
            )
        ),
        "shim_create_to_start_vm_p95": (
            distributions["shim_create_to_start_vm_us"]["p95"] <= shim_target
        ),
        "cri_to_start_vm_p95": (
            distributions["cri_to_start_vm_us"]["p95"] <= cri_target
        ),
        "host_owner_atomic_writes_exactly_4": all(
            sample["host_owner_atomic_write_count"] == 4 for sample in samples
        ),
        "all_atomic_writes_successful": all(
            sample["failed_atomic_write_count"] == 0 for sample in samples
        ),
        "all_concurrent_round_start_spreads_le_250ms": all(
            row["count"] == 10 and row["start_vm_spread_us"] <= 250_000
            for row in rounds
        ),
    }
    result = {
        "stage": "S5.5d.2c",
        "mode": args.mode,
        "commit": args.commit,
        "shim_sha256": args.shim_sha256,
        "expected": args.expected,
        "correlated": len(samples),
        "method": {
            "clock": "Linux CLOCK_MONOTONIC shared by containerd and CubeShim",
            "percentile": "nearest-rank",
            "shim_create_to_start_vm": "Shim Create handler begin through start-vm-begin",
            "cri_to_start_vm": "containerd CRI receive through start-vm-begin",
            "atomic_write_wall_time": (
                "sum of atomic-write-json wall durations; each duration already includes "
                "its directory fsync and must not be added to directory_fsync_us"
            ),
        },
        "targets_us": {
            "shim_create_to_start_vm_p95": shim_target,
            "cri_to_start_vm_p95": cri_target,
            "concurrent_round_start_vm_spread": 250_000,
        },
        "distributions": distributions,
        "rounds": rounds,
        "run_podsandbox_attempts": attempt_inventory,
        "gates": gates,
        "all_gates_pass": all(gates.values()),
        "samples": samples,
    }
    pathlib.Path(args.output).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    print(
        "S55D2C_ANALYSIS"
        f" mode={args.mode} correlated={len(samples)}"
        f" shim_create_to_start_vm_p95_us="
        f"{distributions['shim_create_to_start_vm_us']['p95']}"
        f" cri_to_start_vm_p95_us={distributions['cri_to_start_vm_us']['p95']}"
        f" host_owner_writes_p95="
        f"{distributions['host_owner_atomic_write_count']['p95']}"
        f" all_gates_pass={str(all(gates.values())).lower()}"
    )
    for row in rounds:
        print(
            f"S55D2C_ROUND round={row['round']} count={row['count']}"
            f" start_vm_spread_us={row['start_vm_spread_us']}"
        )
    for key in sorted(gates):
        print(f"S55D2C_GATE {key}={str(gates[key]).lower()}")
    if not all(gates.values()):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
