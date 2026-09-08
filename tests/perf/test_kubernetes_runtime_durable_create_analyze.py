#!/usr/bin/env python3

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).parent))
import kubernetes_runtime_durable_create_analyze as analyzer  # noqa: E402


def cri_event(uid, sandbox, phase, timestamp):
    return {
        "component": "containerd",
        "operation": "run-pod-sandbox",
        "phase": phase,
        "pod_uid": uid,
        "sandbox_id": sandbox,
        "ts_mono_us": timestamp,
    }


def start_vm_event(sandbox, timestamp):
    return {
        "component": "shim",
        "operation": "start",
        "phase": "start-vm-begin",
        "sandbox_id": sandbox,
        "ts_mono_us": timestamp,
    }


class DurableCreateAnalyzerTest(unittest.TestCase):
    def test_retry_inventory_selects_only_unique_successful_attempt(self):
        rows = [
            cri_event("pod-1", "failed-sandbox", "cri-receive", 10),
            cri_event("pod-1", "failed-sandbox", "cri-return", 20),
            cri_event("pod-1", "started-sandbox", "cri-receive", 100),
            cri_event("pod-1", "started-sandbox", "cri-return", 200),
        ]
        selected, inventory = analyzer.select_successful_attempts(
            rows, {"pod-1"}, [start_vm_event("started-sandbox", 150)]
        )
        self.assertEqual(
            {row["sandbox_id"] for row in selected}, {"started-sandbox"}
        )
        self.assertEqual(inventory[0]["attempt_count"], 2)
        self.assertEqual(
            [row["started_vm"] for row in inventory[0]["attempts"]],
            [False, True],
        )

    def test_multiple_started_attempts_are_rejected(self):
        rows = [
            cri_event("pod-1", "sandbox-1", "cri-receive", 10),
            cri_event("pod-1", "sandbox-1", "cri-return", 20),
            cri_event("pod-1", "sandbox-2", "cri-receive", 100),
            cri_event("pod-1", "sandbox-2", "cri-return", 200),
        ]
        shim = [start_vm_event("sandbox-1", 15), start_vm_event("sandbox-2", 150)]
        with self.assertRaisesRegex(ValueError, "is 2, expected 1"):
            analyzer.select_successful_attempts(rows, {"pod-1"}, shim)

    def test_attempt_with_multiple_sandbox_ids_is_rejected(self):
        rows = [
            cri_event("pod-1", "sandbox-1", "cri-receive", 10),
            cri_event("pod-1", "sandbox-2", "cri-return", 20),
        ]
        with self.assertRaisesRegex(ValueError, "attempt sandbox inventory"):
            analyzer.select_successful_attempts(rows, {"pod-1"}, [])


if __name__ == "__main__":
    unittest.main()
