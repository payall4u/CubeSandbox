#!/usr/bin/env python3

import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("kubernetes_runtime_trace_analyze.py")
SPEC = importlib.util.spec_from_file_location("kubernetes_runtime_trace_analyze", MODULE_PATH)
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


def event(component, phase, timestamp, duration=None, uid="pod-1", sandbox="sandbox-1"):
    row = {
        "component": component,
        "operation": "create" if component == "shim" else "run-pod-sandbox",
        "phase": phase,
        "pod_uid": uid,
        "sandbox_id": sandbox,
        "ts_mono_us": timestamp,
    }
    if duration is not None:
        row["duration_us"] = duration
    return row


class TraceAnalyzerTest(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(1, 51))
        self.assertEqual(ANALYZER.nearest_rank(values, 0.95), 48)
        self.assertEqual(ANALYZER.nearest_rank(values, 0.99), 50)

    def test_non_overlapping_timeline(self):
        rows = [
            event("containerd", "cri-receive", 100),
            event("containerd", "id-generated", 101),
            event("containerd", "cni-setup", 130, 20),
            event("containerd", "controller-create-begin", 132),
            event("containerd", "shim-manager-start-begin", 135),
            event("containerd", "binary-start-begin", 138),
            event("containerd", "shim-bootstrap-process", 160, 20),
            event("containerd", "shim-connect", 162, 1),
            event("containerd", "shim-create-rpc", 200, 35),
            event("containerd", "controller-create", 240, 108),
            event("containerd", "cri-return", 500),
        ]
        shim = [event("shim", "ttrpc-total", 240, 74)]
        result = ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")
        sample = result["samples"][0]
        self.assertEqual(sample["cri_to_shim_create_begin_us"], 66)
        self.assertEqual(sample["pre_shim_component_sum_us"], 66)
        self.assertEqual(sample["pre_shim_residual_us"], 0)
        self.assertEqual(sample["cube_controlled_pre_shim_us"], 46)
        self.assertTrue(result["absolute_gate_pass"])
        self.assertTrue(result["cube_controlled_gate_pass"])

    def test_cni_and_controller_overlap_has_zero_critical_path_residual(self):
        rows = [
            event("containerd", "cri-receive", 100),
            event("containerd", "id-generated", 101),
            event("containerd", "cni-setup", 230, 120),
            event("containerd", "controller-create-begin", 112),
            event("containerd", "shim-manager-start-begin", 115),
            event("containerd", "binary-start-begin", 118),
            event("containerd", "shim-bootstrap-process", 140, 20),
            event("containerd", "shim-connect", 142, 1),
            event("containerd", "shim-create-rpc", 170, 25),
            event("containerd", "controller-create", 240, 128),
            event("containerd", "cri-return", 500),
        ]
        shim = [event("shim", "ttrpc-total", 240, 94)]
        result = ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")
        sample = result["samples"][0]
        self.assertEqual(sample["timeline_mode"], "overlap")
        self.assertEqual(sample["cri_to_shim_create_begin_us"], 46)
        self.assertEqual(sample["pre_shim_component_sum_us"], 46)
        self.assertEqual(sample["pre_shim_residual_us"], 0)
        self.assertEqual(sample["cni_controller_overlap_before_shim_us"], 34)
        self.assertEqual(sample["cni_remaining_after_shim_us"], 84)
        self.assertEqual(sample["cube_controlled_pre_shim_us"], 46)
        self.assertTrue(result["absolute_gate_pass"])

    def test_duplicate_phase_is_rejected(self):
        rows = [event("containerd", phase, index + 1) for index, phase in enumerate(ANALYZER.REQUIRED_CONTAINERD_PHASES)]
        rows.append(event("containerd", "cri-receive", 20))
        with self.assertRaisesRegex(ValueError, "duplicates"):
            ANALYZER.analyze(rows, [event("shim", "ttrpc-total", 30, 1)], {"pod-1"}, "serial")

    def test_unrelated_uid_is_ignored(self):
        rows = [
            event("containerd", phase, index + 100, uid="unrelated", sandbox="other")
            for index, phase in enumerate(ANALYZER.REQUIRED_CONTAINERD_PHASES)
        ]
        with self.assertRaisesRegex(ValueError, "missing"):
            ANALYZER.analyze(rows, [], {"pod-1"}, "serial")

    def test_missing_required_duration_is_rejected(self):
        rows = [
            event("containerd", phase, index + 100, 1)
            for index, phase in enumerate(ANALYZER.REQUIRED_CONTAINERD_PHASES)
        ]
        del rows[2]["duration_us"]
        shim = [event("shim", "ttrpc-total", 240, 74)]
        with self.assertRaisesRegex(ValueError, "missing duration"):
            ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")

        rows[2]["duration_us"] = 1
        del rows[7]["duration_us"]
        with self.assertRaisesRegex(ValueError, "missing duration"):
            ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")

    def test_invalid_required_duration_is_rejected(self):
        rows = [
            event("containerd", phase, index + 100, 1)
            for index, phase in enumerate(ANALYZER.REQUIRED_CONTAINERD_PHASES)
        ]
        rows[2]["duration_us"] = -1
        shim = [event("shim", "ttrpc-total", 240, 74)]
        with self.assertRaisesRegex(ValueError, "invalid duration"):
            ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")

        rows[2]["duration_us"] = 1
        rows[7]["duration_us"] = -1
        with self.assertRaisesRegex(ValueError, "invalid duration"):
            ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")

    def test_non_monotonic_timeline_is_rejected(self):
        rows = [
            event("containerd", "cri-receive", 100),
            event("containerd", "id-generated", 101),
            event("containerd", "cni-setup", 130, 20),
            event("containerd", "controller-create-begin", 136),
            event("containerd", "shim-manager-start-begin", 135),
            event("containerd", "binary-start-begin", 138),
            event("containerd", "shim-bootstrap-process", 160, 20),
            event("containerd", "shim-connect", 162, 1),
            event("containerd", "shim-create-rpc", 200, 35),
            event("containerd", "controller-create", 240, 108),
            event("containerd", "cri-return", 500),
        ]
        shim = [event("shim", "ttrpc-total", 240, 74)]
        with self.assertRaisesRegex(ValueError, "non-monotonic controller"):
            ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")

    def test_controller_before_cni_dispatch_is_rejected(self):
        rows = [
            event("containerd", "cri-receive", 100),
            event("containerd", "id-generated", 101),
            event("containerd", "cni-setup", 230, 120),
            event("containerd", "controller-create-begin", 109),
            event("containerd", "shim-manager-start-begin", 115),
            event("containerd", "binary-start-begin", 118),
            event("containerd", "shim-bootstrap-process", 140, 20),
            event("containerd", "shim-connect", 142, 1),
            event("containerd", "shim-create-rpc", 170, 25),
            event("containerd", "controller-create", 240, 131),
            event("containerd", "cri-return", 500),
        ]
        shim = [event("shim", "ttrpc-total", 240, 94)]
        with self.assertRaisesRegex(ValueError, "before CNI dispatch"):
            ANALYZER.analyze(rows, shim, {"pod-1"}, "serial")

    def test_bootstrap_parent_and_server_are_classified(self):
        rows = [
            {
                "component": "bootstrap",
                "operation_id": "sandbox-1",
                "phase": phase,
                "ts_mono_us": index + 100,
                "duration_us": index + 1,
            }
            for index, phase in enumerate(ANALYZER.REQUIRED_BOOTSTRAP_PHASES)
        ]
        rows.extend([
            {
                "component": "bootstrap", "operation_id": "sandbox-1",
                "phase": "main-runtime-ready", "action": "start",
                "ts_mono_us": 90, "duration_us": 7,
            },
            {
                "component": "bootstrap", "operation_id": "sandbox-1",
                "phase": "main-runtime-ready", "action": "serve",
                "ts_mono_us": 95, "duration_us": 9,
            },
        ])
        result = ANALYZER.analyze_bootstrap(rows, {"sandbox-1"})
        self.assertEqual(result["correlated"], 1)
        self.assertEqual(result["distributions"]["start_main_runtime_us"]["p95"], 7)
        self.assertEqual(result["distributions"]["serve_main_runtime_us"]["p95"], 9)

    def test_process_inventory_binds_shim_and_worker(self):
        shim = [{
            "component": "shim", "operation": "create",
            "phase": "systemd-placement-ready", "sandbox_id": "sandbox-1",
            "target_pid": "101", "ts_mono_us": 10,
        }]
        worker = [{
            "component": "vmm-worker", "operation": "start",
            "phase": "fork-exec", "sandbox_id": "sandbox-1",
            "worker_pid": "202", "ts_mono_us": 20,
        }]
        result = ANALYZER.analyze_process_inventory(shim, worker, {"sandbox-1"})
        self.assertEqual(result["correlated"], 1)
        self.assertEqual(result["unique_shim_pids"], 1)
        self.assertEqual(result["unique_worker_pids"], 1)
        self.assertEqual(result["samples"][0]["shim_pid"], 101)
        self.assertEqual(result["samples"][0]["worker_pid"], 202)

    def test_process_inventory_rejects_duplicate_pids(self):
        shim = [
            {
                "component": "shim", "operation": "create",
                "phase": "systemd-placement-ready", "sandbox_id": sandbox,
                "target_pid": "101", "ts_mono_us": 10,
            }
            for sandbox in ("sandbox-1", "sandbox-2")
        ]
        worker = [
            {
                "component": "vmm-worker", "operation": "start",
                "phase": "fork-exec", "sandbox_id": sandbox,
                "worker_pid": str(pid), "ts_mono_us": 20,
            }
            for sandbox, pid in (("sandbox-1", 201), ("sandbox-2", 202))
        ]
        with self.assertRaisesRegex(ValueError, "not one-to-one"):
            ANALYZER.analyze_process_inventory(
                shim, worker, {"sandbox-1", "sandbox-2"}
            )

    def test_process_inventory_rejects_cross_role_pid_overlap(self):
        shim = [
            {
                "component": "shim", "operation": "create",
                "phase": "systemd-placement-ready", "sandbox_id": sandbox,
                "target_pid": str(pid), "ts_mono_us": 10,
            }
            for sandbox, pid in (("sandbox-1", 101), ("sandbox-2", 102))
        ]
        worker = [
            {
                "component": "vmm-worker", "operation": "start",
                "phase": "fork-exec", "sandbox_id": sandbox,
                "worker_pid": str(pid), "ts_mono_us": 20,
            }
            for sandbox, pid in (("sandbox-1", 201), ("sandbox-2", 101))
        ]
        with self.assertRaisesRegex(ValueError, "overlap"):
            ANALYZER.analyze_process_inventory(
                shim, worker, {"sandbox-1", "sandbox-2"}
            )


if __name__ == "__main__":
    unittest.main()
