import ipaddress
import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from boq.core import Boq


class DockerSubnetAllocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_home = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_home.cleanup)
        self.env = patch.dict(os.environ, {"HOME": self.temp_home.name}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def make_boq(self) -> Boq:
        boq = Boq("test")
        boq.boq_root.mkdir(parents=True, exist_ok=True)
        return boq

    def test_reallocates_persisted_subnet_when_it_now_conflicts(self) -> None:
        boq = self.make_boq()
        boq._save_docker_subnet("10.88.0.0/16")

        occupied = [ipaddress.ip_network("10.88.0.0/16")]

        def fake_run_cmd(cmd: list[str], check: bool = True, capture: bool = False, **kwargs):
            if cmd[:3] == ["docker", "network", "inspect"]:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            raise AssertionError(f"unexpected command: {cmd}")

        with patch.object(Boq, "_runtime_prefix", return_value=[]):
            with patch("boq.core.run_cmd", side_effect=fake_run_cmd):
                with patch.object(Boq, "_collect_occupied_networks", return_value=occupied):
                    subnet = boq._get_or_allocate_docker_subnet_locked()

        self.assertEqual(subnet, "10.200.0.0/16")
        self.assertEqual(Path(self.temp_home.name, ".boq", ".docker-subnet").read_text().strip(), subnet)

    def test_existing_managed_network_remains_authoritative(self) -> None:
        boq = self.make_boq()
        boq._save_docker_subnet("10.88.0.0/16")

        def fake_run_cmd(cmd: list[str], check: bool = True, capture: bool = False, **kwargs):
            if cmd[:3] == ["docker", "network", "inspect"]:
                return subprocess.CompletedProcess(cmd, 0, "10.200.0.0/16\n", "")
            raise AssertionError(f"unexpected command: {cmd}")

        with patch.object(Boq, "_runtime_prefix", return_value=[]):
            with patch("boq.core.run_cmd", side_effect=fake_run_cmd):
                subnet = boq._get_or_allocate_docker_subnet_locked()

        self.assertEqual(subnet, "10.200.0.0/16")
        self.assertEqual(Path(self.temp_home.name, ".boq", ".docker-subnet").read_text().strip(), subnet)

    def test_nonlocked_lookup_still_revalidates_persisted_subnet(self) -> None:
        boq = self.make_boq()
        boq._save_docker_subnet("10.88.0.0/16")

        class FakeLock:
            @contextmanager
            def exclusive(self):
                yield None

        with patch("boq.core.get_global_lock", return_value=FakeLock()):
            with patch.object(Boq, "_get_or_allocate_docker_subnet_locked", return_value="10.200.0.0/16") as locked:
                subnet = boq._get_or_allocate_docker_subnet()

        self.assertEqual(subnet, "10.200.0.0/16")
        locked.assert_called_once_with()
