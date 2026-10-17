import os
import unittest

from tdxguard import docker

IMAGE = "ghcr.io/tda-corp/tdxguard-scanner:v1"


def fake_stat(gid):
    def stat(path):
        return os.stat_result((0o140660, 0, 0, 1, 0, gid, 0, 0, 0, 0))

    return stat


def missing(path):
    raise FileNotFoundError(path)


class TestScannerCommand(unittest.TestCase):
    def test_without_images(self):
        command = docker.scanner_command(
            image=IMAGE,
            src="/repo",
            out="/tmp/out",
            cache="/home/u/.cache/tdxguard/scanner",
            uid=1000,
            gid=1000,
            socket=docker.Socket("/var/run/docker.sock", 999),
            excludes=["mobile/", "agents/eval/"],
        )
        self.assertEqual(
            [
                "docker", "run", "--rm",
                "-v", "/repo:/src:ro",
                "-v", "/tmp/out:/out",
                "-v", "/home/u/.cache/tdxguard/scanner:/cache",
                "--user", "1000:1000",
                IMAGE, "scan",
                "--exclude", "mobile/",
                "--exclude", "agents/eval/",
            ],
            command,
        )  # fmt: skip

    def test_with_images(self):
        command = docker.scanner_command(
            image=IMAGE,
            src="/repo",
            out="/tmp/out",
            cache="/c",
            uid=1000,
            gid=1000,
            socket=docker.Socket("/run/user/1000/docker.sock", 998),
            images=[("tdxguard-local/root:scan", "root"), ("tdxguard-local/api:scan", "api")],
            skips=["opengrep"],
            secrets_mode="git",
        )
        self.assertEqual(
            [
                "docker", "run", "--rm",
                "-v", "/repo:/src:ro",
                "-v", "/tmp/out:/out",
                "-v", "/run/user/1000/docker.sock:/var/run/docker.sock",
                "-v", "/c:/cache",
                "--user", "1000:1000",
                "--group-add", "998",
                IMAGE, "scan",
                "--image", "tdxguard-local/root:scan=root",
                "--image", "tdxguard-local/api:scan=api",
                "--skip", "opengrep",
                "--secrets-mode", "git",
            ],
            command,
        )  # fmt: skip

    def test_image_skipped_means_no_socket(self):
        command = docker.scanner_command(
            image=IMAGE,
            src="/r",
            out="/o",
            cache="/c",
            uid=1,
            gid=1,
            socket=docker.Socket("/var/run/docker.sock", 0),
            images=[("tdxguard-local/root:scan", "root")],
            skips=["image"],
        )
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", " ".join(command))
        self.assertNotIn("--image", command)
        self.assertNotIn("--group-add", command)
        self.assertEqual(["--skip", "image"], command[-2:])

    def test_no_group_add_when_the_user_has_the_group(self):
        command = docker.scanner_command(
            image=IMAGE,
            src="/r",
            out="/o",
            cache="/c",
            uid=1000,
            gid=999,
            socket=docker.Socket("/var/run/docker.sock", 999),
            images=[("tdxguard-local/root:scan", "root")],
        )
        self.assertNotIn("--group-add", command)

    def test_build_command(self):
        self.assertEqual(
            ["docker", "build", "-f", "docker/api/Dockerfile", "-t", "tdxguard-local/docker-api:scan", "."],
            docker.build_command("docker/api/Dockerfile", ".", "tdxguard-local/docker-api:scan"),
        )


class TestDetectSocket(unittest.TestCase):
    def test_linux_context(self):
        socket = docker.detect_socket(
            platform="linux", context_host="unix:///run/user/1000/docker.sock", environ={}, stat=fake_stat(1000)
        )
        self.assertEqual(docker.Socket("/run/user/1000/docker.sock", 1000), socket)

    def test_linux_tcp_context_falls_back(self):
        socket = docker.detect_socket(
            platform="linux", context_host="tcp://1.2.3.4:2376", environ={}, stat=fake_stat(998)
        )
        self.assertEqual(docker.Socket("/var/run/docker.sock", 998), socket)

    def test_linux_socket_missing(self):
        socket = docker.detect_socket(platform="linux", context_host="", environ={}, stat=missing)
        self.assertEqual(docker.Socket("/var/run/docker.sock", None), socket)

    def test_docker_desktop(self):
        # The context points at ~/.docker/run/docker.sock on the Mac, but the daemon in
        # the VM knows its socket as /var/run/docker.sock.
        socket = docker.detect_socket(
            platform="darwin", context_host="unix:///Users/jane/.docker/run/docker.sock", environ={}, stat=missing
        )
        self.assertEqual(docker.Socket("/var/run/docker.sock", 0), socket)

    def test_override(self):
        socket = docker.detect_socket(
            platform="darwin", environ={"TDXGUARD_DOCKER_SOCKET": "/custom.sock"}, stat=fake_stat(5)
        )
        self.assertEqual(docker.Socket("/custom.sock", 5), socket)


class TestRegistryImages(unittest.TestCase):
    def command(self, **kwargs):
        return docker.scanner_command(
            image=IMAGE, src="/repo", out="/out", cache="/cache", uid=1000, gid=1000,
            socket=docker.Socket("/var/run/docker.sock", 999), **kwargs,
        )  # fmt: skip

    def test_remote_only_needs_no_socket(self):
        command = self.command(remote_images=[("ghcr.io/org/app:1", "app-1")])
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", command)
        self.assertNotIn("--group-add", command)
        self.assertEqual(["--remote-image", "ghcr.io/org/app:1=app-1"], command[-2:])

    def test_local_and_remote(self):
        command = self.command(images=[("tdxguard-local/api:scan", "api")], remote_images=[("nginx:1", "nginx-1")])
        self.assertIn("/var/run/docker.sock:/var/run/docker.sock", command)
        self.assertEqual(["--image", "tdxguard-local/api:scan=api", "--remote-image", "nginx:1=nginx-1"], command[-4:])

    def test_skip_image_drops_remote_images(self):
        command = self.command(remote_images=[("nginx:1", "nginx-1")], skips=["image"])
        self.assertNotIn("--remote-image", command)


class TestAvailability(unittest.TestCase):
    def test_is_available(self):
        from unittest.mock import patch

        from tdxguard.errors import DockerError

        with patch("tdxguard.docker.ensure_available"):
            self.assertTrue(docker.is_available())
        with patch("tdxguard.docker.ensure_available", side_effect=DockerError("down")):
            self.assertFalse(docker.is_available())


if __name__ == "__main__":
    unittest.main()
