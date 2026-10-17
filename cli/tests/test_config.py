import tempfile
import unittest
from pathlib import Path

import yaml

from tdxguard import config, gitinfo
from tdxguard.errors import ConfigError


class TestDeriveSlug(unittest.TestCase):
    # The same cases as the comment in ci-templates/github/tdxguard.yml, plus the edges of
    # its sed expression.
    CASES = {
        "docker/backend/Dockerfile": "docker-backend",
        "Dockerfile": "root",
        "./Dockerfile.prod": "prod",
        "Deploy/Dockerfile": "deploy",
        "api.Dockerfile": "api",
        "services/web/Dockerfile.dev": "services-web.dev",
        "docker/My App/Dockerfile": "docker-my-app",
        "frontend/Dockerfile-alpine": "frontend-alpine",
        "dockerfile": "root",
        # Only the first "dockerfile" goes, like sed without the g flag.
        "dockerfiles/Dockerfile": "s-dockerfile",
    }

    def test_cases(self):
        for dockerfile, expected in self.CASES.items():
            with self.subTest(dockerfile=dockerfile):
                self.assertEqual(expected, config.derive_slug(dockerfile))


class TestParse(unittest.TestCase):
    def assert_error(self, data, fragment, root=None):
        with self.assertRaises(ConfigError) as cm:
            config.parse(data, root)
        self.assertIn(fragment, cm.exception.message)
        return cm.exception

    def test_minimal(self):
        cfg = config.parse({"project": "tdx-scribe"})
        self.assertEqual("tdx-scribe", cfg.project)
        self.assertIsNone(cfg.repository)
        self.assertEqual([], cfg.exclude)
        self.assertEqual([], cfg.images)
        self.assertEqual({}, cfg.gate)

    def test_full(self):
        cfg = config.parse(
            {
                "project": "tdx-scribe",
                "repository": "tda-corp/tdx-scribe",
                "exclude": ["mobile/", "./agents/eval/"],
                "images": [
                    {"dockerfile": "Dockerfile", "context": ".", "name": "root"},
                    {"dockerfile": "docker/backend/Dockerfile"},
                    "web/Dockerfile.prod",
                ],
                "gate": {"critical": 0, "high": None},
            }
        )
        self.assertEqual(["mobile/", "agents/eval/"], cfg.exclude)
        self.assertEqual(
            [("Dockerfile", ".", "root"), ("docker/backend/Dockerfile", "docker/backend", "docker-backend")],
            [(i.dockerfile, i.context, i.name) for i in cfg.images[:2]],
        )
        self.assertEqual("web.prod", cfg.images[2].name)
        self.assertEqual("tdxguard-local/docker-backend:scan", cfg.images[1].ref)
        self.assertEqual({"critical": 0, "high": None}, cfg.gate)

    def test_not_a_mapping(self):
        self.assert_error(["project"], "must be a mapping")
        self.assert_error(None, "must be a mapping")

    def test_project_missing(self):
        self.assert_error({}, ".tdxguard.yml: project: is required")

    def test_project_not_a_string(self):
        self.assert_error({"project": 42}, "project: must be a non-empty string")

    def test_unknown_top_level_key(self):
        error = self.assert_error({"project": "p", "imagse": []}, ".tdxguard.yml: imagse: unknown key")
        self.assertIn("images", error.hint)

    def test_exclude_absolute(self):
        self.assert_error({"project": "p", "exclude": ["/etc"]}, "exclude[0]: must be a path relative")

    def test_exclude_leaves_repository(self):
        self.assert_error({"project": "p", "exclude": ["ok/", "../x"]}, "exclude[1]: must stay inside")

    def test_exclude_wrong_type(self):
        self.assert_error({"project": "p", "exclude": {"a": 1}}, "exclude: must be a list")

    def test_image_without_dockerfile(self):
        self.assert_error({"project": "p", "images": [{"context": "."}]}, "images[0].dockerfile: is required")

    def test_image_unknown_key(self):
        self.assert_error({"project": "p", "images": [{"dockerfile": "D", "tag": "x"}]}, "images[0].tag: unknown key")

    def test_image_bad_name(self):
        self.assert_error(
            {"project": "p", "images": [{"dockerfile": "Dockerfile", "name": "Bad Name"}]},
            "images[0].name: must be a slug",
        )

    def test_image_duplicate_name(self):
        self.assert_error(
            {"project": "p", "images": ["Dockerfile", {"dockerfile": "x/Dockerfile", "name": "root"}]},
            "images[1].name: the name 'root' is used twice",
        )

    def test_ignore_unfixed(self):
        self.assertTrue(config.parse({"project": "p"}).ignore_unfixed)
        self.assertTrue(config.parse({"project": "p", "gate": {"critical": 0}}).ignore_unfixed)
        cfg = config.parse({"project": "p", "gate": {"critical": 0, "ignore_unfixed": False}})
        self.assertFalse(cfg.ignore_unfixed)
        self.assertEqual({"critical": 0}, cfg.gate)
        self.assert_error(
            {"project": "p", "gate": {"ignore_unfixed": "no"}}, "gate.ignore_unfixed: must be true or false"
        )

    def test_gate_unknown_key(self):
        self.assert_error({"project": "p", "gate": {"medium": 1}}, "gate.medium: unknown key")

    def test_gate_negative(self):
        self.assert_error({"project": "p", "gate": {"high": -1}}, "gate.high: must be a whole number")

    def test_gate_bool(self):
        self.assert_error({"project": "p", "gate": {"critical": True}}, "gate.critical: must be a whole number")

    def test_files_must_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app" / "Dockerfile").write_text("FROM scratch\n")
            cfg = config.parse({"project": "p", "images": ["app/Dockerfile"]}, root)
            self.assertEqual("app", cfg.images[0].context)

            self.assert_error(
                {"project": "p", "images": ["missing/Dockerfile"]}, "file not found: missing/Dockerfile", root
            )
            self.assert_error(
                {"project": "p", "images": [{"dockerfile": "app/Dockerfile", "context": "nope"}]},
                "images[0].context: directory not found: nope",
                root,
            )


class TestLoad(unittest.TestCase):
    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConfigError) as cm:
                config.load(Path(directory))
            self.assertIn("tdxguard init", cm.exception.hint)

    def test_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".tdxguard.yml").write_text("project: [unclosed\n")
            with self.assertRaises(ConfigError) as cm:
                config.load(Path(directory))
            self.assertIn("not valid YAML", cm.exception.message)


class TestInit(unittest.TestCase):
    def test_find_dockerfiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in (
                "Dockerfile",
                "api.Dockerfile",
                "web/Dockerfile.prod",
                "docker/backend/Dockerfile",
                "node_modules/pkg/Dockerfile",
                "vendor/x/Dockerfile",
                ".git/Dockerfile",
                "docs/dockerfile-guide.md",
                "README.md",
            ):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text("")
            self.assertEqual(
                ["Dockerfile", "api.Dockerfile", "web/Dockerfile.prod", "docker/backend/Dockerfile"],
                config.find_dockerfiles(root),
            )

    def test_render_round_trip(self):
        text = config.render("tdx-scribe", "tda-corp/tdx-scribe", ["Dockerfile", "docker/backend/Dockerfile"])
        cfg = config.parse(yaml.safe_load(text))
        self.assertEqual("tdx-scribe", cfg.project)
        self.assertEqual("tda-corp/tdx-scribe", cfg.repository)
        self.assertEqual(["root", "docker-backend"], [i.name for i in cfg.images])
        self.assertEqual("docker/backend", cfg.images[1].context)
        self.assertEqual({"critical": 0, "high": None}, cfg.gate)
        self.assertTrue(cfg.ignore_unfixed)

    def test_render_without_dockerfiles(self):
        cfg = config.parse(yaml.safe_load(config.render("p1", None, [])))
        self.assertEqual([], cfg.images)
        self.assertIsNone(cfg.repository)

    def test_render_quotes_odd_values(self):
        cfg = config.parse(yaml.safe_load(config.render("yes", None, ["a b/Dockerfile"])))
        self.assertEqual("yes", cfg.project)
        self.assertEqual("a b/Dockerfile", cfg.images[0].dockerfile)

    def test_product_name_from_repository(self):
        self.assertEqual("tdx-scribe", config.product_name_from_repository("tdx-scribe"))
        self.assertEqual("my-app-v2", config.product_name_from_repository("My_App.v2"))
        self.assertEqual("my-project", config.product_name_from_repository("___"))


class TestParseRemote(unittest.TestCase):
    def test_remotes(self):
        cases = {
            "git@github.com:tda-corp/tdx-scribe.git": ("tda-corp/tdx-scribe", "tdx-scribe"),
            "https://github.com/tda-corp/tdx-scribe": ("tda-corp/tdx-scribe", "tdx-scribe"),
            "https://gitlab.example.com/group/sub/project.git": ("group/sub/project", "project"),
            "ssh://git@gitlab.example.com:2222/group/project.git": ("group/project", "project"),
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(expected, gitinfo.parse_remote(url))


class TestEngineAndRegistryImages(unittest.TestCase):
    def test_engine(self):
        self.assertIsNone(config.parse({"project": "p"}).engine)
        for engine in ("auto", "docker", "native"):
            self.assertEqual(engine, config.parse({"project": "p", "engine": engine}).engine)
        with self.assertRaises(ConfigError) as cm:
            config.parse({"project": "p", "engine": "podman"})
        self.assertIn("engine: must be one of auto, docker, native", cm.exception.message)

    def test_registry_image(self):
        cfg = config.parse(
            {
                "project": "p",
                "images": [{"ref": "ghcr.io/org/app:1.2"}, {"ref": " nginx ", "name": "web"}, "Dockerfile"],
            }
        )
        app, web, root = cfg.images
        self.assertEqual(("app-1.2", "ghcr.io/org/app:1.2", True), (app.name, app.ref, app.remote))
        self.assertIsNone(app.dockerfile)
        self.assertEqual(("web", "nginx"), (web.name, web.ref))
        self.assertEqual(("root", "tdxguard-local/root:scan", False), (root.name, root.ref, root.remote))

    def test_ref_slugs(self):
        cases = {
            "ghcr.io/org/app:1.2": "app-1.2",
            "registry:5000/team/api": "api",
            "nginx@sha256:" + "a" * 64: "nginx",
            "Org/App_Name:Latest": "app_name-latest",
        }
        for ref, slug in cases.items():
            with self.subTest(ref=ref):
                self.assertEqual(slug, config.derive_ref_slug(ref))
                self.assertRegex(slug, config.SLUG_PATTERN)

    def test_registry_image_errors(self):
        cases = [
            ({"ref": "app:1", "dockerfile": "Dockerfile"}, "images[0].dockerfile: an image with `ref` is not built"),
            ({"ref": "app:1", "context": "."}, "images[0].context: an image with `ref` is not built"),
            ({"ref": ""}, "images[0].ref: must be an image reference"),
            ({"ref": "app 1"}, "images[0].ref: must be an image reference"),
            ({"ref": "app:1", "name": "Bad Name"}, "images[0].name: must be a slug"),
            ({"name": "x"}, "images[0].dockerfile: is required"),
        ]
        for entry, message in cases:
            with self.subTest(entry=entry), self.assertRaises(ConfigError) as cm:
                config.parse({"project": "p", "images": [entry]})
            self.assertIn(message, cm.exception.message)

    def test_names_unique_across_forms(self):
        with self.assertRaises(ConfigError) as cm:
            config.parse({"project": "p", "images": ["Dockerfile", {"ref": "app:1", "name": "root"}]})
        self.assertIn("is used twice", cm.exception.message)


if __name__ == "__main__":
    unittest.main()
