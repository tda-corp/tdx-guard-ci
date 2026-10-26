import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tdxguard.engine.helpers import opengrep_prune_rules as prune

RULE = "rules:\n- id: {name}\n  pattern: $X\n  languages: [php]\n"
SYMFONY = "php/symfony/security/audit/symfony-non-literal-redirect.yaml"
DJANGO_CSRF = "python/django/security/django-no-csrf-token.yaml"
LARAVEL = "php/laravel/security/laravel-sql-injection.yaml"


class TestPruneRules(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.rules = Path(tmp.name) / "rules"
        self.repo = Path(tmp.name) / "repo"
        for relative in (SYMFONY, DJANGO_CSRF, LARAVEL):
            path = self.rules / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(RULE.format(name=path.stem))
        self.repo.mkdir()

    def write(self, relative: str, text: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run_prune(self) -> str:
        out = io.StringIO()
        with patch("sys.argv", ["opengrep-prune-rules.py", str(self.rules), str(self.repo)]), redirect_stdout(out):
            self.assertEqual(0, prune.main())
        return out.getvalue()

    def test_symfony_redirect_rule_needs_the_framework_bundle(self):
        # A Yii or Laravel application pulls in symfony/* components without being Symfony:
        # `$this->redirect(...)` there is the framework's own redirect, not Symfony's.
        self.write("composer.json", '{"require": {"yiisoft/yii2": "~2.0", "symfony/mailer": "^7.0"}}')
        output = self.run_prune()
        self.assertFalse((self.rules / SYMFONY).exists())
        self.assertIn("symfony name-only rules (1): removed, not used", output)
        # Framework rules that are not name-only stay.
        self.assertTrue((self.rules / LARAVEL).exists())

    def test_symfony_redirect_rule_confined_to_the_symfony_subproject(self):
        self.write("api/composer.json", '{"require": {"symfony/framework-bundle": "7.1.*"}}')
        self.write("web/package.json", '{"dependencies": {"react": "19"}}')
        output = self.run_prune()
        self.assertIn('- "api/**"', (self.rules / SYMFONY).read_text())
        self.assertIn("symfony name-only rules (1): only api/", output)

    def test_django_csrf_rule_only_where_django_is(self):
        # Thymeleaf, Blade or ERB forms get their CSRF token from their own framework.
        self.write("pom.xml", "<project><artifactId>spring-boot-starter-web</artifactId></project>")
        self.run_prune()
        self.assertFalse((self.rules / DJANGO_CSRF).exists())

    def test_django_csrf_rule_kept_in_a_django_project(self):
        self.write("requirements.txt", "Django==5.2\n")
        output = self.run_prune()
        self.assertTrue((self.rules / DJANGO_CSRF).exists())
        self.assertNotIn("paths:", (self.rules / DJANGO_CSRF).read_text())
        self.assertIn("django name-only rules (1): whole repository", output)

    def test_a_rule_with_paths_of_its_own_keeps_them_below_the_directory(self):
        # The real django-no-csrf-token has `paths: include: ["*.html"]`. A second `paths:` key
        # made Opengrep reject the whole configuration and scan nothing (tda-plane, apps/api/).
        (self.rules / DJANGO_CSRF).write_text(
            "rules:\n  - id: django-no-csrf-token\n    pattern: <form>\n    languages: [generic]\n"
            '    paths:\n      include:\n        - "*.html"\n        - "**/templates/*.txt"\n'
            "      exclude:\n        - tests\n    severity: WARNING\n"
        )
        self.write("apps/api/requirements.txt", "Django==5.2\n")
        self.write("apps/web/package.json", '{"dependencies": {"next": "16"}}')
        self.run_prune()
        text = (self.rules / DJANGO_CSRF).read_text()
        self.assertEqual(1, text.count("paths:"), text)
        self.assertIn('        - "apps/api/**/*.html"\n        - "apps/api/**/templates/*.txt"\n', text)
        self.assertIn("      exclude:\n        - tests\n    severity: WARNING\n", text)

    def test_a_rule_with_only_an_exclude_gets_an_include(self):
        (self.rules / DJANGO_CSRF).write_text(
            "rules:\n- id: django-no-csrf-token\n  pattern: <form>\n  paths:\n    exclude:\n      - tests\n"
        )
        self.write("apps/api/requirements.txt", "Django==5.2\n")
        self.run_prune()
        text = (self.rules / DJANGO_CSRF).read_text()
        self.assertEqual(1, text.count("paths:"), text)
        self.assertIn('  paths:\n    include:\n      - "apps/api/**"\n    exclude:\n      - tests\n', text)


if __name__ == "__main__":
    unittest.main()
