import tempfile
import unittest
from pathlib import Path

from ssh_guard import audit, install_dropin, parse_config, parse_effective_output


class SshGuardTests(unittest.TestCase):
    def test_first_value_wins_and_match_is_not_global(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sshd_config"
            config.write_text("PermitRootLogin no\nPermitRootLogin yes\nMatch User guest\nPasswordAuthentication yes\n", encoding="utf-8")
            self.assertEqual(parse_config(config), {"permitrootlogin": "no"})

    def test_effective_output_and_audit(self):
        settings = parse_effective_output("permitrootlogin no\npasswordauthentication no\nmaxauthtries 3\n")
        findings = {item.key: item for item in audit(settings)}
        self.assertEqual(findings["permitrootlogin"].status, "pass")
        self.assertEqual(findings["maxauthtries"].status, "pass")

    def test_apply_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            ok, message = install_dropin(Path(directory) / "sshd_config", Path(directory) / "dropin", False)
            self.assertFalse(ok)
            self.assertIn("--yes", message)


if __name__ == "__main__":
    unittest.main()
