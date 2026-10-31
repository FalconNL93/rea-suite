"""Registration decisions must consider the full configuration, not just its command."""

import unittest
from unittest.mock import patch

from rea_suite import agents


class RegistrationTests(unittest.TestCase):
    def agent(self, current=True, **extra):
        return {
            "name": "codex",
            "display": "Codex",
            "command": agents.LAUNCHER,
            "current": current,
            "quit_first": False,
            **extra,
        }

    def test_suite_launcher_with_outdated_settings_needs_refresh(self):
        self.assertEqual(agents.state(self.agent(current=False)), "stale")

    def test_current_registration_is_unchanged(self):
        with patch.object(agents, "run") as run:
            self.assertIsNone(agents.register(self.agent(), named=False))
        run.assert_not_called()

    def test_desktop_is_deferred_until_explicitly_selected(self):
        agent = self.agent(current=False, quit_first=True)
        with patch.object(agents, "run") as run:
            self.assertIn("quit it fully", agents.register(agent, named=False))
        run.assert_not_called()

    def test_outdated_registration_is_repaired(self):
        agent = self.agent(current=False, definition={"format": "toml"})
        with patch.object(agents, "registration") as registration:
            self.assertIsNone(agents.register(agent, named=False))
        registration.assert_called_once_with("configure", [agent])


if __name__ == "__main__":
    unittest.main()
