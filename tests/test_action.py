import importlib
import os
import unittest
from unittest.mock import patch


class TestApiBaseUrl(unittest.TestCase):
    """Tests for the API_BASE_URL module-level constant in action.py."""

    def _reload_action(self):
        """Reload action module so that the module-level constant is re-evaluated."""
        import action
        return importlib.reload(action)

    @patch.dict(os.environ, {}, clear=True)
    def test_defaults_to_github_com(self):
        # Ensure GITHUB_API_URL is not set so the default is used
        os.environ.pop('GITHUB_API_URL', None)
        action = self._reload_action()
        self.assertEqual(action.API_BASE_URL, 'https://api.github.com')

    @patch.dict(os.environ, {'GITHUB_API_URL': 'https://api.octodemo.ghe.com'})
    def test_honors_github_api_url(self):
        action = self._reload_action()
        self.assertEqual(action.API_BASE_URL, 'https://api.octodemo.ghe.com')

    @patch.dict(os.environ, {'GITHUB_API_URL': 'https://api.github.com/'})
    def test_strips_trailing_slash(self):
        action = self._reload_action()
        self.assertEqual(action.API_BASE_URL, 'https://api.github.com')

    @patch.dict(os.environ, {'GITHUB_API_URL': 'https://ghes.example.com/api/v3'})
    def test_ghes_url(self):
        action = self._reload_action()
        self.assertEqual(action.API_BASE_URL, 'https://ghes.example.com/api/v3')


if __name__ == '__main__':
    unittest.main()
