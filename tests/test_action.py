import importlib
import os
import unittest


class TestApiBaseUrl(unittest.TestCase):
    """Tests for the API_BASE_URL module-level constant in action.py."""

    def _reload_action(self):
        """Reload action module so that the module-level constant is re-evaluated."""
        import action
        return importlib.reload(action)

    def test_defaults_to_github_com(self):
        os.environ.pop('GITHUB_API_URL', None)
        action = self._reload_action()
        self.assertEqual(action.API_BASE_URL, 'https://api.github.com')

    def test_honors_github_api_url(self):
        os.environ['GITHUB_API_URL'] = 'https://api.octodemo.ghe.com'
        try:
            action = self._reload_action()
            self.assertEqual(action.API_BASE_URL, 'https://api.octodemo.ghe.com')
        finally:
            del os.environ['GITHUB_API_URL']

    def test_strips_trailing_slash(self):
        os.environ['GITHUB_API_URL'] = 'https://api.github.com/'
        try:
            action = self._reload_action()
            self.assertEqual(action.API_BASE_URL, 'https://api.github.com')
        finally:
            del os.environ['GITHUB_API_URL']

    def test_ghes_url(self):
        os.environ['GITHUB_API_URL'] = 'https://ghes.example.com/api/v3'
        try:
            action = self._reload_action()
            self.assertEqual(action.API_BASE_URL, 'https://ghes.example.com/api/v3')
        finally:
            del os.environ['GITHUB_API_URL']


if __name__ == '__main__':
    unittest.main()
