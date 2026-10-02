"""Tests for pagination in action.py"""

import importlib
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import requests

# Add parent directory to path so we can import action module
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import action


def _make_comments(n):
    """Create a list of n fake comment dicts."""
    return [{"id": i, "body": f"comment {i}"} for i in range(n)]


def _make_issue_comment_url(owner, repo, comment_id):
    """Create a GitHub issue comment API URL for test data."""
    return f"{action.API_BASE_URL}/repos/{owner}/{repo}/issues/comments/{comment_id}"


def _mock_response(json_data, status_code=200):
    """Create a mock response object."""
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status.return_value = None
    return resp


class TestGetPullRequestCommentsPagination:
    """Tests for get_pull_request_comments pagination."""

    @patch("action.requests.get")
    def test_single_page(self, mock_get):
        """When fewer than 100 comments, only one request is made."""
        comments = _make_comments(50)
        mock_get.return_value = _mock_response(comments)

        result = action.get_pull_request_comments(
            "token", "owner", "repo", 1, None, None, True
        )

        assert len(result) == 50
        assert mock_get.call_count == 1

    @patch("action.requests.get")
    def test_multiple_pages(self, mock_get):
        """When exactly 100 comments on first page, fetches next page."""
        page1 = _make_comments(100)
        page2 = _make_comments(30)
        mock_get.side_effect = [_mock_response(page1), _mock_response(page2)]

        result = action.get_pull_request_comments(
            "token", "owner", "repo", 1, None, None, True
        )

        assert len(result) == 130
        assert mock_get.call_count == 2
        # Verify second call uses page=2
        second_call_url = mock_get.call_args_list[1][0][0]
        assert "page=2" in second_call_url

    @patch("action.requests.get")
    def test_three_pages(self, mock_get):
        """When 100 comments on first two pages, fetches all three."""
        page1 = _make_comments(100)
        page2 = _make_comments(100)
        page3 = _make_comments(10)
        mock_get.side_effect = [
            _mock_response(page1),
            _mock_response(page2),
            _mock_response(page3),
        ]

        result = action.get_pull_request_comments(
            "token", "owner", "repo", 1, None, None, True
        )

        assert len(result) == 210
        assert mock_get.call_count == 3
        # Verify page numbers advance
        urls = [call[0][0] for call in mock_get.call_args_list]
        assert "page=1" in urls[0]
        assert "page=2" in urls[1]
        assert "page=3" in urls[2]

    @patch("action.requests.get")
    def test_http_404_exits(self, mock_get):
        """When GitHub returns 404, the function exits with failure."""
        resp = _mock_response({"message": "Not Found"}, status_code=404)
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error")
        mock_get.return_value = resp

        with pytest.raises(SystemExit) as exc:
            action.get_pull_request_comments("token", "owner", "repo", 1, None, None, True)
        assert exc.value.code == 1

    @patch("action.requests.get")
    def test_http_410_exits(self, mock_get):
        """When GitHub returns 410, the function exits with failure."""
        resp = _mock_response({"message": "Gone"}, status_code=410)
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("410 Client Error")
        mock_get.return_value = resp

        with pytest.raises(SystemExit) as exc:
            action.get_pull_request_comments("token", "owner", "repo", 1, None, None, True)
        assert exc.value.code == 1


class TestUpdatePullRequestCommentPagination:
    """Tests for update_pull_request_comment pagination during comment fetching."""

    @patch("action.requests.patch")
    @patch("action.requests.post")
    @patch("action.requests.get")
    def test_pagination_advances_pages(self, mock_get, mock_post, mock_patch):
        """Verify pagination URL is rebuilt with incremented page number."""
        watermark = "<!-- secret-scanning-review-pr-comment-watermark -->"
        page1 = _make_comments(100)
        page2 = [
            {
                "id": 200,
                "body": f"{watermark}\nold summary",
                "url": _make_issue_comment_url("owner", "repo", 200),
            }
        ]
        mock_get.side_effect = [_mock_response(page1), _mock_response(page2)]

        # Mock PATCH for updating an existing comment found on page 2
        mock_patch.return_value = _mock_response(
            {"html_url": "https://github.com/owner/repo/pull/1#issuecomment-200"}
        )

        action.update_pull_request_comment(
            "token", "owner", "repo", 1, "summary", None, None, True
        )

        assert mock_get.call_count == 2
        second_call_url = mock_get.call_args_list[1][0][0]
        assert "page=2" in second_call_url
        # Ensure comments from page 2 were actually processed
        assert mock_patch.call_count == 1
        assert mock_post.call_count == 0

    @patch("action.requests.patch")
    @patch("action.requests.get")
    def test_finds_existing_comment_across_pages(self, mock_get, mock_patch):
        """When the watermark comment is on page 2, it should be found."""
        watermark = "<!-- secret-scanning-review-pr-comment-watermark -->"
        page1 = _make_comments(100)
        page2 = [{
            "id": 200,
            "body": f"{watermark}\nold summary",
            "url": _make_issue_comment_url("owner", "repo", 200),
        }]
        mock_get.side_effect = [_mock_response(page1), _mock_response(page2)]

        mock_patch.return_value = _mock_response(
            {"html_url": "https://github.com/owner/repo/pull/1#issuecomment-200"}
        )

        action.update_pull_request_comment(
            "token", "owner", "repo", 1, "new summary", None, None, True
        )

        # Should have used PATCH (existing comment found), not POST
        assert mock_patch.call_count == 1


class TestApiBaseUrl:
    """Tests for API_BASE_URL module-level configuration."""

    @staticmethod
    def _reload_action():
        return importlib.reload(action)

    @patch.dict(os.environ, {}, clear=True)
    def test_defaults_to_github_com(self):
        # Ensure GITHUB_API_URL is not set so the default is used
        os.environ.pop("GITHUB_API_URL", None)
        reloaded_action = self._reload_action()
        assert reloaded_action.API_BASE_URL == "https://api.github.com"

    @patch.dict(os.environ, {"GITHUB_API_URL": "https://api.octodemo.ghe.com"})
    def test_honors_github_api_url(self):
        reloaded_action = self._reload_action()
        assert reloaded_action.API_BASE_URL == "https://api.octodemo.ghe.com"

    @patch.dict(os.environ, {"GITHUB_API_URL": "https://api.github.com/"})
    def test_strips_trailing_slash(self):
        reloaded_action = self._reload_action()
        assert reloaded_action.API_BASE_URL == "https://api.github.com"

    @patch.dict(os.environ, {"GITHUB_API_URL": "https://ghes.example.com/api/v3"})
    def test_ghes_url(self):
        reloaded_action = self._reload_action()
        assert reloaded_action.API_BASE_URL == "https://ghes.example.com/api/v3"


def test_main_retains_only_matching_locations_and_trusts_review_comment_locations(monkeypatch, tmp_path):
    """Matching alerts retain only PR locations without fetching pending review comments."""
    matching_commit = {
        "type": "commit",
        "details": {
            "commit_sha": "matching-sha",
            "path": "src/example.py",
            "start_line": 1,
            "start_column": 1,
        },
    }
    matching_review_comment = {
        "type": "pull_request_review_comment",
        "details": {
            "pull_request_review_comment_url": (
                f"{action.API_BASE_URL}/repos/owner/repo/pulls/comments/1"
            ),
        },
    }
    alert = {
        "number": 1,
        "secret_type": "test_secret",
        "secret_type_display_name": "Test secret",
        "state": "open",
        "resolution": None,
        "push_protection_bypassed": False,
        "push_protection_bypassed_by": None,
        "validity": None,
        "validity_checked_at": None,
        "html_url": "https://example.test/alert/1",
    }
    output_file = tmp_path / "output"
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/1/merge")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    monkeypatch.setattr(
        action,
        "get_pull_request",
        lambda *_: {
            "url": f"{action.API_BASE_URL}/repos/owner/repo/pulls/1",
            "html_url": "https://example.test/owner/repo/pull/1",
        },
    )
    monkeypatch.setattr(
        action, "get_commits_for_pr", lambda *_: [{"sha": "matching-sha"}]
    )
    monkeypatch.setattr(
        action, "get_secret_scanning_alerts_for_repo",
        lambda *args, **kwargs: [alert] if kwargs.get("secret_type") is None else [],
    )
    locations = [matching_commit, matching_review_comment, {
        "type": "commit",
        "details": {
            "commit_sha": "other-sha",
            "path": "src/other.py",
            "start_line": 1,
            "start_column": 1,
        },
    }]
    mock_locations = MagicMock(return_value=locations)
    monkeypatch.setattr(action, "get_locations_for_alert", mock_locations)
    review_comment = MagicMock()
    monkeypatch.setattr(action, "get_pull_request_review_comment", review_comment)
    monkeypatch.setattr(action, "get_dismissal_request_for_alert", lambda *_: None)

    with pytest.raises(SystemExit) as exc:
        action.main("token", False, False, True, None, None, True, False, True)

    assert exc.value.code == 0
    assert mock_locations.call_count == 1
    review_comment.assert_not_called()
    assert alert["locations"] == [matching_commit, matching_review_comment]
