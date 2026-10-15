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
    def test_http_404_raises(self, mock_get):
        """When GitHub returns 404, an EvaluationError with the status code is raised."""
        resp = _mock_response({"message": "Not Found"}, status_code=404)
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error")
        mock_get.return_value = resp

        with pytest.raises(action.EvaluationError) as exc:
            action.get_pull_request_comments("token", "owner", "repo", 1, None, None, True)
        assert exc.value.status_code == 404

    @patch("action.requests.get")
    def test_http_410_raises(self, mock_get):
        """When GitHub returns 410, an EvaluationError with the status code is raised."""
        resp = _mock_response({"message": "Gone"}, status_code=410)
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("410 Client Error")
        mock_get.return_value = resp

        with pytest.raises(action.EvaluationError) as exc:
            action.get_pull_request_comments("token", "owner", "repo", 1, None, None, True)
        assert exc.value.status_code == 410
        assert "deleted" in str(exc.value)


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


@pytest.fixture
def github_com_api(monkeypatch):
    """Pin API_BASE_URL to github.com (other tests reload the module with different hosts)."""
    monkeypatch.setattr(action, "API_BASE_URL", "https://api.github.com")


class TestWorkflowCommandEscaping:
    """Tests for workflow command escaping helpers."""

    def test_escape_command_data(self):
        assert action.escape_command_data("a%b\r\nc") == "a%25b%0D%0Ac"

    def test_escape_command_property(self):
        assert action.escape_command_property("src/a,b:c%\n.txt") == "src/a%2Cb%3Ac%25%0A.txt"

    def test_escape_command_property_non_string(self):
        assert action.escape_command_property(12) == "12"


class TestHandleEvaluationError:
    """Tests for the fail-closed error handler."""

    def test_fail_closed_exits(self, capsys):
        warnings = []
        with pytest.raises(SystemExit) as exc:
            action.handle_evaluation_error(action.EvaluationError("boom\nnext"), True, warnings)
        assert exc.value.code == 1
        assert "::error::boom%0Anext" in capsys.readouterr().out
        assert warnings == []

    def test_fail_open_warns_and_continues(self, capsys):
        warnings = []
        action.handle_evaluation_error(action.EvaluationError("boom"), False, warnings)
        assert warnings == ["boom"]
        assert "::warning::boom (fail-closed is disabled, continuing)" in capsys.readouterr().out


class TestEvaluationWarningMarkdown:
    """Tests for get_evaluation_warning_markdown."""

    def test_empty(self):
        assert action.get_evaluation_warning_markdown([]) == ""

    def test_lists_warnings_on_single_lines(self):
        markdown = action.get_evaluation_warning_markdown(["first\r\nerror", "second"])
        assert "> [!WARNING]" in markdown
        assert "> - first error\n" in markdown
        assert "> - second\n" in markdown


class TestCommitShasForPr:
    """Tests for get_commit_shas_for_pr and the compare fallback for PRs with more than 250 commits."""

    PR = {"commits": 300, "base": {"ref": "feature/base"}, "head": {"sha": "headsha"}}

    @patch("action.get_commits_for_compare")
    @patch("action.get_commits_for_pr")
    def test_uses_pr_commits_when_complete(self, mock_pr_commits, mock_compare):
        mock_pr_commits.return_value = [{"sha": "a"}, {"sha": "b"}]
        pr = {"commits": 2, "base": {"ref": "main"}, "head": {"sha": "headsha"}}

        result = action.get_commit_shas_for_pr("token", "owner", "repo", pr, 1, None, None, True)

        assert result == ["a", "b"]
        mock_compare.assert_not_called()

    @patch("action.get_commits_for_compare")
    @patch("action.get_commits_for_pr")
    def test_falls_back_to_compare_when_truncated(self, mock_pr_commits, mock_compare):
        mock_pr_commits.return_value = [{"sha": f"s{i}"} for i in range(250)]
        mock_compare.return_value = [{"sha": f"s{i}"} for i in range(300)]

        result = action.get_commit_shas_for_pr("token", "owner", "repo", self.PR, 1, None, None, True)

        assert len(result) == 300
        assert mock_compare.call_args[0][3:5] == ("feature/base", "headsha")

    @patch("action.requests.get")
    def test_compare_encodes_ref_and_paginates(self, mock_get, github_com_api):
        page1 = _mock_response({"commits": [{"sha": "a"}]})
        page1.headers = {"Link": '<https://api.github.com/x?page=2>; rel="next"'}
        page2 = _mock_response({"commits": [{"sha": "b"}]})
        page2.headers = {}
        mock_get.side_effect = [page1, page2]

        result = action.get_commits_for_compare("token", "owner", "repo", "feature/base", "headsha", None, None, True)

        assert [c["sha"] for c in result] == ["a", "b"]
        first_url = mock_get.call_args_list[0][0][0]
        assert first_url.startswith("https://api.github.com/repos/owner/repo/compare/feature%2Fbase...headsha?")
        assert "page=2" in mock_get.call_args_list[1][0][0]


class TestGetPullRequestReviewComment:
    """Tests for get_pull_request_review_comment error handling."""

    @patch("action.requests.get")
    def test_rejects_unexpected_host(self, mock_get, github_com_api):
        with pytest.raises(action.EvaluationError) as exc:
            action.get_pull_request_review_comment("token", "https://evil.example.com/repos/o/r/pulls/comments/1", None, None, True)
        assert exc.value.status_code is None
        mock_get.assert_not_called()

    @patch("action.requests.get")
    def test_404_raises_with_status(self, mock_get, github_com_api):
        resp = _mock_response({"message": "Not Found"}, status_code=404)
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error")
        mock_get.return_value = resp

        with pytest.raises(action.EvaluationError) as exc:
            action.get_pull_request_review_comment("token", "https://api.github.com/repos/o/r/pulls/comments/1", None, None, True)
        assert exc.value.status_code == 404


PR_API_URL = "https://api.github.com/repos/owner/repo/pulls/1"
REVIEW_COMMENT_URL = "https://api.github.com/repos/owner/repo/pulls/comments/99"


def _alert(number=1):
    return {
        "number": number,
        "secret_type": "github_personal_access_token",
        "secret_type_display_name": "GitHub Personal Access Token",
        "state": "open",
        "resolution": None,
        "push_protection_bypassed": False,
        "push_protection_bypassed_by": None,
        "html_url": f"https://github.com/owner/repo/security/secret-scanning/{number}",
    }


class TestMainFailClosed:
    """Tests for main() fail-closed behavior and review comment matching."""

    @pytest.fixture
    def env(self, tmp_path, monkeypatch, github_com_api):
        summary = tmp_path / "summary.md"
        output = tmp_path / "output.txt"
        monkeypatch.setenv("GITHUB_TOKEN", "token")
        monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
        monkeypatch.setenv("GITHUB_REF", "refs/pull/1/merge")
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        monkeypatch.setenv("GITHUB_OUTPUT", str(output))
        return summary, output

    @staticmethod
    def _run(fail_closed, fail_on_alert=False):
        with pytest.raises(SystemExit) as exc:
            action.main(None, fail_on_alert, False, True, None, None, True, False, False, fail_closed)
        return exc.value.code

    @staticmethod
    def _pr():
        return {"url": PR_API_URL, "html_url": "https://github.com/owner/repo/pull/1", "commits": 1}

    @patch("action.get_pull_request")
    def test_pr_error_fails_when_fail_closed(self, mock_pr, env):
        mock_pr.side_effect = action.EvaluationError("Error getting PR", 500)
        assert self._run(True) == 1

    @patch("action.get_pull_request")
    def test_pr_error_reports_incomplete_when_not_fail_closed(self, mock_pr, env):
        summary, output = env
        mock_pr.side_effect = action.EvaluationError("Error getting PR", 500)

        assert self._run(False) == 0
        assert "alerts=[]" in output.read_text()
        assert "could not be completed" in summary.read_text(encoding="utf-8")
        assert "Error getting PR" in summary.read_text(encoding="utf-8")

    @patch("action.get_dismissal_request_for_alert", return_value=None)
    @patch("action.get_locations_for_alert")
    @patch("action.get_secret_scanning_alerts_for_repo")
    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_generic_alerts_error_warns_when_not_fail_closed(self, mock_pr, _shas, mock_alerts, mock_locations, _dismissal, env):
        summary, _ = env
        mock_pr.return_value = self._pr()
        mock_alerts.side_effect = [[_alert()], action.EvaluationError("Error getting generic alerts", 500)]
        mock_locations.return_value = [{"type": "commit", "details": {"commit_sha": "abc", "path": "a.txt", "start_line": 1, "start_column": 1}}]

        assert self._run(False) == 0
        text = summary.read_text(encoding="utf-8")
        assert "Found [1] secret scanning alert " in text
        assert "Error getting generic alerts" in text

    @patch("action.get_secret_scanning_alerts_for_repo")
    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_generic_alerts_error_fails_when_fail_closed(self, mock_pr, _shas, mock_alerts, env):
        mock_pr.return_value = self._pr()
        mock_alerts.side_effect = [[_alert()], action.EvaluationError("Error getting generic alerts", 500)]
        assert self._run(True) == 1

    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_incomplete_commit_list_fails_when_fail_closed(self, mock_pr, _shas, env):
        pr = self._pr()
        pr["commits"] = 2
        mock_pr.return_value = pr
        assert self._run(True) == 1

    @patch("action.get_dismissal_request_for_alert", return_value=None)
    @patch("action.get_pull_request_review_comment")
    @patch("action.get_locations_for_alert")
    @patch("action.get_secret_scanning_alerts_for_repo")
    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_review_comment_on_other_pr_is_not_matched(self, mock_pr, _shas, mock_alerts, mock_locations, mock_review, _dismissal, env):
        _, output = env
        mock_pr.return_value = self._pr()
        mock_alerts.side_effect = [[_alert()], []]
        mock_locations.return_value = [{"type": "pull_request_review_comment", "details": {"pull_request_review_comment_url": REVIEW_COMMENT_URL}}]
        mock_review.return_value = {"pull_request_url": "https://api.github.com/repos/owner/repo/pulls/2"}

        assert self._run(True, fail_on_alert=True) == 0
        assert "alerts=[]" in output.read_text()

    @patch("action.get_dismissal_request_for_alert", return_value=None)
    @patch("action.get_pull_request_review_comment")
    @patch("action.get_locations_for_alert")
    @patch("action.get_secret_scanning_alerts_for_repo")
    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_review_comment_on_this_pr_is_matched(self, mock_pr, _shas, mock_alerts, mock_locations, mock_review, _dismissal, env):
        mock_pr.return_value = self._pr()
        mock_alerts.side_effect = [[_alert()], []]
        mock_locations.return_value = [{"type": "pull_request_review_comment", "details": {"pull_request_review_comment_url": REVIEW_COMMENT_URL}}]
        mock_review.return_value = {"pull_request_url": PR_API_URL}

        assert self._run(True, fail_on_alert=True) == 1

    @pytest.mark.parametrize("fail_closed,expected_exit", [(True, 1), (False, 0)])
    @patch("action.get_dismissal_request_for_alert", return_value=None)
    @patch("action.get_pull_request_review_comment")
    @patch("action.get_locations_for_alert")
    @patch("action.get_secret_scanning_alerts_for_repo")
    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_inaccessible_review_comment(self, mock_pr, _shas, mock_alerts, mock_locations, mock_review, _dismissal, fail_closed, expected_exit, env):
        """A 404 review comment (pending or deleted) counts as a match only when fail-closed is enabled."""
        mock_pr.return_value = self._pr()
        mock_alerts.side_effect = [[_alert()], []]
        mock_locations.return_value = [{"type": "pull_request_review_comment", "details": {"pull_request_review_comment_url": REVIEW_COMMENT_URL}}]
        mock_review.side_effect = action.EvaluationError("Not Found", 404)

        assert self._run(fail_closed, fail_on_alert=True) == expected_exit

    @patch("action.get_dismissal_request_for_alert", return_value=None)
    @patch("action.get_locations_for_alert")
    @patch("action.get_secret_scanning_alerts_for_repo")
    @patch("action.get_commit_shas_for_pr", return_value=["abc"])
    @patch("action.get_pull_request")
    def test_annotation_properties_are_escaped(self, mock_pr, _shas, mock_alerts, mock_locations, _dismissal, env, capsys):
        mock_pr.return_value = self._pr()
        mock_alerts.side_effect = [[_alert()], []]
        mock_locations.return_value = [{"type": "commit", "details": {"commit_sha": "abc", "path": "dir/a,b::c.txt", "start_line": 1, "start_column": 2}}]

        assert self._run(True) == 0
        assert "::warning file=dir/a%2Cb%3A%3Ac.txt,line=1,col=2::" in capsys.readouterr().out
