"""Tests for pagination in action.py"""

import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path so we can import action module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import action


def _make_comments(n):
    """Create a list of n fake comment dicts."""
    return [{"id": i, "body": f"comment {i}"} for i in range(n)]


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


class TestUpdatePullRequestCommentPagination:
    """Tests for update_pull_request_comment pagination during comment fetching."""

    @patch("action.requests.post")
    @patch("action.requests.get")
    def test_pagination_advances_pages(self, mock_get, mock_post):
        """Verify pagination URL is rebuilt with incremented page number."""
        page1 = _make_comments(100)
        page2 = _make_comments(30)
        mock_get.side_effect = [_mock_response(page1), _mock_response(page2)]

        # Mock the POST for creating a new comment
        mock_post.return_value = _mock_response(
            {"html_url": "https://github.com/owner/repo/pull/1#issuecomment-1"}
        )

        action.update_pull_request_comment(
            "token", "owner", "repo", 1, "summary", None, None, True
        )

        assert mock_get.call_count == 2
        second_call_url = mock_get.call_args_list[1][0][0]
        assert "page=2" in second_call_url

    @patch("action.requests.patch")
    @patch("action.requests.get")
    def test_finds_existing_comment_across_pages(self, mock_get, mock_patch):
        """When the watermark comment is on page 2, it should be found."""
        watermark = "<!-- secret-scanning-review-pr-comment-watermark -->"
        page1 = _make_comments(100)
        page2 = [{"id": 200, "body": f"{watermark}\nold summary", "url": "https://api.github.com/repos/owner/repo/issues/comments/200"}]
        mock_get.side_effect = [_mock_response(page1), _mock_response(page2)]

        mock_patch.return_value = _mock_response(
            {"html_url": "https://github.com/owner/repo/pull/1#issuecomment-200"}
        )

        action.update_pull_request_comment(
            "token", "owner", "repo", 1, "new summary", None, None, True
        )

        # Should have used PATCH (existing comment found), not POST
        assert mock_patch.call_count == 1
