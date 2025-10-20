"""Tests for search functionality."""

import pytest
from src.indexer import ModuleIndexer
from src.search import ModuleSearch


class TestModuleSearch:
    """Tests for module search functionality."""

    @pytest.fixture
    def mock_indexer(self):
        """Create a mock indexer with test data."""
        indexer = ModuleIndexer.__new__(ModuleIndexer)
        indexer.modules = {
            "custom": [
                {
                    "machine_name": "demo_email",
                    "name": "Demo Email",
                    "description": "HTML email notifications",
                    "services": [
                        {
                            "id": "demo_email.sender",
                            "keywords": ["email", "sender"],
                            "arguments": ["symfony_mailer"],
                        }
                    ],
                    "routes": [],
                    "classes": [],
                    "hooks": [],
                    "dependencies": ["symfony_mailer"],
                    "keywords": ["email", "html", "notifications"],
                },
                {
                    "machine_name": "demo_api",
                    "name": "Demo API",
                    "description": "REST API endpoints",
                    "services": [
                        {
                            "id": "demo_api.response",
                            "keywords": ["api", "response"],
                            "arguments": [],
                        }
                    ],
                    "routes": [
                        {
                            "name": "demo_api.endpoint",
                            "path": "/api/data",
                            "keywords": ["api", "data"],
                        }
                    ],
                    "classes": [],
                    "hooks": [],
                    "dependencies": [],
                    "keywords": ["api", "rest", "endpoints"],
                },
            ],
            "contrib": [
                {
                    "machine_name": "symfony_mailer",
                    "name": "Symfony Mailer",
                    "description": "Email service with HTML support",
                    "services": [
                        {
                            "id": "symfony_mailer.mailer",
                            "keywords": ["mailer", "email"],
                            "arguments": [],
                        }
                    ],
                    "routes": [],
                    "classes": [],
                    "hooks": [],
                    "dependencies": [],
                    "keywords": ["email", "mailer", "html", "smtp"],
                },
                {
                    "machine_name": "entity_print",
                    "name": "Entity Print",
                    "description": "PDF generation for entities",
                    "services": [
                        {
                            "id": "entity_print.builder",
                            "keywords": ["print", "pdf"],
                            "arguments": [],
                        }
                    ],
                    "routes": [],
                    "classes": [],
                    "hooks": [],
                    "dependencies": [],
                    "keywords": ["pdf", "print", "export"],
                },
            ],
            "total": 4,
        }
        return indexer

    def test_search_email_functionality(self, mock_indexer):
        """Test searching for email functionality."""
        search = ModuleSearch(mock_indexer)
        results = search.search_functionality("email")

        assert results["total_matches"] == 2
        assert len(results["custom_modules"]) == 1
        assert len(results["contrib_modules"]) == 1
        assert results["custom_modules"][0]["module"] == "demo_email"
        assert results["contrib_modules"][0]["module"] == "symfony_mailer"

    def test_search_html_email(self, mock_indexer):
        """Test searching with multiple terms."""
        search = ModuleSearch(mock_indexer)
        results = search.search_functionality("html email")

        # Should rank modules with both terms higher
        assert results["total_matches"] >= 2
        custom = results["custom_modules"][0]
        assert custom["module"] == "demo_email"
        # Demo email has both "html" and "email" in keywords
        assert custom["score"] > 5

    def test_search_api(self, mock_indexer):
        """Test searching for API functionality."""
        search = ModuleSearch(mock_indexer)
        results = search.search_functionality("api")

        assert len(results["custom_modules"]) == 1
        assert results["custom_modules"][0]["module"] == "demo_api"
        # Should find matching routes
        matches = results["custom_modules"][0]["matches"]
        assert "demo_api.endpoint" in matches["routes"]

    def test_search_no_results(self, mock_indexer):
        """Test search with no matches."""
        search = ModuleSearch(mock_indexer)
        results = search.search_functionality("nonexistent")

        assert results["total_matches"] == 0
        assert len(results["custom_modules"]) == 0
        assert len(results["contrib_modules"]) == 0

    def test_find_unused_contrib(self, mock_indexer):
        """Test finding unused contrib modules."""
        search = ModuleSearch(mock_indexer)
        unused = search.find_unused_contrib()

        # entity_print is not used by any custom module
        assert len(unused) == 1
        assert unused[0]["module"] == "entity_print"

    def test_check_redundancy_exists(self, mock_indexer):
        """Test redundancy check when functionality exists."""
        search = ModuleSearch(mock_indexer)
        result = search.check_redundancy("email")

        assert len(result["existing_contrib"]) > 0
        assert "symfony_mailer" in [m["module"] for m in result["existing_contrib"]]
        assert "Consider using" in result["recommendation"]

    def test_check_redundancy_not_exists(self, mock_indexer):
        """Test redundancy check when functionality doesn't exist."""
        search = ModuleSearch(mock_indexer)
        result = search.check_redundancy("blockchain")

        assert len(result["existing_contrib"]) == 0
        assert len(result["existing_custom"]) == 0
        assert "Building custom is reasonable" in result["recommendation"]

    def test_list_all_modules(self, mock_indexer):
        """Test listing all modules."""
        search = ModuleSearch(mock_indexer)
        result = search.list_all_modules()

        assert result["total"] == 4
        assert len(result["custom"]) == 2
        assert len(result["contrib"]) == 2

    def test_list_custom_only(self, mock_indexer):
        """Test listing custom modules only."""
        search = ModuleSearch(mock_indexer)
        result = search.list_all_modules(scope="custom")

        assert len(result["custom"]) == 2
        assert len(result["contrib"]) == 0

    def test_list_contrib_only(self, mock_indexer):
        """Test listing contrib modules only."""
        search = ModuleSearch(mock_indexer)
        result = search.list_all_modules(scope="contrib")

        assert len(result["custom"]) == 0
        assert len(result["contrib"]) == 2

    def test_describe_existing_module(self, mock_indexer):
        """Test describing an existing module."""
        search = ModuleSearch(mock_indexer)
        result = search.describe_module("demo_email")

        assert result["found"] is True
        assert result["module"]["machine_name"] == "demo_email"
        assert result["module"]["name"] == "Demo Email"

    def test_describe_nonexistent_module(self, mock_indexer):
        """Test describing a module that doesn't exist."""
        search = ModuleSearch(mock_indexer)
        result = search.describe_module("nonexistent_module")

        assert result["found"] is False
        assert "error" in result

    def test_search_scope_custom(self, mock_indexer):
        """Test searching custom modules only."""
        search = ModuleSearch(mock_indexer)
        results = search.search_functionality("email", scope="custom")

        assert len(results["custom_modules"]) == 1
        assert len(results["contrib_modules"]) == 0

    def test_search_scope_contrib(self, mock_indexer):
        """Test searching contrib modules only."""
        search = ModuleSearch(mock_indexer)
        results = search.search_functionality("email", scope="contrib")

        assert len(results["custom_modules"]) == 0
        assert len(results["contrib_modules"]) == 1


class TestScoring:
    """Tests for search scoring logic."""

    @pytest.fixture
    def mock_module(self):
        """Create a mock module for scoring tests."""
        return {
            "name": "Test Email Module",
            "description": "Provides email sending with HTML support",
            "keywords": ["email", "html", "notifications"],
            "services": [{"id": "test.email_sender", "keywords": ["email", "sender"]}],
        }

    def test_exact_name_match(self, mock_module):
        """Test scoring for exact name match."""
        search = ModuleSearch(ModuleIndexer.__new__(ModuleIndexer))
        score = search._score_module(mock_module, ["test email module"])

        # Exact name match should get high score
        assert score >= 10

    def test_name_contains_term(self, mock_module):
        """Test scoring when name contains search term."""
        search = ModuleSearch(ModuleIndexer.__new__(ModuleIndexer))
        score = search._score_module(mock_module, ["email"])

        # Name contains 'email' should get good score
        assert score >= 5

    def test_multiple_term_match(self, mock_module):
        """Test scoring with multiple matching terms."""
        search = ModuleSearch(ModuleIndexer.__new__(ModuleIndexer))
        score = search._score_module(mock_module, ["email", "html"])

        # Multiple matches should accumulate score
        assert score > 5

    def test_no_match(self, mock_module):
        """Test scoring with no matches."""
        search = ModuleSearch(ModuleIndexer.__new__(ModuleIndexer))
        score = search._score_module(mock_module, ["blockchain"])

        assert score == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
