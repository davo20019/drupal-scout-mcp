"""Basic tests to verify package structure."""


def test_imports():
    """Test that core modules can be imported."""
    from src import indexer
    from src import search
    from src import drupal_org
    from src import prioritizer

    assert indexer is not None
    assert search is not None
    assert drupal_org is not None
    assert prioritizer is not None


def test_drupal_org_api():
    """Test DrupalOrgAPI can be instantiated."""
    from src.drupal_org import DrupalOrgAPI

    api = DrupalOrgAPI()
    assert api is not None
    assert hasattr(api, "search_modules")
    assert hasattr(api, "get_module_details")
    assert hasattr(api, "search_issues")


def test_version():
    """Test that version is defined."""
    # Version should be in pyproject.toml
    from pathlib import Path

    # For Python 3.11+, tomllib is built-in
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"

    if pyproject_path.exists():
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
            version = data.get("project", {}).get("version")
            assert version is not None
            assert version == "1.0.1"
