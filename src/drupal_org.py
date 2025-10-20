"""Integration with drupal.org API for module discovery."""

import logging
from typing import Dict, List, Optional
import urllib.request
import urllib.parse
import json
import time

logger = logging.getLogger(__name__)


class DrupalOrgAPI:
    """
    Client for drupal.org API to search and discover modules.

    API Documentation:
    https://www.drupal.org/drupalorg/docs/apis
    """

    BASE_URL = "https://www.drupal.org/api-d7"

    def __init__(self):
        """Initialize the API client."""
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour

    def search_modules(self, query: str, limit: int = 10) -> List[Dict]:
        """
        Search for modules on drupal.org.

        Args:
            query: Search query (e.g., "email", "PDF", "payment")
            limit: Maximum number of results

        Returns:
            List of module information dictionaries
        """
        # Check cache
        cache_key = f"search:{query}:{limit}"
        if cache_key in self.cache:
            cached_time, cached_data = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return cached_data

        try:
            # Try multiple search strategies for better results
            modules = []

            # Strategy 1: Search by machine name (exact match)
            logger.info(f"Searching drupal.org for: {query}")
            params_machine = {
                "type": "project_module",
                "field_project_machine_name": query.lower().replace(" ", "_"),
            }
            url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params_machine)}"

            try:
                with urllib.request.urlopen(url, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    for item in data.get("list", [])[:limit]:
                        module_info = self._parse_module(item)
                        if module_info and module_info not in modules:
                            modules.append(module_info)
            except Exception:
                pass

            # Strategy 2: Search by title (partial match)
            if len(modules) < limit:
                params_title = {
                    "type": "project_module",
                    "title": query,
                    "field_project_type": "full",
                }
                url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params_title)}"

                try:
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        for item in data.get("list", [])[:limit]:
                            module_info = self._parse_module(item)
                            if module_info and module_info["machine_name"] not in [
                                m["machine_name"] for m in modules
                            ]:
                                modules.append(module_info)
                except Exception:
                    pass

            # Strategy 3: Broader keyword search in body/description
            if len(modules) < limit // 2:
                # Split query into keywords and search
                keywords = query.lower().split()
                for keyword in keywords[:2]:  # Try first 2 keywords
                    if len(modules) >= limit:
                        break
                    params_keyword = {
                        "type": "project_module",
                        "title": keyword,
                    }
                    url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params_keyword)}"

                    try:
                        with urllib.request.urlopen(url, timeout=10) as response:
                            data = json.loads(response.read().decode())
                            for item in data.get("list", [])[:3]:  # Take fewer from keyword search
                                module_info = self._parse_module(item)
                                if module_info and module_info["machine_name"] not in [
                                    m["machine_name"] for m in modules
                                ]:
                                    modules.append(module_info)
                    except Exception:
                        pass

            logger.info(f"Found {len(modules)} modules on drupal.org")

            # Limit to requested number
            modules = modules[:limit]

            # Cache results
            self.cache[cache_key] = (time.time(), modules)

            return modules

        except Exception as e:
            logger.error(f"Error searching drupal.org: {e}")
            return []

    def get_module_details(self, project_name: str, include_issues: bool = False) -> Optional[Dict]:
        """
        Get detailed information about a specific module.

        Args:
            project_name: Machine name of the project (e.g., "webform")
            include_issues: Whether to include recent issues for qualitative analysis

        Returns:
            Detailed module information
        """
        cache_key = f"details:{project_name}:issues={include_issues}"
        if cache_key in self.cache:
            cached_time, cached_data = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return cached_data

        try:
            # Search for specific project
            params = {
                "type": "project_module",
                "field_project_machine_name": project_name,
            }

            url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params)}"

            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())

            if data.get("list"):
                details = self._parse_module(data["list"][0], detailed=True)

                # Optionally fetch issues for qualitative analysis
                if include_issues and details.get("nid"):
                    issues = self._fetch_module_issues(details["nid"])
                    details["recent_issues"] = issues

                self.cache[cache_key] = (time.time(), details)
                return details

            return None

        except Exception as e:
            logger.error(f"Error fetching module details: {e}")
            return None

    def get_popular_modules(self, category: Optional[str] = None, limit: int = 20) -> List[Dict]:
        """
        Get popular/recommended modules.

        Args:
            category: Optional category filter
            limit: Number of results

        Returns:
            List of popular modules
        """
        cache_key = f"popular:{category}:{limit}"
        if cache_key in self.cache:
            cached_time, cached_data = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return cached_data

        try:
            params = {
                "type": "project_module",
                "sort": "usage",
                "direction": "DESC",
            }

            if category:
                params["taxonomy_vocabulary_44"] = category

            url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params)}"

            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())

            modules = []
            for item in data.get("list", [])[:limit]:
                module_info = self._parse_module(item)
                if module_info:
                    modules.append(module_info)

            self.cache[cache_key] = (time.time(), modules)
            return modules

        except Exception as e:
            logger.error(f"Error fetching popular modules: {e}")
            return []

    def _parse_module(self, node_data: Dict, detailed: bool = False) -> Optional[Dict]:
        """
        Parse module data from drupal.org API response.

        Args:
            node_data: Raw node data from API
            detailed: Whether to include detailed information

        Returns:
            Parsed module information
        """
        try:
            # Extract description - body can be a dict or a list (sometimes empty)
            body = node_data.get("body", {})
            description = ""
            if isinstance(body, dict):
                description = self._clean_html(body.get("value", ""))
            elif isinstance(body, list) and body:
                # If it's a list with items, take the first
                description = self._clean_html(body[0].get("value", ""))

            # Calculate total usage across all versions
            usage_data = node_data.get("project_usage", {})
            total_usage = sum(
                int(v)
                for k, v in usage_data.items()
                if k != "total" and isinstance(v, (int, str)) and str(v).isdigit()
            )

            module = {
                "machine_name": node_data.get("field_project_machine_name", ""),
                "name": node_data.get("title", ""),
                "description": description,
                "url": node_data.get("url", ""),
                "project_usage": total_usage,
                "maintenance_status": node_data.get("field_maintenance_status", ""),
                "development_status": node_data.get("field_development_status", ""),
            }

            if detailed:
                # Extract timestamps
                import datetime

                created_ts = int(node_data.get("created", 0))
                changed_ts = int(node_data.get("changed", 0))

                # Get star count
                stars = node_data.get("flag_project_star_user", {})
                star_count = len(stars) if isinstance(stars, dict) else 0

                # Get supporting orgs
                orgs = node_data.get("field_supporting_organizations", [])
                org_count = len(orgs) if isinstance(orgs, list) else 0

                # Get documentation links
                docs = node_data.get("field_project_documentation", [])
                doc_links = []
                if isinstance(docs, list):
                    for doc in docs:
                        if isinstance(doc, dict) and doc.get("url"):
                            doc_links.append(doc["url"])

                # Extract Drupal version compatibility
                # First try to get from page (most accurate)
                drupal_versions = []
                project_url = node_data.get("url", "")
                if project_url:
                    compat_str = self._fetch_page_compatibility(project_url)
                    if compat_str:
                        drupal_versions = self._parse_compatibility_string(compat_str)
                        logger.info(
                            f"Got compatibility from page: {compat_str} → {drupal_versions}"
                        )

                # Fallback to inferring from usage data
                if not drupal_versions:
                    drupal_versions = self._extract_drupal_versions(usage_data)
                    logger.info(f"Inferred compatibility from usage data: {drupal_versions}")

                module.update(
                    {
                        "categories": self._extract_categories(node_data),
                        "recommended_releases": self._extract_releases(node_data),
                        "security_coverage": node_data.get("field_security_advisory_coverage", ""),
                        "created_date": (
                            datetime.datetime.fromtimestamp(created_ts).strftime("%Y-%m-%d")
                            if created_ts
                            else ""
                        ),
                        "last_updated": (
                            datetime.datetime.fromtimestamp(changed_ts).strftime("%Y-%m-%d")
                            if changed_ts
                            else ""
                        ),
                        "star_count": star_count,
                        "has_issue_queue": node_data.get("field_project_has_issue_queue", False),
                        "usage_by_version": usage_data,
                        "supporting_orgs_count": org_count,
                        "documentation_links": doc_links,
                        "nid": node_data.get("nid", ""),
                        "drupal_versions": drupal_versions,
                    }
                )

            return module

        except Exception as e:
            logger.warning(f"Error parsing module data: {e}")
            return None

    def _clean_html(self, html_text: str) -> str:
        """Remove HTML tags from text."""
        import re

        # Simple HTML tag removal
        clean = re.sub(r"<[^>]+>", "", html_text)
        # Clean up whitespace
        clean = " ".join(clean.split())
        # Limit length
        return clean[:500] if len(clean) > 500 else clean

    def _extract_categories(self, node_data: Dict) -> List[str]:
        """Extract module categories."""
        categories = []
        # Drupal.org uses taxonomy_vocabulary_44 for categories
        # Can be a list of category objects or a single dict reference
        cat_data = node_data.get("taxonomy_vocabulary_44", [])
        if isinstance(cat_data, list):
            categories = [c.get("name", "") for c in cat_data if isinstance(c, dict)]
        elif isinstance(cat_data, dict):
            # Single category reference - would need additional API call to get name
            # For now, just note that categories exist but don't fetch
            if cat_data.get("id"):
                categories = [f"category_{cat_data['id']}"]
        return categories

    def _extract_releases(self, node_data: Dict) -> List[str]:
        """Extract recommended release versions."""
        releases = []
        # This would need additional API calls to get release info
        # For now, just return empty
        return releases

    def _fetch_page_compatibility(self, project_url: str) -> Optional[str]:
        """
        Fetch the actual compatibility from the project page.

        This scrapes the "Works with Drupal:" field which has the actual
        core_version_requirement from composer.json.

        Args:
            project_url: URL to the project page

        Returns:
            Compatibility string (e.g., "^9.5 || ^10 || ^11") or None
        """
        import re

        try:
            with urllib.request.urlopen(project_url, timeout=10) as response:
                html = response.read().decode("utf-8")

                # Look for 'Works with Drupal:'
                match = re.search(r"Works with Drupal:\s*([^\<\n]+)", html)
                if match:
                    return match.group(1).strip()

        except Exception as e:
            logger.debug(f"Could not fetch page compatibility: {e}")

        return None

    def _parse_compatibility_string(self, compat_str: str) -> List[str]:
        """
        Parse a composer compatibility string into Drupal versions.

        Args:
            compat_str: String like "^9.5 || ^10 || ^11"

        Returns:
            List of Drupal versions (e.g., ["Drupal 9", "Drupal 10", "Drupal 11"])
        """
        import re

        versions = set()

        # Find all version numbers: ^9.5, ^10, ^11, etc.
        for match in re.finditer(r"\^?(\d+)", compat_str):
            version = int(match.group(1))
            if version >= 6 and version <= 99:  # Reasonable Drupal versions
                versions.add(f"Drupal {version}")

        # Sort by version number
        sorted_versions = sorted(versions, key=lambda x: int(re.search(r"\d+", x).group()))
        return sorted_versions

    def _extract_drupal_versions(self, usage_by_version: Dict) -> List[str]:
        """
        Extract supported Drupal versions from version strings.

        Args:
            usage_by_version: Dict of version strings to usage counts

        Returns:
            List of Drupal versions (e.g., ["Drupal 7", "Drupal 9", "Drupal 10"])
        """
        import re

        drupal_versions = set()

        for version_string in usage_by_version.keys():
            # Old format: 7.x-1.0, 8.x-3.x, etc.
            # This format is explicit and future-proof - any numeric version works
            match = re.match(r"^(\d+)\.x-", version_string)
            if match:
                core_version = int(match.group(1))
                # Accept any reasonable Drupal version (6+)
                if core_version >= 6 and core_version <= 99:
                    drupal_versions.add(f"Drupal {core_version}")
                continue

            # New semantic versioning format: 4.0.x, 5.1.x
            # Mapping based on when Drupal adopted semantic versioning:
            # 1.x = D8, 2.x-3.x = D9, 4.x-6.x = D10, 7.x+ = D11+
            # Note: This mapping may need updates when Drupal 11+ releases
            match = re.match(r"^(\d+)\.", version_string)
            if match:
                major = int(match.group(1))
                if major == 1:
                    drupal_versions.add("Drupal 8")
                elif major in [2, 3]:
                    drupal_versions.add("Drupal 9")
                elif major in [4, 5, 6]:
                    drupal_versions.add("Drupal 10")
                elif major >= 7:
                    # Future-proof: map to "Drupal 11+" for unknown versions
                    drupal_versions.add("Drupal 11+")

        # Sort by version number
        sorted_versions = sorted(drupal_versions, key=lambda x: int(re.search(r"\d+", x).group()))
        return sorted_versions

    def _fetch_module_issues(self, nid: str, limit: int = 15) -> List[Dict]:
        """
        Fetch recent issues for a module from drupal.org issue queue.

        This provides qualitative data for analysis of:
        - Maintainer responsiveness
        - Common problems (Symfony issues, migration patterns, etc.)
        - Community activity
        - Technical debt indicators

        Args:
            nid: Node ID of the project
            limit: Number of recent issues to fetch (default: 15)

        Returns:
            List of issues with title, status, priority, category, url
        """
        try:
            # Fetch recent issues sorted by last changed
            params = {
                "type": "project_issue",
                "field_project": nid,
                "sort": "changed",
                "direction": "DESC",
                "limit": str(limit),
            }

            url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params)}"
            logger.info(f"Fetching issues from: {url}")

            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())

            issues = []
            for item in data.get("list", []):
                # Extract relevant fields for qualitative analysis
                issue = {
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "status": item.get("field_issue_status", "Unknown"),
                    "priority": item.get("field_issue_priority", "Unknown"),
                    "category": item.get("field_issue_category", "Unknown"),
                    "created": item.get("created", 0),
                    "changed": item.get("changed", 0),
                    "version": item.get("field_issue_version", ""),  # For version filtering
                }
                issues.append(issue)

            logger.info(f"Fetched {len(issues)} issues for module (nid: {nid})")
            return issues

        except Exception as e:
            logger.warning(f"Could not fetch issues: {e}")
            return []

    def search_issues(
        self,
        project_name: str,
        problem_description: str,
        limit: int = 10,
        drupal_version: Optional[str] = None,
    ) -> List[Dict]:
        """
        Search a module's issue queue for problems similar to yours.

        Perfect for troubleshooting - finds existing issues that match your problem
        so you can find solutions, patches, or workarounds.

        Args:
            project_name: Machine name of the module (e.g., "samlauth")
            problem_description: Description of your problem (e.g., "Azure AD authentication error")
            limit: Maximum number of matching issues to return (default: 10)
            drupal_version: Optional Drupal version to filter issues (e.g., "10", "11")
                          Filters out issues for incompatible versions

        Returns:
            List of matching issues sorted by relevance
        """
        # First, get the module's nid
        cache_key = f"module_nid:{project_name}"
        nid = None

        if cache_key in self.cache:
            cached_time, nid = self.cache[cache_key]
            if time.time() - cached_time > self.cache_ttl:
                nid = None

        if not nid:
            try:
                params = {
                    "type": "project_module",
                    "field_project_machine_name": project_name,
                }
                url = f"{self.BASE_URL}/node.json?{urllib.parse.urlencode(params)}"

                with urllib.request.urlopen(url, timeout=10) as response:
                    data = json.loads(response.read().decode())

                if data.get("list"):
                    nid = data["list"][0].get("nid", "")
                    self.cache[cache_key] = (time.time(), nid)
                else:
                    logger.warning(f"Module '{project_name}' not found")
                    return []

            except Exception as e:
                logger.error(f"Error finding module: {e}")
                return []

        # Fetch more issues for better search coverage (50-100 recent issues)
        issues = self._fetch_module_issues(nid, limit=100)

        if not issues:
            return []

        # Extract keywords from problem description
        import re

        # Remove common words and split into keywords
        stop_words = {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
            "from",
            "is",
            "are",
            "was",
            "were",
            "been",
            "be",
            "have",
            "has",
            "had",
            "do",
            "does",
            "did",
            "will",
            "would",
            "should",
            "could",
            "may",
            "might",
            "can",
            "i",
            "my",
            "me",
            "getting",
            "get",
            "got",
        }

        keywords = [
            word.lower()
            for word in re.findall(r"\b\w+\b", problem_description.lower())
            if word.lower() not in stop_words and len(word) > 2
        ]

        logger.info(f"Searching for keywords: {keywords}")

        # Score each issue based on keyword matches
        scored_issues = []
        for issue in issues:
            title_lower = issue["title"].lower()

            # Version filtering (if Drupal version provided)
            if drupal_version:
                issue_version = issue.get("version", "")
                if issue_version and not self._is_version_compatible(issue_version, drupal_version):
                    # Skip issues for incompatible Drupal versions
                    logger.debug(
                        f"Skipping issue '{issue['title']}' - incompatible version {issue_version} for Drupal {drupal_version}"
                    )
                    continue

            # Count keyword matches
            matches = sum(1 for keyword in keywords if keyword in title_lower)

            # Bonus points for exact phrase matches
            if problem_description.lower() in title_lower:
                matches += 10

            # Only include issues with at least one match
            if matches > 0:
                issue["relevance_score"] = matches
                scored_issues.append(issue)

        # Sort by relevance score (descending)
        scored_issues.sort(key=lambda x: x["relevance_score"], reverse=True)

        # Return top matches
        return scored_issues[:limit]

    def _is_version_compatible(self, issue_version: str, drupal_version: str) -> bool:
        """
        Check if an issue version is compatible with the given Drupal version.

        Args:
            issue_version: Module version from issue (e.g., "8.x-1.x-dev", "2.0.x-dev")
            drupal_version: Drupal major version (e.g., "10", "11")

        Returns:
            True if the issue might be relevant for this Drupal version
        """
        import re

        # Extract major version from issue_version
        # Old format: "7.x-1.0" -> Drupal 7
        # New format: "8.x-1.0" -> Drupal 8/9/10/11 (all compatible)
        # Semantic: "2.0.x-dev" -> Check module compatibility separately

        match = re.match(r"^(\d+)\.x-", issue_version)
        if match:
            issue_drupal_version = match.group(1)

            # Drupal 7 and earlier are separate
            if issue_drupal_version in ["5", "6", "7"]:
                return issue_drupal_version == str(drupal_version)

            # Drupal 8/9/10/11 share the same API
            # Issues for "8.x-" module versions may apply to D8/9/10/11
            if issue_drupal_version == "8":
                return str(drupal_version) in ["8", "9", "10", "11"]

            # Exact match
            return issue_drupal_version == str(drupal_version)

        # Semantic versioning format (e.g., "2.0.x-dev")
        # These are generally for Drupal 8/9/10/11
        # Be conservative - include these unless user is on D7 or earlier
        if str(drupal_version) not in ["5", "6", "7"]:
            return True

        # If we can't determine, include it (be permissive)
        return True


def format_drupal_org_results(modules: List[Dict], query: str) -> str:
    """
    Format drupal.org search results for display.

    Args:
        modules: List of module dictionaries from drupal.org
        query: Original search query

    Returns:
        Formatted string for MCP response
    """
    if not modules:
        return f"❌ No modules found on drupal.org for '{query}'"

    output = [
        f"🔍 Found {len(modules)} modules on drupal.org for '{query}':\n",
    ]

    for i, module in enumerate(modules, 1):
        output.append(f"{i}. **{module['name']}** ({module['machine_name']})")
        output.append(f"   {module['description'][:200]}...")

        # Add stats
        usage = module.get("project_usage", 0)
        if usage > 0:
            usage_str = f"{usage:,}" if usage < 1000000 else f"{usage/1000000:.1f}M"
            output.append(f"   📊 Installations: {usage_str}")

        # Add status
        maint = module.get("maintenance_status", "")
        dev = module.get("development_status", "")
        if maint or dev:
            status_parts = []
            if maint:
                status_parts.append(f"Maintenance: {maint}")
            if dev:
                status_parts.append(f"Development: {dev}")
            output.append(f"   ⚙️  {' | '.join(status_parts)}")

        output.append(f"   🔗 {module['url']}")
        output.append("")

    output.append("\n💡 **Recommendations:**")
    output.append("   • Check maintenance status before installing")
    output.append("   • Prefer actively maintained modules")
    output.append("   • Review documentation and issue queue")
    output.append("   • Consider installation count as popularity indicator")

    return "\n".join(output)


def generate_recommendations(
    query: str, local_results: List[Dict], drupal_org_results: List[Dict]
) -> str:
    """
    Generate recommendations combining local and drupal.org results.

    Args:
        query: Original search query
        local_results: Results from local Drupal site
        drupal_org_results: Results from drupal.org

    Returns:
        Formatted recommendations
    """
    output = [
        f"📋 **Recommendations for '{query}':**\n",
    ]

    # Analyze local results
    has_local_custom = any(r.get("source_type") == "custom" for r in local_results)
    has_local_contrib = any(r.get("source_type") == "contrib" for r in local_results)

    if has_local_custom:
        output.append("✅ **You already have custom implementation:**")
        output.append("   • Review existing custom code first")
        output.append("   • Consider if it can be extended vs. installing new module")
        output.append("")

    if has_local_contrib:
        output.append("✅ **You have contrib modules installed:**")
        output.append("   • Check if they're being used effectively")
        output.append("   • May already provide the functionality you need")
        output.append("")

    if not local_results:
        output.append("❌ **No local modules found**\n")

        if drupal_org_results:
            output.append("💡 **Suggested Actions:**")
            output.append("\n**Option 1: Install Popular Module**")

            # Get top 3 by usage
            top_modules = sorted(
                drupal_org_results, key=lambda x: x.get("project_usage", 0), reverse=True
            )[:3]

            for i, mod in enumerate(top_modules, 1):
                output.append(f"\n   {i}. **{mod['name']}**")
                output.append(f"      • Machine name: `{mod['machine_name']}`")
                output.append(f"      • Installations: {mod.get('project_usage', 0):,}")
                output.append(f"      • Status: {mod.get('maintenance_status', 'Unknown')}")
                output.append(f"      • {mod['url']}")

            output.append("\n**Option 2: Build Custom**")
            output.append("   • If requirements are very specific")
            output.append("   • If no suitable contrib module exists")
            output.append("   • Consider maintenance burden")

            output.append("\n**Recommended Next Steps:**")
            output.append("   1. Review top module documentation")
            output.append("   2. Check module issue queue for known problems")
            output.append("   3. Verify compatibility with your Drupal version")
            output.append("   4. Install in dev environment first")
    else:
        output.append("✅ **You have local modules. Consider:**")
        output.append("   • Using existing modules vs. installing new ones")
        output.append("   • Comparing features with drupal.org options")
        output.append("   • Checking if updates/alternatives are available")

    return "\n".join(output)
