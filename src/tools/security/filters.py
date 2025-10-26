"""
False positive filtering for Drupal security scanning.

Drupal-aware filtering to reduce false positives from pattern matching:
- SQL Injection: Recognizes EntityQuery, TempStore, Config, State, Cache APIs
- Access Control: Distinguishes entity operations from config/cache operations
- Command Injection: Detects escapeshellarg/escapeshellcmd usage
- Path Traversal: Recognizes stream wrappers (public://, private://)
- Hardcoded Secrets: Filters examples, test files, documentation
- XSS: Understands Form API render arrays, preprocess hooks

Each filter checks code context to determine if a pattern match is a
real vulnerability or a false positive from safe Drupal APIs.
"""


def _is_false_positive(line: str, pattern_name: str, category: str) -> bool:
    """
    Check if a finding is likely a false positive based on context.

    Args:
        line: The line of code that matched
        pattern_name: Name of the pattern that matched
        category: Category of the finding

    Returns:
        True if this is likely a false positive
    """
    line_lower = line.lower()

    # SQL injection false positives
    if category == "sql_injection":
        # Drupal's safe APIs that look like SQL
        safe_drupal_apis = [
            "->condition(",  # EntityQuery conditions are safe
            "->fields(",  # EntityQuery field selection
            "->range(",  # EntityQuery range
            "->sort(",  # EntityQuery sorting
            "gettempstore(",  # Temp storage is not SQL
            "getprivatetempstore(",  # Private temp storage
            "getsharedtempstore(",  # Shared temp storage
            "->get(",  # KeyValue store get
            "->set(",  # KeyValue store set
            "->delete(",  # KeyValue store delete (not SQL DELETE)
            "cache_get(",  # Cache API
            "cache_set(",  # Cache API
            "state_get(",  # State API
            "config_get(",  # Config API
        ]

        for safe_api in safe_drupal_apis:
            if safe_api in line_lower:
                return True

        # Check if SQL keywords are in comments or strings only (not actual SQL)
        if pattern_name == "sql_concat":
            # If the line contains SQL keywords but no actual query construction
            # Look for non-SQL contexts like variable names containing "select"
            if not any(
                keyword in line_lower for keyword in ["db_query", "->query(", "mysqli", "pdo"]
            ):
                # Likely a false positive if no database functions present
                return True

    # Access control false positives
    if category == "access_control":
        # ->save() and ->delete() on non-entity objects
        if pattern_name == "missing_permission_check":
            # Config and cache operations are not entity operations
            if any(
                keyword in line_lower
                for keyword in ["config->save(", "cache->delete(", "state->delete("]
            ):
                return True

    # Command injection false positives
    if category == "command_injection":
        # escapeshellarg or escapeshellcmd present means it's likely handled
        if "escapeshellarg" in line_lower or "escapeshellcmd" in line_lower:
            return True
        # Drush commands with hardcoded strings (no variables) are safe
        if pattern_name == "drush_shell_exec" and "$" not in line:
            return True

    # Path traversal false positives
    if category == "path_traversal":
        # realpath() or drupal_realpath() present means validation is happening
        if "realpath(" in line_lower or "drupal_realpath(" in line_lower:
            return True
        # file_create_url is safe (generates URLs, not file access)
        if "file_create_url" in line_lower:
            return True
        # Stream wrappers are generally safe (public://, private://)
        if "public://" in line or "private://" in line or "temporary://" in line:
            return True

    # Hardcoded secrets false positives
    if category == "hardcoded_secrets":
        # Example values, placeholders, or comments
        if any(
            word in line_lower
            for word in ["example", "placeholder", "your_api_key", "your_password", "xxx"]
        ):
            return True
        # Test files
        if "/test" in line_lower or "test.php" in line_lower or "phpunit" in line_lower:
            return True
        # Documentation/comments
        if line.strip().startswith(("//", "#", "*", "/*")):
            return True

    # XSS false positives
    if category == "xss":
        # drupal_set_message with t() is safe
        if "drupal_set_message" in line_lower and "t(" in line_lower:
            return True

        # Form returns are safe (Form API handles sanitization)
        if pattern_name == "unsafe_render_string":
            # return $form; is safe - Form API sanitizes
            if "return $form" in line_lower:
                return True

            # return $build; is safe - render arrays are sanitized
            if "return $build" in line_lower:
                return True

            # return $element; is safe in form context
            if "return $element" in line_lower:
                return True

            # return $requirements; is safe (system requirements)
            if "return $requirements" in line_lower:
                return True

            # return $items; is safe in field formatter context
            if "return $items" in line_lower:
                return True

            # return $variables; is safe in preprocess hooks
            if "return $variables" in line_lower:
                return True

            # return $output; when it's a render array variable
            if "return $output" in line_lower:
                return True

            # return $page; is safe (page render array)
            if "return $page" in line_lower:
                return True

            # return $entity; in load/create contexts is not XSS
            if "return $entity" in line_lower:
                return True

    return False
