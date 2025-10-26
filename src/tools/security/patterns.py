"""
Vulnerability detection patterns for Drupal security scanning.

Pattern-based detection for:
- XSS (Cross-Site Scripting)
- SQL Injection
- Command Injection
- Path Traversal
- Hardcoded Secrets
- Access Control Issues
- CSRF Protection
- Deprecated/Unsafe APIs

Each pattern includes:
- pattern: Regular expression to match vulnerable code
- severity: "high", "medium", or "low"
- description: What the vulnerability is
- recommendation: How to fix it
"""

XSS_PATTERNS = {
    # Unescaped print/echo statements
    "unescaped_print": {
        "pattern": r"\b(print|echo)\s+\$",
        "severity": "high",
        "description": "Direct output of variable without escaping",
        "recommendation": "Use \\Drupal\\Component\\Utility\\Html::escape() or render arrays with #markup",
    },
    # Direct variable in render array key (potential XSS)
    "unsafe_render_string": {
        "pattern": r"['\"](#[\w_]+)['\"]:\s*\$[\w_]+(?!\s*[,\]])",
        "severity": "medium",
        "description": "Variable assigned to render array without explicit sanitization",
        "recommendation": "Use #markup with Xss::filterAdmin() or #plain_text for user content",
    },
    # drupal_set_message with variable (Drupal 7/8 style)
    "drupal_set_message_var": {
        "pattern": r"drupal_set_message\(\s*\$",
        "severity": "medium",
        "description": "drupal_set_message() with variable (potential XSS)",
        "recommendation": "Use t() or Markup::create() to sanitize",
    },
    # Direct $_GET/$_POST usage
    "direct_superglobal": {
        "pattern": r"\b(echo|print|return)\s+.*\$_(GET|POST|REQUEST|COOKIE)",
        "severity": "high",
        "description": "Direct output of user input from superglobals",
        "recommendation": "Use \\Drupal\\Component\\Utility\\Html::escape() or Xss::filter()",
    },
    # innerHTML/outerHTML in JavaScript
    "javascript_innerhtml": {
        "pattern": r"\.innerHTML\s*=|\.outerHTML\s*=",
        "severity": "medium",
        "description": "Direct DOM manipulation (XSS vector in JavaScript)",
        "recommendation": "Use textContent or sanitize with DOMPurify",
    },
}


# ============================================================================
# SQL INJECTION PATTERNS
# ============================================================================

SQL_INJECTION_PATTERNS = {
    # db_query with concatenation (Drupal 7)
    "db_query_concat": {
        "pattern": r"db_query\([^)]*\.\s*\$|db_query\([^)]*%[sd].*,\s*\$_",
        "severity": "high",
        "description": "db_query() with string concatenation or direct superglobals",
        "recommendation": "Use placeholders: db_query('SELECT * FROM {table} WHERE id = :id', [':id' => $id])",
    },
    # Direct SQL with concatenation in string context
    "sql_concat": {
        "pattern": r"['\"](\s*SELECT\s+|\s*INSERT\s+INTO\s+|\s*UPDATE\s+|\s*DELETE\s+FROM\s+).*['\"]?\s*\.\s*\$",
        "severity": "high",
        "description": "SQL query string with variable concatenation",
        "recommendation": "Use Drupal's Database API with placeholders",
    },
    # mysqli/PDO without prepared statements
    "mysqli_query_concat": {
        "pattern": r"(mysqli_query|mysql_query|->query)\([^)]*['\"].*\.\s*\$",
        "severity": "high",
        "description": "Direct database query with concatenation",
        "recommendation": "Use prepared statements or Drupal's Database API",
    },
    # EntityQuery with user input without validation
    "entity_query_user_input": {
        "pattern": r"->condition\([^)]*\$_(GET|POST|REQUEST)",
        "severity": "medium",
        "description": "EntityQuery condition with direct user input",
        "recommendation": "Validate and sanitize user input before EntityQuery",
    },
}


# ============================================================================
# ACCESS CONTROL PATTERNS
# ============================================================================

ACCESS_CONTROL_PATTERNS = {
    # Route without _permission or _access requirement
    "route_no_access": {
        "pattern": r"^[\s]*\w+\.[\w\.]+:$",  # Route definition
        "check_yaml": True,
        "severity": "high",
        "description": "Route definition may be missing access control",
        "recommendation": "Add _permission, _role, or _custom_access requirement",
    },
    # Form without access check
    "form_no_access": {
        "pattern": r"class\s+\w+\s+extends\s+FormBase(?!.*access)",
        "severity": "medium",
        "description": "Form class may be missing access control",
        "recommendation": "Implement access() method or use _permission in routing",
    },
    # Missing permission check before sensitive operation
    "missing_permission_check": {
        "pattern": r"(->save\(\)|->delete\(\)|->update\(\))(?!.*->access\()",
        "severity": "medium",
        "description": "Entity modification without visible access check",
        "recommendation": "Use ->access('update'/'delete') before operations",
    },
    # User load without access check
    "user_load_no_check": {
        "pattern": r"User::load\(|user_load\(",
        "severity": "low",
        "description": "User entity loaded without access verification",
        "recommendation": "Use ->access('view') after loading sensitive user data",
    },
}


# ============================================================================
# CSRF PROTECTION PATTERNS
# ============================================================================

CSRF_PATTERNS = {
    # Custom route POST handler without CSRF (outside Form API)
    "custom_post_no_csrf": {
        "pattern": r"Request::(create|createFromGlobals)|\\$request->request->get\(.*\$_POST",
        "severity": "medium",
        "description": "Custom POST handler detected - verify CSRF token validation is present",
        "recommendation": "Use Form API (auto CSRF) or validate with \\Drupal::csrfToken()->validate()",
    },
    # State-changing operation that might be in GET
    "potential_get_state_change": {
        "pattern": r"(->save\(\)|->delete\(\)|->update\(\)|->create\(\))",
        "severity": "low",
        "description": "State-changing operation detected - verify route uses POST/DELETE with CSRF",
        "recommendation": "Ensure operation is in POST route with Form API or CSRF token",
    },
}


# ============================================================================
# COMMAND INJECTION PATTERNS
# ============================================================================

COMMAND_INJECTION_PATTERNS = {
    # exec/shell_exec/system/passthru with variables
    "exec_with_variable": {
        "pattern": r"\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\([^)]*\$",
        "severity": "high",
        "description": "Command execution function with variable (potential command injection)",
        "recommendation": "Avoid shell commands. Use PHP functions or escapeshellarg()/escapeshellcmd()",
    },
    # Backtick operator (shell execution)
    "backtick_operator": {
        "pattern": r"`[^`]*\$[^`]*`",
        "severity": "high",
        "description": "Backtick shell execution with variable (command injection risk)",
        "recommendation": "Avoid backtick operator. Use PHP functions instead",
    },
    # Drush shell execution
    "drush_shell_exec": {
        "pattern": r"drush_shell_exec\([^)]*\$",
        "severity": "high",
        "description": "Drush shell execution with variable",
        "recommendation": "Use Drush API directly instead of shell commands",
    },
    # PHP mail() with user input (can inject shell commands)
    "mail_injection": {
        "pattern": r"\bmail\s*\([^)]*\$_(GET|POST|REQUEST)",
        "severity": "medium",
        "description": "mail() with user input (potential header/command injection)",
        "recommendation": "Use Drupal's mail system and sanitize inputs",
    },
}


# ============================================================================
# PATH TRAVERSAL PATTERNS
# ============================================================================

PATH_TRAVERSAL_PATTERNS = {
    # File operations with user input
    "file_include_variable": {
        "pattern": r"\b(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
        "severity": "high",
        "description": "File include with user input (path traversal/RCE risk)",
        "recommendation": "Never include files based on user input. Use whitelist approach",
    },
    # File read operations with variables
    "file_read_variable": {
        "pattern": r"\b(file_get_contents|fopen|readfile|file)\s*\([^)]*\$_(GET|POST|REQUEST)",
        "severity": "high",
        "description": "File read operation with user input (path traversal risk)",
        "recommendation": "Validate with realpath(), check against allowed directories",
    },
    # Directory traversal pattern in string
    "dotdot_slash": {
        "pattern": r"\$[^=]*\.\.[\\/]",
        "severity": "medium",
        "description": "Potential path traversal sequence (../) in variable",
        "recommendation": "Use realpath() or drupal_realpath() to canonicalize paths",
    },
    # Drupal file operations without validation
    "drupal_file_ops_no_validation": {
        "pattern": r"file_save_data\([^)]*\$_(GET|POST)|->createFile\([^)]*\$_(GET|POST)",
        "severity": "medium",
        "description": "File operation with user input without visible validation",
        "recommendation": "Validate filename, use file_munge_filename(), check directory permissions",
    },
    # Unlink/delete with user input
    "file_delete_user_input": {
        "pattern": r"\b(unlink|file_unmanaged_delete)\s*\([^)]*\$_(GET|POST|REQUEST)",
        "severity": "high",
        "description": "File deletion with user input (path traversal risk)",
        "recommendation": "Validate against allowed directories, use realpath()",
    },
}


# ============================================================================
# HARDCODED SECRETS PATTERNS
# ============================================================================

HARDCODED_SECRETS_PATTERNS = {
    # API keys
    "api_key_hardcoded": {
        "pattern": r"['\"]?api[_-]?key['\"]?\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
        "severity": "high",
        "description": "Hardcoded API key detected",
        "recommendation": "Use settings.php, environment variables, or Key module",
    },
    # Password in code
    "password_hardcoded": {
        "pattern": r"['\"]?password['\"]?\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "severity": "high",
        "description": "Hardcoded password detected",
        "recommendation": "Never hardcode passwords. Use configuration or Key module",
    },
    # Database credentials
    "db_credentials": {
        "pattern": r"['\"](mysql|mysqli|pdo):.*password[=:][^;'\"]+",
        "severity": "high",
        "description": "Database credentials in code",
        "recommendation": "Use settings.php for database configuration",
    },
    # Private keys
    "private_key_hardcoded": {
        "pattern": r"['\"]?(private|secret)[_-]?key['\"]?\s*[=:]\s*['\"][a-zA-Z0-9+/=]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded private/secret key detected",
        "recommendation": "Use Key module or settings.php",
    },
    # OAuth tokens
    "oauth_token_hardcoded": {
        "pattern": r"['\"]?(access|bearer|oauth)[_-]?token['\"]?\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded OAuth/access token detected",
        "recommendation": "Use secure credential storage (Key module, settings.php)",
    },
    # AWS keys
    "aws_key_pattern": {
        "pattern": r"(AKIA[0-9A-Z]{16}|aws[_-]?secret|aws[_-]?access)",
        "severity": "high",
        "description": "AWS credentials pattern detected",
        "recommendation": "Use IAM roles or AWS credentials file, not hardcoded keys",
    },
}


# ============================================================================
# DEPRECATED/UNSAFE API PATTERNS
# ============================================================================

DEPRECATED_API_PATTERNS = {
    # Drupal 7 functions in D8+
    "drupal7_functions": {
        "pattern": r"\b(drupal_set_message|drupal_get_path|drupal_goto|t|variable_get|variable_set|db_query|db_select|format_date)\(",
        "severity": "medium",
        "description": "Drupal 7 function used (deprecated in D8+)",
        "recommendation": "Use D8+ services: \\Drupal::messenger(), \\Drupal::database(), etc.",
    },
    # eval() usage
    "eval_usage": {
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "description": "eval() usage detected (security risk)",
        "recommendation": "Refactor to avoid eval() - use proper PHP constructs",
    },
    # unserialize with user input
    "unserialize_user_input": {
        "pattern": r"unserialize\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
        "severity": "high",
        "description": "unserialize() with user input (RCE risk)",
        "recommendation": "Use JSON or validate source before unserialize()",
    },
    # create_function (deprecated PHP 7.2+)
    "create_function": {
        "pattern": r"\bcreate_function\s*\(",
        "severity": "medium",
        "description": "create_function() is deprecated (removed in PHP 8)",
        "recommendation": "Use anonymous functions: function() { ... }",
    },
    # extract() usage
    "extract_usage": {
        "pattern": r"\bextract\s*\(",
        "severity": "medium",
        "description": "extract() can overwrite variables (security/maintainability risk)",
        "recommendation": "Manually assign array values to avoid variable pollution",
    },
    # assert() with string argument
    "assert_string": {
        "pattern": r"\bassert\s*\(['\"]",
        "severity": "high",
        "description": "assert() with string is deprecated and dangerous (removed in PHP 8)",
        "recommendation": "Use proper conditionals or assertions with boolean expressions",
    },
}


# ============================================================================
