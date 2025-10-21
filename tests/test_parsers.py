"""Tests for parser modules."""

import pytest
from src.parsers import parse_info_file, parse_services_file, parse_routing_file, parse_php_file


class TestInfoParser:
    """Tests for .info.yml parser."""

    def test_parse_valid_info_file(self, tmp_path):
        """Test parsing a valid .info.yml file."""
        info_file = tmp_path / "test_module.info.yml"
        info_file.write_text(
            """
name: Test Module
type: module
description: 'A test module for parsing'
package: Testing
core_version_requirement: ^9 || ^10
dependencies:
  - drupal:node
  - views
"""
        )

        result = parse_info_file(info_file)

        assert result["name"] == "Test Module"
        assert result["type"] == "module"
        assert result["description"] == "A test module for parsing"
        assert result["package"] == "Testing"
        assert "node" in result["dependencies"]
        assert "views" in result["dependencies"]
        assert "test" in result["keywords"]
        assert "module" in result["keywords"]

    def test_parse_minimal_info_file(self, tmp_path):
        """Test parsing minimal .info.yml file."""
        info_file = tmp_path / "minimal.info.yml"
        info_file.write_text(
            """
name: Minimal
type: module
"""
        )

        result = parse_info_file(info_file)

        assert result["name"] == "Minimal"
        assert result["type"] == "module"
        assert result["dependencies"] == []

    def test_parse_invalid_info_file(self, tmp_path):
        """Test parsing invalid YAML."""
        info_file = tmp_path / "invalid.info.yml"
        info_file.write_text("invalid: yaml: content:")

        result = parse_info_file(info_file)

        assert "error" in result
        assert result["name"] == ""


class TestServicesParser:
    """Tests for .services.yml parser."""

    def test_parse_valid_services_file(self, tmp_path):
        """Test parsing a valid .services.yml file."""
        services_file = tmp_path / "test.services.yml"
        services_file.write_text(
            """
services:
  test.email_sender:
    class: Drupal\\test\\EmailSender
    arguments:
      - '@mailer'
      - '@logger.factory'
    tags:
      - { name: service }
"""
        )

        result = parse_services_file(services_file)

        assert len(result["services"]) == 1
        service = result["services"][0]
        assert service["id"] == "test.email_sender"
        assert service["class"] == "Drupal\\test\\EmailSender"
        assert "mailer" in service["arguments"]
        assert "logger.factory" in service["arguments"]
        # Check for any email-related keyword (could be 'email', 'emailsender', etc.)
        assert any("email" in kw for kw in service["keywords"])

    def test_parse_empty_services_file(self, tmp_path):
        """Test parsing empty services file."""
        services_file = tmp_path / "empty.services.yml"
        services_file.write_text("services: {}")

        result = parse_services_file(services_file)

        assert result["services"] == []


class TestRoutingParser:
    """Tests for .routing.yml parser."""

    def test_parse_valid_routing_file(self, tmp_path):
        """Test parsing a valid .routing.yml file."""
        routing_file = tmp_path / "test.routing.yml"
        routing_file.write_text(
            """
test.api_endpoint:
  path: '/api/test'
  defaults:
    _controller: '\\Drupal\\test\\Controller\\ApiController::getData'
  methods: [GET]
  requirements:
    _permission: 'access content'
"""
        )

        result = parse_routing_file(routing_file)

        assert len(result["routes"]) == 1
        route = result["routes"][0]
        assert route["name"] == "test.api_endpoint"
        assert route["path"] == "/api/test"
        assert "ApiController" in route["controller"]
        assert "api" in route["keywords"]

    def test_parse_form_route(self, tmp_path):
        """Test parsing route with _form controller."""
        routing_file = tmp_path / "form.routing.yml"
        routing_file.write_text(
            """
test.settings_form:
  path: '/admin/config/test'
  defaults:
    _form: '\\Drupal\\test\\Form\\SettingsForm'
"""
        )

        result = parse_routing_file(routing_file)

        route = result["routes"][0]
        assert "SettingsForm" in route["controller"]


class TestPhpParser:
    """Tests for PHP parser."""

    def test_parse_class_file(self, tmp_path):
        """Test parsing a PHP class file."""
        php_file = tmp_path / "TestClass.php"
        php_file.write_text(
            """<?php

namespace Drupal\\test\\Service;

use Drupal\\Core\\Logger\\LoggerChannelFactoryInterface;

/**
 * Test service for email functionality.
 */
class EmailSender {

  public function sendEmail() {
    // Send email
  }

}
"""
        )

        result = parse_php_file(php_file)

        assert result["namespace"] == "Drupal\\test\\Service"
        assert len(result["classes"]) == 1
        assert result["classes"][0]["name"] == "EmailSender"
        assert "Drupal\\Core\\Logger\\LoggerChannelFactoryInterface" in result["uses"]
        assert "email" in result["keywords"]

    def test_parse_module_file(self, tmp_path):
        """Test parsing a .module file with hooks."""
        module_file = tmp_path / "test.module"
        module_file.write_text(
            """<?php

/**
 * Implements hook_cron().
 */
function test_hook_cron() {
  // Do cron stuff
}

/**
 * Implements hook_form_alter().
 */
function test_hook_form_alter(&$form, $form_state, $form_id) {
  // Alter form
}
"""
        )

        result = parse_php_file(module_file)

        assert len(result["hooks"]) == 2
        # Hooks are now dicts with 'name' and 'line' keys
        hook_names = [hook["name"] for hook in result["hooks"]]
        assert "test_hook_cron" in hook_names
        assert "test_hook_form_alter" in hook_names
        # Verify line numbers are present
        assert all("line" in hook for hook in result["hooks"])

    def test_parse_class_with_inheritance(self, tmp_path):
        """Test parsing class with extends and implements."""
        php_file = tmp_path / "Controller.php"
        php_file.write_text(
            """<?php

namespace Drupal\\test\\Controller;

use Drupal\\Core\\Controller\\ControllerBase;

class ApiController extends ControllerBase implements MyInterface {

  public function getData() {
    return [];
  }

}
"""
        )

        result = parse_php_file(php_file)

        assert result["classes"][0]["name"] == "ApiController"
        assert result["classes"][0]["extends"] == "ControllerBase"
        assert "MyInterface" in result["classes"][0]["implements"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
