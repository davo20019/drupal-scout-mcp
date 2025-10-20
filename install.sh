#!/bin/bash
#
# Drupal Scout MCP - Easy Installation Script
#
# Usage: curl -sSL https://raw.githubusercontent.com/davo20019/drupal-scout-mcp/main/install.sh | bash
#

set -e

echo "🔍 Drupal Scout MCP - Installation"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    echo "Please install Python 3.10 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python 3.10+ required (you have $PYTHON_VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
echo ""

# Install location
INSTALL_DIR="$HOME/.local/drupal-scout-mcp"
CONFIG_DIR="$HOME/.config/drupal-scout"

echo "Installing to: $INSTALL_DIR"
echo ""

# Clone or update repository
if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
else
    echo "Cloning repository..."
    git clone https://github.com/davo20019/drupal-scout-mcp.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo -e "${GREEN}✓ Repository cloned${NC}"
echo ""

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --quiet
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Create config directory
mkdir -p "$CONFIG_DIR"
echo -e "${GREEN}✓ Config directory created${NC}"
echo ""

# Prompt for Drupal path
echo "=================================="
echo "Configuration"
echo "=================================="
echo ""

if [ -f "$CONFIG_DIR/config.json" ]; then
    echo -e "${YELLOW}Config file already exists at $CONFIG_DIR/config.json${NC}"
    read -p "Do you want to reconfigure? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        SKIP_CONFIG=1
    fi
fi

if [ -z "$SKIP_CONFIG" ]; then
    read -p "Enter your Drupal root path: " DRUPAL_ROOT

    # Expand ~ to home directory
    DRUPAL_ROOT="${DRUPAL_ROOT/#\~/$HOME}"

    # Check if directory exists
    if [ ! -d "$DRUPAL_ROOT" ]; then
        echo -e "${YELLOW}Warning: Directory does not exist: $DRUPAL_ROOT${NC}"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Detect modules path
    if [ -d "$DRUPAL_ROOT/web/modules" ]; then
        MODULES_PATH="web/modules"
        echo -e "${GREEN}Detected Composer-based Drupal (web/modules)${NC}"
    elif [ -d "$DRUPAL_ROOT/modules" ]; then
        MODULES_PATH="modules"
        echo -e "${GREEN}Detected standard Drupal (modules)${NC}"
    else
        echo -e "${YELLOW}Could not detect modules directory${NC}"
        read -p "Enter modules path (relative to Drupal root): " MODULES_PATH
    fi

    # Create config file
    cat > "$CONFIG_DIR/config.json" << EOF
{
  "drupal_root": "$DRUPAL_ROOT",
  "modules_path": "$MODULES_PATH",
  "exclude_paths": [
    "*/node_modules/*",
    "*/vendor/*",
    "*/tests/*",
    "*/test/*"
  ]
}
EOF

    echo -e "${GREEN}✓ Config file created${NC}"
fi

echo ""

# Detect MCP client
echo "=================================="
echo "MCP Client Configuration"
echo "=================================="
echo ""

MCP_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
CURSOR_CONFIG="$HOME/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"

MCP_CONFIG="{
  \"mcpServers\": {
    \"drupal-scout\": {
      \"command\": \"python3\",
      \"args\": [\"$INSTALL_DIR/server.py\"]
    }
  }
}"

# Check for MCP client
if [ -f "$MCP_CONFIG" ]; then
    echo -e "${GREEN}Found MCP client config${NC}"
    echo "Would you like to add Drupal Scout to your MCP client?"
    read -p "(y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup existing config
        cp "$CLAUDE_CONFIG" "$CLAUDE_CONFIG.backup"

        # Add to config (simple append - user should verify)
        echo ""
        echo "Please add this to your MCP client config:"
        echo "$MCP_CONFIG"
        echo ""
        echo "Config file: $CLAUDE_CONFIG"
        echo "(Backup saved to $CLAUDE_CONFIG.backup)"
    fi
fi

# Check for Cursor
if [ -d "$HOME/Library/Application Support/Cursor" ]; then
    echo -e "${GREEN}Found Cursor${NC}"
    echo "For Cursor, add this to your MCP settings:"
    echo "$MCP_CONFIG"
    echo ""
fi

# Test installation
echo "=================================="
echo "Testing Installation"
echo "=================================="
echo ""

echo "Running quick test..."
cd "$INSTALL_DIR"
if python3 -c "from src.drupal_org import DrupalOrgAPI; print('✓ Import successful')" 2>/dev/null; then
    echo -e "${GREEN}✓ Installation test passed${NC}"
else
    echo -e "${RED}✗ Installation test failed${NC}"
    echo "Please check the installation and try again"
    exit 1
fi

echo ""
echo "=================================="
echo "Installation Complete! 🎉"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Restart your MCP client (Cursor, Claude Desktop, or other MCP-compatible IDE)"
echo "2. Try: 'List all Drupal modules'"
echo "3. Read docs: $INSTALL_DIR/README.md"
echo ""
echo "Config file: $CONFIG_DIR/config.json"
echo "Installation: $INSTALL_DIR"
echo ""
echo "For help: https://github.com/davo20019/drupal-scout-mcp"
echo ""
