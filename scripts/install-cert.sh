#!/bin/bash

# Arc Browser Certificate Installation Script
# This script helps install the generated certificates for Arc Browser usage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT/certificates"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if certificates exist
check_certificates() {
    if [ ! -f "$CERT_DIR/mitm-proxy.pem" ] || [ ! -f "$CERT_DIR/mitm-proxy-key.pem" ]; then
        log_error "Certificates not found. Please run 'npm run cert' first."
        exit 1
    fi
}

# Install certificate in system keychain
install_system_keychain() {
    log_info "Installing certificate in system keychain..."
    
    # Get the CA certificate path from mkcert
    CA_CERT_PATH="$(mkcert -CAROOT)/rootCA.pem"
    
    if [ -f "$CA_CERT_PATH" ]; then
        # Add to system keychain with trust settings
        sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CERT_PATH"
        
        if [ $? -eq 0 ]; then
            log_success "Certificate installed in system keychain"
        else
            log_warning "Failed to install in system keychain (may already be installed)"
        fi
    else
        log_error "CA certificate not found at $CA_CERT_PATH"
        exit 1
    fi
}

# Install certificate in user keychain
install_user_keychain() {
    log_info "Installing certificate in user keychain..."
    
    CA_CERT_PATH="$(mkcert -CAROOT)/rootCA.pem"
    
    if [ -f "$CA_CERT_PATH" ]; then
        # Add to user keychain
        security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain "$CA_CERT_PATH" 2>/dev/null || true
        log_success "Certificate installed in user keychain"
    fi
}

# Create Arc Browser configuration
create_arc_config() {
    log_info "Creating Arc Browser proxy configuration..."
    
    # Arc Browser configuration directory
    ARC_CONFIG_DIR="$HOME/Library/Application Support/Arc/User Data/Default"
    
    if [ ! -d "$ARC_CONFIG_DIR" ]; then
        log_warning "Arc Browser configuration directory not found"
        log_info "Please ensure Arc Browser is installed and has been run at least once"
        return 1
    fi
    
    # Create proxy configuration
    PROXY_CONFIG_FILE="$ARC_CONFIG_DIR/proxy_config.json"
    
    cat > "$PROXY_CONFIG_FILE" << EOF
{
  "mode": "fixed_servers",
  "rules": {
    "singleProxy": {
      "scheme": "http",
      "host": "127.0.0.1",
      "port": 8080
    }
  }
}
EOF
    
    log_success "Arc Browser proxy configuration created"
    log_info "Configuration saved to: $PROXY_CONFIG_FILE"
}

# Display Arc Browser setup instructions
show_arc_instructions() {
    log_info "Arc Browser Setup Instructions:"
    echo ""
    echo "1. Open Arc Browser"
    echo "2. Go to Arc Menu → Settings (or press Cmd+,)"
    echo "3. Navigate to Advanced → Network → Proxy Settings"
    echo "4. Select 'Manual proxy configuration'"
    echo "5. Set HTTP Proxy to: localhost:8080"
    echo "6. Set HTTPS Proxy to: localhost:8080"
    echo "7. Leave 'No proxy for' empty or add exclusions as needed"
    echo "8. Click 'OK' to save settings"
    echo ""
    log_warning "Alternative: Use system proxy settings in macOS System Preferences"
}

# Set system proxy (optional)
set_system_proxy() {
    read -p "Do you want to set system-wide HTTP proxy? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Setting system-wide HTTP proxy..."
        
        # Get the primary network service
        NETWORK_SERVICE=$(networksetup -listnetworkserviceorder | grep -E "^\([0-9]+\)" | head -1 | sed 's/^([0-9]*) //')
        
        if [ -n "$NETWORK_SERVICE" ]; then
            # Set HTTP proxy
            networksetup -setwebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
            # Set HTTPS proxy
            networksetup -setsecurewebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
            
            log_success "System proxy configured for: $NETWORK_SERVICE"
            log_warning "Remember to disable proxy when you're done!"
            echo "To disable: networksetup -setwebproxystate '$NETWORK_SERVICE' off"
            echo "           networksetup -setsecurewebproxystate '$NETWORK_SERVICE' off"
        else
            log_error "Could not determine primary network service"
        fi
    fi
}

# Verify certificate installation
verify_installation() {
    log_info "Verifying certificate installation..."
    
    CA_CERT_PATH="$(mkcert -CAROOT)/rootCA.pem"
    
    # Check if certificate is in keychain
    if security find-certificate -c "mkcert" >/dev/null 2>&1; then
        log_success "mkcert CA certificate found in keychain"
    else
        log_warning "mkcert CA certificate not found in keychain"
    fi
    
    # Test HTTPS connection
    log_info "Testing HTTPS connection to localhost..."
    if openssl s_client -connect localhost:8443 -cert "$CERT_DIR/mitm-proxy.pem" -key "$CERT_DIR/mitm-proxy-key.pem" </dev/null >/dev/null 2>&1; then
        log_success "HTTPS connection test passed"
    else
        log_warning "HTTPS connection test failed (server may not be running)"
    fi
}

# Main execution
main() {
    log_info "Installing certificates for Arc Browser MITM Proxy..."
    echo ""
    
    check_certificates
    install_system_keychain
    install_user_keychain
    create_arc_config
    
    echo ""
    show_arc_instructions
    echo ""
    
    set_system_proxy
    
    echo ""
    verify_installation
    
    echo ""
    log_success "Certificate installation completed!"
    echo ""
    log_info "You can now:"
    echo "  1. Start the MITM proxy: npm run dev"
    echo "  2. Open Arc Browser and browse normally"
    echo "  3. View captured traffic in the logs"
    echo ""
    log_warning "Security Notice: Only intercept your own traffic!"
}

# Run main function
main "$@"