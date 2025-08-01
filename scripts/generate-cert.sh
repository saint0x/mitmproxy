#!/bin/bash

# Arc Browser MITM Proxy Certificate Generation Script
# This script generates a self-signed CA certificate for local HTTPS interception

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

# Check if mkcert is installed
check_mkcert() {
    if ! command -v mkcert &> /dev/null; then
        log_error "mkcert is not installed. Please install it first:"
        echo "  macOS: brew install mkcert"
        echo "  Linux: Follow instructions at https://github.com/FiloSottile/mkcert"
        exit 1
    fi
}

# Create certificates directory
create_cert_dir() {
    if [ ! -d "$CERT_DIR" ]; then
        log_info "Creating certificates directory..."
        mkdir -p "$CERT_DIR"
    fi
}

# Generate CA certificate
generate_ca() {
    log_info "Installing mkcert CA in system trust store..."
    mkcert -install
    
    if [ $? -eq 0 ]; then
        log_success "CA certificate installed in system trust store"
    else
        log_error "Failed to install CA certificate"
        exit 1
    fi
}

# Generate server certificates
generate_server_certs() {
    log_info "Generating server certificates for MITM proxy..."
    
    cd "$CERT_DIR"
    
    # Generate certificate for localhost and common domains
    mkcert -cert-file "mitm-proxy.pem" -key-file "mitm-proxy-key.pem" \
        localhost \
        127.0.0.1 \
        ::1 \
        "*.arc.net" \
        "*.segment.io" \
        "*.firebaseio.com" \
        "*.amplitude.com" \
        "*.sentry.io" \
        "*.launchdarkly.com"
    
    if [ $? -eq 0 ]; then
        log_success "Server certificates generated successfully"
    else
        log_error "Failed to generate server certificates"
        exit 1
    fi
}

# Set proper permissions
set_permissions() {
    log_info "Setting secure permissions on certificates..."
    chmod 600 "$CERT_DIR"/*.pem
    chmod 700 "$CERT_DIR"
    
    log_success "Certificate permissions set to secure mode"
}

# Display certificate information
show_cert_info() {
    log_info "Certificate information:"
    echo "  Certificate file: $CERT_DIR/mitm-proxy.pem"
    echo "  Private key file: $CERT_DIR/mitm-proxy-key.pem"
    echo ""
    
    log_info "Certificate details:"
    openssl x509 -in "$CERT_DIR/mitm-proxy.pem" -text -noout | grep -E "(Subject:|DNS:|IP Address:)" || true
}

# Create environment file with certificate paths
create_env_file() {
    ENV_FILE="$PROJECT_ROOT/.env"
    
    if [ ! -f "$ENV_FILE" ]; then
        log_info "Creating .env file with certificate paths..."
        cat > "$ENV_FILE" << EOF
# MITM Proxy Configuration
CERT_PATH=$CERT_DIR/mitm-proxy.pem
KEY_PATH=$CERT_DIR/mitm-proxy-key.pem
PROXY_PORT=8080
HTTPS_PORT=8443
LOG_LEVEL=info
EOF
        log_success ".env file created"
    else
        log_warning ".env file already exists, skipping creation"
    fi
}

# Main execution
main() {
    log_info "Starting certificate generation for Arc Browser MITM Proxy..."
    echo ""
    
    check_mkcert
    create_cert_dir
    generate_ca
    generate_server_certs
    set_permissions
    create_env_file
    show_cert_info
    
    echo ""
    log_success "Certificate generation completed successfully!"
    echo ""
    log_info "Next steps:"
    echo "  1. Run 'npm run install-cert' to install certificates for Arc Browser"
    echo "  2. Configure Arc Browser to use localhost:8080 as HTTPS proxy"
    echo "  3. Start the MITM proxy with 'npm run dev' or 'npm start'"
    echo ""
    log_warning "Remember: Only use this for your own traffic analysis!"
}

# Run main function
main "$@"