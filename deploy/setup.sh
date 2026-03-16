#!/usr/bin/env bash
set -euo pipefail

# ShieldAGI 2.0 — Server Setup Script
# Run on a fresh Ubuntu 24.04 server

INSTALL_DIR="/opt/shieldagi"
REPO_URL="https://github.com/shieldagi/shieldagi.git"

echo "========================================="
echo " ShieldAGI 2.0 — Server Setup"
echo "========================================="

# ─── Check root ─────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)."
    exit 1
fi

# ─── System updates ─────────────────────────
echo "[1/7] Updating system packages..."
apt update -qq && apt upgrade -y -qq

# ─── Install Docker ─────────────────────────
echo "[2/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "  Docker already installed: $(docker --version)"
fi

# Install Docker Compose plugin if missing
if ! docker compose version &> /dev/null; then
    apt install -y -qq docker-compose-plugin
fi

# ─── Install Nginx ──────────────────────────
echo "[3/7] Installing Nginx and Certbot..."
apt install -y -qq nginx certbot python3-certbot-nginx

# ─── Clone repository ───────────────────────
echo "[4/7] Cloning ShieldAGI..."
if [[ -d "$INSTALL_DIR" ]]; then
    echo "  Directory exists, pulling latest..."
    cd "$INSTALL_DIR" && git pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

# ─── Configure environment ──────────────────
echo "[5/7] Configuring environment..."
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cat > "$INSTALL_DIR/.env" << 'ENVEOF'
# ShieldAGI 2.0 — Environment Configuration
# Fill in the required values before starting.

# Required: Anthropic API key
ANTHROPIC_API_KEY=

# PostgreSQL
POSTGRES_USER=shieldagi
POSTGRES_PASSWORD=CHANGE_ME
POSTGRES_DB=shieldagi

# Redis
REDIS_URL=redis://redis:6379

# Grafana
GF_SECURITY_ADMIN_PASSWORD=CHANGE_ME

# OpenFang
OPENFANG_PORT=4200
OPENFANG_DATA_DIR=/opt/shieldagi/data

# Alert channels (optional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SLACK_WEBHOOK_URL=
ENVEOF

    echo ""
    echo "  IMPORTANT: Edit $INSTALL_DIR/.env and set:"
    echo "    - ANTHROPIC_API_KEY"
    echo "    - POSTGRES_PASSWORD (generate a strong one)"
    echo "    - GF_SECURITY_ADMIN_PASSWORD"
    echo ""
fi

# ─── Configure firewall ─────────────────────
echo "[6/7] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp    # SSH
    ufw allow 80/tcp    # HTTP
    ufw allow 443/tcp   # HTTPS
    ufw deny 3000/tcp   # Block direct Grafana
    ufw deny 4200/tcp   # Block direct OpenFang
    ufw deny 5432/tcp   # Block direct PostgreSQL
    ufw deny 6379/tcp   # Block direct Redis
    ufw --force enable
    echo "  Firewall configured: SSH, HTTP, HTTPS allowed. Internal ports blocked."
else
    echo "  Warning: ufw not found. Install and configure manually."
fi

# ─── Deploy services ────────────────────────
echo "[7/7] Deploying services..."
cd "$INSTALL_DIR"

# Copy compose file
cp deploy/docker-compose.production.yml docker-compose.yml

# Copy and enable nginx config
cp deploy/nginx.conf /etc/nginx/sites-available/shieldagi
ln -sf /etc/nginx/sites-available/shieldagi /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Install systemd service
cp deploy/systemd/shieldagi.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable shieldagi

# Create data and backup directories
mkdir -p /opt/shieldagi/data /opt/backups

# Check if .env has been configured
if grep -q "CHANGE_ME" "$INSTALL_DIR/.env" || grep -q "^ANTHROPIC_API_KEY=$" "$INSTALL_DIR/.env"; then
    echo ""
    echo "========================================="
    echo " Setup complete, but .env needs editing!"
    echo "========================================="
    echo ""
    echo " Next steps:"
    echo "   1. Edit /opt/shieldagi/.env with your credentials"
    echo "   2. Update domain in /etc/nginx/sites-available/shieldagi"
    echo "   3. Run: certbot --nginx -d YOUR_DOMAIN"
    echo "   4. Run: systemctl start shieldagi"
    echo "   5. Verify: docker compose ps"
    echo ""
else
    # Start services
    systemctl start shieldagi

    echo ""
    echo "========================================="
    echo " ShieldAGI deployed successfully!"
    echo "========================================="
    echo ""

    # Health checks
    echo "Running health checks..."
    sleep 10

    if curl -sf http://localhost:4200/health > /dev/null 2>&1; then
        echo "  [OK] OpenFang is running"
    else
        echo "  [--] OpenFang starting up (check: docker compose logs openfang)"
    fi

    if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
        echo "  [OK] Grafana is running"
    else
        echo "  [--] Grafana starting up (check: docker compose logs grafana)"
    fi

    if docker exec shieldagi-postgres pg_isready -U shieldagi > /dev/null 2>&1; then
        echo "  [OK] PostgreSQL is running"
    else
        echo "  [--] PostgreSQL starting up"
    fi

    if docker exec shieldagi-redis redis-cli ping > /dev/null 2>&1; then
        echo "  [OK] Redis is running"
    else
        echo "  [--] Redis starting up"
    fi

    echo ""
    echo " Next steps:"
    echo "   1. Update domain in /etc/nginx/sites-available/shieldagi"
    echo "   2. Run: certbot --nginx -d YOUR_DOMAIN"
    echo "   3. Run: nginx -t && systemctl reload nginx"
    echo "   4. Access dashboard at https://YOUR_DOMAIN/grafana"
    echo ""
fi
