# ShieldAGI 2.0 — Production Deployment

This guide covers deploying ShieldAGI on a dedicated Hetzner AX102 server (or equivalent).

## Server Requirements

- **Hetzner AX102** (or equivalent): AMD Ryzen 9 7950X, 128GB RAM, 2x 1TB NVMe
- **OS**: Ubuntu 24.04 LTS
- **Network**: 1 Gbps dedicated, static IPv4

## Quick Setup

```bash
# On a fresh Ubuntu 24.04 server:
curl -fsSL https://raw.githubusercontent.com/shieldagi/shieldagi/main/deploy/setup.sh | bash
```

Or step by step:

## 1. Server Preparation

```bash
# System updates
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker $USER

# Install Docker Compose plugin
apt install docker-compose-plugin -y

# Install Nginx
apt install nginx certbot python3-certbot-nginx -y
```

## 2. Clone and Configure

```bash
git clone https://github.com/shieldagi/shieldagi.git /opt/shieldagi
cd /opt/shieldagi
```

Create `/opt/shieldagi/.env`:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...

# PostgreSQL
POSTGRES_USER=shieldagi
POSTGRES_PASSWORD=<generate-strong-password>
POSTGRES_DB=shieldagi

# Redis
REDIS_URL=redis://redis:6379

# Grafana
GF_SECURITY_ADMIN_PASSWORD=<generate-strong-password>

# Alerts (optional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SLACK_WEBHOOK_URL=

# OpenFang
OPENFANG_PORT=4200
OPENFANG_DATA_DIR=/opt/shieldagi/data
```

## 3. Docker Compose Stack

Copy the production compose file:

```bash
cp deploy/docker-compose.production.yml docker-compose.yml
```

Services:
- **openfang**: Agent runtime on port 4200
- **postgres**: PostgreSQL 16 for knowledge store and reports
- **redis**: Rate limiting, caching, job queues
- **grafana**: Monitoring dashboard on port 3000

```bash
docker compose up -d
```

## 4. Nginx SSL Reverse Proxy

```bash
# Copy nginx config
cp deploy/nginx.conf /etc/nginx/sites-available/shieldagi
ln -sf /etc/nginx/sites-available/shieldagi /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Replace domain placeholder
sed -i 's/shieldagi.example.com/YOUR_DOMAIN/g' /etc/nginx/sites-available/shieldagi

# Get SSL certificate
certbot --nginx -d YOUR_DOMAIN

# Test and reload
nginx -t && systemctl reload nginx
```

The nginx config provides:
- SSL termination with HTTP/2
- Rate limiting (10 req/s burst 20)
- Security headers (HSTS, X-Frame-Options, CSP, etc.)
- Proxy to OpenFang (4200) at `/`
- Proxy to Grafana (3000) at `/grafana`
- WebSocket support for live dashboard updates

## 5. systemd Service

```bash
# Install service
cp deploy/systemd/shieldagi.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable shieldagi
systemctl start shieldagi
```

Manage the service:
```bash
systemctl status shieldagi     # Check status
systemctl restart shieldagi    # Restart
journalctl -u shieldagi -f     # View logs
```

## 6. Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Claude API key |
| `POSTGRES_USER` | Yes | Database username |
| `POSTGRES_PASSWORD` | Yes | Database password |
| `POSTGRES_DB` | Yes | Database name |
| `REDIS_URL` | No | Redis connection (default: redis://redis:6379) |
| `GF_SECURITY_ADMIN_PASSWORD` | Yes | Grafana admin password |
| `OPENFANG_PORT` | No | OpenFang API port (default: 4200) |
| `OPENFANG_DATA_DIR` | No | Data directory (default: /opt/shieldagi/data) |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot API token |
| `TELEGRAM_CHAT_ID` | No | Telegram chat/channel ID |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook URL |

## 7. Monitoring with Grafana

Access Grafana at `https://YOUR_DOMAIN/grafana` (or port 3000 directly).

**Pre-configured dashboards**:

- **Sentinel Overview**: threat timeline, attack type distribution, blocked IPs, response times
- **Dependency Health**: monitored deps, new CVEs, auto-patched count, pending reviews
- **Incident Log**: incidents by severity, MTTC, MTTR, false positive rate
- **Pipeline Runs**: scan duration, vulnerabilities found per run, fixes applied

**Data sources**: PostgreSQL (knowledge store) and Redis (real-time metrics) are auto-configured.

## 8. Backup Strategy

```bash
# Daily PostgreSQL backup (add to crontab)
0 2 * * * docker exec shieldagi-postgres pg_dump -U shieldagi shieldagi | gzip > /opt/backups/shieldagi-$(date +\%Y\%m\%d).sql.gz

# Keep 30 days of backups
0 3 * * * find /opt/backups -name "shieldagi-*.sql.gz" -mtime +30 -delete

# Backup Grafana dashboards
0 2 * * * docker cp shieldagi-grafana:/var/lib/grafana/grafana.db /opt/backups/grafana-$(date +\%Y\%m\%d).db
```

Create the backup directory:
```bash
mkdir -p /opt/backups
```

## 9. Firewall Rules

```bash
# UFW configuration
ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow 22/tcp

# HTTP/HTTPS (Nginx)
ufw allow 80/tcp
ufw allow 443/tcp

# Block direct access to internal services
# (Grafana and OpenFang are proxied through Nginx)
ufw deny 3000/tcp
ufw deny 4200/tcp
ufw deny 5432/tcp
ufw deny 6379/tcp

ufw enable
```

## Health Check

Verify everything is running:

```bash
# Docker services
docker compose ps

# OpenFang API
curl -s http://localhost:4200/health

# Grafana
curl -s http://localhost:3000/api/health

# Nginx
curl -s -o /dev/null -w "%{http_code}" https://YOUR_DOMAIN/health

# PostgreSQL
docker exec shieldagi-postgres pg_isready -U shieldagi

# Redis
docker exec shieldagi-redis redis-cli ping
```
