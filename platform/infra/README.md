# OWASP Top 10 Lab Manager - Infrastructure

This directory contains the infrastructure configuration for running the OWASP Top 10 Lab Manager platform.

## Quick Start

From this directory, run:

```bash
docker-compose up -d
```

This will start:
- **Dashboard** (port 80): Web interface for browsing and managing labs
- **Lab Manager API** (port 4999): Backend API for starting/stopping individual labs

## Accessing the Platform

- Main Dashboard: http://localhost
- Lab Manager API: http://localhost:4999/api/labs

## Directory Structure

```
platform/
├── backend/          # Flask API for lab management
├── frontend/         # HTML/CSS/JS dashboard
└── infra/           # Docker Compose and infrastructure configs (you are here)
```

## Files

- `docker-compose.yml`: Main platform services configuration
- `Dockerfile.lab-manager`: Lab manager API container
- `nginx.conf`: Nginx configuration for serving the frontend

## How It Works

1. The nginx container serves the frontend from `../frontend/`
2. The lab-manager container runs the Python Flask API from `../backend/`
3. The lab-manager uses Docker-in-Docker (DooD) to start/stop individual labs
4. Labs are located in `../../labs/` organized by category (web, api, mobile, llm)

## Troubleshooting

### Platform won't start

Check that Docker is running:
```bash
docker ps
```

Check logs:
```bash
docker-compose logs
```

### Labs not discovered

The lab manager looks for labs in:
- `../../labs/web/OWASP-Web/`
- `../../labs/api/OWASP-API/`
- `../../labs/mobile/OWASP-Mobile/`
- `../../labs/llm/OWASP-LLM/`

Ensure these directories exist and contain lab subdirectories with `lab/` folders.

### Lab won't start

Check individual lab logs:
```bash
docker logs <lab-container-name>
```

Ensure the lab's docker-compose.yml is properly configured.
