# Platform Directory

This directory contains the core Lab Manager platform code - the engine that powers the OWASP Top 10 learning experience.

## Structure

```
platform/
├── backend/          # Flask API for lab management
│   ├── app.py                   # Main API application
│   └── requirements.txt         # Python dependencies
├── frontend/         # Web dashboard
│   ├── index.html               # Landing page
│   ├── owasp-labs.html         # Main lab browser
│   ├── js/                      # JavaScript assets
│   ├── css/                     # Stylesheets (future)
│   └── assets/                  # Images and media (future)
└── infra/           # Infrastructure configuration
    ├── docker-compose.yml       # Platform services
    ├── Dockerfile.lab-manager   # Lab manager container
    ├── nginx.conf               # Web server config
    └── README.md                # Setup instructions
```

## Quick Start

From the `platform/infra/` directory:

```bash
docker-compose up -d
```

Access the platform:
- Dashboard: http://localhost
- API: http://localhost:4999

## Components

### Backend (`backend/`)

Flask-based REST API that:
- Discovers available labs
- Starts/stops lab containers via Docker
- Manages lab lifecycle
- Provides lab metadata

**Key file**: `app.py`

### Frontend (`frontend/`)

Web interface that:
- Displays available labs by category and year
- Provides lab descriptions and objectives
- Enables one-click lab start/stop
- Shows lab status in real-time

**Key files**: `index.html`, `owasp-labs.html`

### Infrastructure (`infra/`)

Docker Compose configuration that:
- Runs the dashboard (nginx)
- Runs the lab manager API
- Manages networking
- Handles Docker-in-Docker (DooD) for lab containers

**Key file**: `docker-compose.yml`

## Development

### Backend Development

```bash
cd platform/backend
pip install -r requirements.txt
python app.py
```

The API will be available at http://localhost:5000

### Frontend Development

Simply edit the HTML/CSS/JS files. Changes are reflected immediately when served by nginx.

For local testing without Docker:
```bash
cd platform/frontend
python -m http.server 8080
```

### Full Platform Development

```bash
cd platform/infra
docker-compose up --build
```

## Architecture

```
┌─────────────────┐
│   Browser       │
│  (localhost)    │
└────────┬────────┘
         │
    ┌────▼─────────────────┐
    │  nginx (port 80)     │
    │  Serves Frontend     │
    └────┬─────────────────┘
         │
    ┌────▼──────────────────────┐
    │  Lab Manager API          │
    │  (Flask, port 4999)       │
    │  - Discovers labs         │
    │  - Manages containers     │
    └────┬──────────────────────┘
         │
         │ Docker API
         │
    ┌────▼──────────────────────┐
    │  Docker Engine            │
    │  - Starts/stops labs      │
    │  - Manages lab containers │
    └───────────────────────────┘
```

## API Endpoints

- `GET /health` - Health check
- `GET /api/labs` - List all discovered labs
- `POST /api/labs/<lab_id>/start` - Start a lab
- `POST /api/labs/<lab_id>/stop` - Stop a lab
- `GET /api/labs/<lab_id>/status` - Get lab status

## Configuration

The backend discovers labs from:
- `../../OWASP-Web/` (Web category)
- `../../OWASP-API/` (API category)
- `../../OWASP-Mobile/` (Mobile category)
- `../../OWASP-LLM/` (LLM category)

**Note**: In future phases, labs will be moved to `../../labs/` with year-based organization.

## Troubleshooting

See `platform/infra/README.md` for detailed troubleshooting steps.

## Contributing

When modifying platform code:
1. Test changes locally first
2. Ensure backward compatibility
3. Update documentation
4. Test with multiple labs
5. Check Docker logs for errors

## Security Note

The Lab Manager uses Docker-in-Docker (DooD) by mounting `/var/run/docker.sock`. This gives the container access to the host's Docker daemon. Only run this in development/learning environments, not in production.
