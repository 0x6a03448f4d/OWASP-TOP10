# 🐳 OWASP Top 10 - Docker Setup Guide

## Quick Start

Start the entire platform with a single command:

```bash
docker-compose up -d
```

Access the dashboard at: **http://localhost**

## What Gets Started

The main `docker-compose.yml` starts:

- **Dashboard Web Interface** - Main navigation hub (port 80)
- All static resources (cheat sheets, diagrams, CTF hub, quiz platform)

## Starting Individual Labs

Labs are started on-demand to save resources. There are two ways to start labs:

### Method 1: Through the Web Interface

1. Navigate to http://localhost
2. Click on "OWASP Top 10 Labs"
3. Select a category (Web, API, Mobile, or LLM)
4. Click "Start Lab" on any vulnerability
5. Follow the instructions to start the lab's Docker container

### Method 2: Manual Docker Compose

Navigate to the specific lab directory and start it:

```bash
# Example: Starting Web Lab 01 - Broken Access Control
cd OWASP-Web/01-Broken-Access-Control/lab
docker-compose up -d

# Example: Starting API Lab 01 - BOLA
cd OWASP-API/API01-Broken-Object-Level-Authorization/lab
docker-compose up -d

# Example: Starting Mobile Lab 01
cd OWASP-Mobile/M01-Improper-Credential-Usage/lab/m01-credential-exposure-lab
docker-compose up -d
```

## Available Services

### Main Dashboard (Port 80)
- **Homepage**: http://localhost
- **Cheat Sheets**: http://localhost/cheat-sheets/
- **CTF Hub**: http://localhost/ctf-hub/
- **Diagrams**: http://localhost/diagrams/
- **Quiz Platform**: http://localhost/quiz-platform/
- **Compliance Mappings**: http://localhost/compliance-mappings/
- **OWASP Labs**: http://localhost/owasp-labs.html

### Lab Port Ranges

When you start individual labs, they use these port ranges:

- **Web Labs**: 8001-8010
- **API Labs**: 9001-9010
- **Mobile Labs**: 7001-7010
- **LLM Labs**: 6001-6010

## Managing Services

### View Running Containers

```bash
docker ps
```

### View All Containers (including stopped)

```bash
docker ps -a
```

### Stop All Services

```bash
docker-compose down
```

### Stop Individual Lab

```bash
cd <lab-directory>
docker-compose down
```

### View Logs

```bash
# Dashboard logs
docker-compose logs -f dashboard

# Individual lab logs
cd <lab-directory>
docker-compose logs -f
```

### Restart Services

```bash
docker-compose restart
```

## Resource Management

### On-Demand vs Pre-Started Labs

**Recommended: On-Demand (Default)**
- Start only the labs you're currently using
- Saves CPU, memory, and disk space
- Faster initial startup

**Pre-Started (Optional)**
- Uncomment lab services in `docker-compose.yml`
- All labs ready immediately
- Requires more resources

### To Pre-Start All Labs

Edit `docker-compose.yml` and uncomment the lab services you want to pre-start, then:

```bash
docker-compose up -d
```

## Troubleshooting

### Port Already in Use

If you see "port already in use" errors:

```bash
# Find what's using the port (example for port 80)
lsof -i :80  # macOS/Linux
netstat -ano | findstr :80  # Windows

# Stop the conflicting service or change the port in docker-compose.yml
```

### Container Won't Start

```bash
# Check logs
docker-compose logs <service-name>

# Rebuild the container
docker-compose up -d --build <service-name>
```

### Reset Everything

```bash
# Stop and remove all containers, networks, and volumes
docker-compose down -v

# Start fresh
docker-compose up -d
```

## Network Architecture

All services run on the `owasp-network` bridge network, allowing:
- Inter-container communication
- Isolated environment from host
- Easy service discovery

## Security Notes

⚠️ **Important Security Warnings**

1. **Educational Purpose Only**: These are intentionally vulnerable applications
2. **Never expose to the internet**: Run only on localhost or isolated networks
3. **Use in isolated environment**: Consider running in a VM or isolated network
4. **Do not use in production**: These apps contain security vulnerabilities by design

## Advanced Configuration

### Custom Ports

Edit `docker-compose.yml` to change the dashboard port:

```yaml
services:
  dashboard:
    ports:
      - "8080:80"  # Change 8080 to your desired port
```

### Resource Limits

Add resource limits to prevent overconsumption:

```yaml
services:
  dashboard:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
```

### Persistent Data

Some labs may need persistent data. Uncomment volume mounts as needed.

## Platform Requirements

- **Docker**: 20.10.0 or higher
- **Docker Compose**: 1.29.0 or higher
- **Disk Space**: 5GB minimum (more if running all labs)
- **RAM**: 4GB minimum (8GB recommended for multiple labs)
- **CPU**: 2 cores minimum (4 cores recommended)

## Getting Help

1. Check the logs: `docker-compose logs`
2. Review lab-specific README: `<lab-directory>/README.md`
3. Visit the main repository README
4. Open an issue on GitHub

## License

MIT License - See LICENSE file for details

## Ethical Use Reminder

This platform is for **educational purposes only**. Always:
- ✅ Use in isolated environments
- ✅ Learn responsibly
- ✅ Practice ethical hacking
- ❌ Never attack systems without authorization
