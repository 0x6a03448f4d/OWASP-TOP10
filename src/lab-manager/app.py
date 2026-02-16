#!/usr/bin/env python3
"""
OWASP Lab Manager API
A simple Flask API to manage Docker-based vulnerable labs
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import docker
import os
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Docker client
try:
    # Forçar a ligação ao socket nativo para evitar o erro "http+docker"
    docker_client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
    docker_client.ping()
    logger.info("Docker client initialized successfully via unix socket")
except Exception as e:
    logger.warning(f"Failed with unix socket, trying from_env. Error: {e}")
    try:
        docker_client = docker.from_env()
        docker_client.ping()
        logger.info("Docker client initialized successfully via env")
    except Exception as e2:
        logger.error(f"Failed to initialize Docker client completely: {e2}")
        docker_client = None

LAB_NETWORK = os.getenv('LAB_NETWORK', 'owasp-network')

def discover_labs():
    """
    Dynamically discover all available labs by scanning the directory structure
    """
    categories = {
        'web': {'path': 'OWASP-Web', 'base_port': 8000, 'prefix': 'web'},
        'api': {'path': 'OWASP-API', 'base_port': 9000, 'prefix': 'api'},
        'mobile': {'path': 'OWASP-Mobile', 'base_port': 7000, 'prefix': 'mobile'},
        'llm': {'path': 'OWASP-LLM', 'base_port': 6000, 'prefix': 'llm'}
    }
    
    labs = {}
    for cat_key, cat_info in categories.items():
        cat_path = cat_info['path']
        if not os.path.exists(cat_path):
            logger.warning(f"Category path not found: {cat_path}")
            continue
        
        # List all subdirectories
        try:
            subdirs = sorted([d for d in os.listdir(cat_path) if os.path.isdir(os.path.join(cat_path, d))])
        except Exception as e:
            logger.error(f"Error listing directory {cat_path}: {e}")
            continue
        
        port_offset = 1
        for subdir in subdirs:
            lab_path = os.path.join(cat_path, subdir, 'lab')
            if os.path.exists(lab_path):
                # Extract ID from directory name
                dir_parts = subdir.split('-')
                lab_id_part = dir_parts[0]
                
                # Format the lab ID for API call: category-id_part
                # e.g., web-01, api-api01, mobile-m01, llm-llm01
                lab_id = f"{cat_key}-{lab_id_part.lower()}"
                
                # Generate clean lab name
                lab_name = ' '.join(dir_parts[1:]) if len(dir_parts) > 1 else subdir
                
                # Generate container name based on category and number
                container_name = f"owasp-{cat_key}-lab-{lab_id_part.lower()}"
                
                labs[lab_id] = {
                    'name': lab_name,
                    'path': lab_path,
                    'port': cat_info['base_port'] + port_offset,
                    'container': container_name,
                    'category': cat_key,
                    'directory': subdir
                }
                port_offset += 1
    
    logger.info(f"Discovered {len(labs)} labs across {len(categories)} categories")
    return labs

# Discover labs at startup
LABS = discover_labs()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'docker': docker_client is not None})

@app.route('/api/labs', methods=['GET'])
def list_labs():
    """List all available labs with their status"""
    if not docker_client:
        return jsonify({'error': 'Docker client not available'}), 500
    
    labs_status = []
    try:
        containers = docker_client.containers.list(all=True)
        running_containers = {c.name: c.status for c in containers}
        
        for lab_id, lab_info in LABS.items():
            container_name = lab_info['container']
            status = running_containers.get(container_name, 'stopped')
            
            labs_status.append({
                'id': lab_id,
                'name': lab_info['name'],
                'port': lab_info['port'],
                'status': status,
                'url': f"http://localhost:{lab_info['port']}" if status == 'running' else None
            })
        
        return jsonify({'labs': labs_status})
    except Exception as e:
        logger.error(f"Error listing labs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>/start', methods=['POST'])
def start_lab(lab_id):
    """Start a specific lab - auto-build if needed"""
    if not docker_client:
        return jsonify({'error': 'Docker client not available'}), 500
    
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        # Check if container already exists
        try:
            container = docker_client.containers.get(container_name)
            if container.status == 'running':
                return jsonify({
                    'status': 'already_running',
                    'message': f"Lab {lab_info['name']} is already running",
                    'url': f"http://localhost:{lab_info['port']}"
                })
            else:
                # Start existing stopped container
                container.start()
                logger.info(f"Started existing container: {container_name}")
                return jsonify({
                    'status': 'started',
                    'message': f"Lab {lab_info['name']} started successfully",
                    'url': f"http://localhost:{lab_info['port']}"
                })
        except docker.errors.NotFound:
            # Container doesn't exist, auto-build it
            logger.info(f"Container {container_name} not found, attempting auto-build")
            import subprocess
            import os
            
            lab_path = os.path.abspath(lab_info['path'])
            
            # Security: Validate lab path is within expected directory
            expected_base = os.path.abspath('.')
            if not lab_path.startswith(expected_base):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid lab path - security violation'
                }), 403
            
            if not os.path.exists(lab_path):
                return jsonify({
                    'status': 'error',
                    'message': f"Lab path not found: {lab_path}"
                }), 404
            
            # Find docker-compose file
            compose_file = None
            for root, dirs, files in os.walk(lab_path):
                if 'docker-compose.yml' in files or 'docker-compose.yaml' in files:
                    compose_file = os.path.join(root, 'docker-compose.yml' if 'docker-compose.yml' in files else 'docker-compose.yaml')
                    break
            
            if not compose_file:
                return jsonify({
                    'status': 'error',
                    'message': f"No docker-compose file found in {lab_path}"
                }), 404
            
            # Build and start using docker-compose
            compose_dir = os.path.dirname(compose_file)
            logger.info(f"Auto-building lab from: {compose_dir}")
            
            try:
                # Run docker compose up -d
                result = subprocess.run(
                    ['docker', 'compose', 'up', '-d'],
                    cwd=compose_dir,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout
                )
                
                if result.returncode == 0:
                    logger.info(f"Successfully built and started lab: {container_name}")
                    return jsonify({
                        'status': 'started',
                        'message': f"Lab {lab_info['name']} built and started successfully",
                        'url': f"http://localhost:{lab_info['port']}",
                        'build_output': result.stdout
                    })
                else:
                    logger.error(f"Failed to build lab: {result.stderr}")
                    return jsonify({
                        'status': 'error',
                        'message': f"Failed to build lab: {result.stderr}"
                    }), 500
            except subprocess.TimeoutExpired:
                return jsonify({
                    'status': 'error',
                    'message': 'Lab build timeout (>5 minutes)'
                }), 500
            except Exception as e:
                logger.error(f"Error building lab: {e}")
                return jsonify({
                    'status': 'error',
                    'message': f"Error building lab: {str(e)}"
                }), 500
            
    except Exception as e:
        logger.error(f"Error starting lab {lab_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>/stop', methods=['POST'])
def stop_lab(lab_id):
    """Stop a specific lab"""
    if not docker_client:
        return jsonify({'error': 'Docker client not available'}), 500
    
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        container = docker_client.containers.get(container_name)
        if container.status == 'running':
            container.stop()
            logger.info(f"Stopped container: {container_name}")
            return jsonify({
                'status': 'stopped',
                'message': f"Lab {lab_info['name']} stopped successfully"
            })
        else:
            return jsonify({
                'status': 'already_stopped',
                'message': f"Lab {lab_info['name']} is not running"
            })
    except docker.errors.NotFound:
        return jsonify({
            'status': 'not_found',
            'message': f"Lab {lab_info['name']} container not found"
        }), 404
    except Exception as e:
        logger.error(f"Error stopping lab {lab_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>/status', methods=['GET'])
def lab_status(lab_id):
    """Get status of a specific lab"""
    if not docker_client:
        return jsonify({'error': 'Docker client not available'}), 500
    
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        container = docker_client.containers.get(container_name)
        return jsonify({
            'id': lab_id,
            'name': lab_info['name'],
            'status': container.status,
            'port': lab_info['port'],
            'url': f"http://localhost:{lab_info['port']}" if container.status == 'running' else None
        })
    except docker.errors.NotFound:
        return jsonify({
            'id': lab_id,
            'name': lab_info['name'],
            'status': 'not_found',
            'message': 'Container not built yet'
        })
    except Exception as e:
        logger.error(f"Error getting lab status {lab_id}: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
