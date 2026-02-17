#!/usr/bin/env python3
"""
OWASP Lab Manager API
A simple Flask API to manage Docker-based vulnerable labs
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import os
import logging
import json
import yaml
import tempfile
import shutil

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test Docker connectivity using CLI
def test_docker_connection():
    """Test if Docker CLI is available and working"""
    try:
        result = subprocess.run(
            ['docker', 'version', '--format', '{{.Server.Version}}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            logger.info(f"Docker connection OK - Server version: {version}")
            return True
        else:
            logger.error(f"Docker connection failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Failed to connect to Docker: {e}")
        return False

# Check Docker connectivity at startup
docker_available = test_docker_connection()

LAB_NETWORK = os.getenv('LAB_NETWORK', 'owasp-network')

def extract_port_from_compose(compose_file):
    """
    Extract the host port from a docker-compose.yml file
    Returns the port number or None if not found
    """
    try:
        with open(compose_file, 'r') as f:
            compose_data = yaml.safe_load(f)
        
        # Look for the first service with ports
        if 'services' in compose_data:
            for service_name, service_config in compose_data['services'].items():
                if 'ports' in service_config and service_config['ports']:
                    # Get first port mapping
                    port_mapping = service_config['ports'][0]
                    if isinstance(port_mapping, str):
                        # Format: "8080:80" - extract host port
                        host_port = port_mapping.split(':')[0]
                        return int(host_port)
                    elif isinstance(port_mapping, dict):
                        # Format: {published: 8080, target: 80}
                        return int(port_mapping.get('published', port_mapping.get('target')))
        
        logger.warning(f"No port found in {compose_file}")
        return None
    except Exception as e:
        logger.error(f"Error extracting port from {compose_file}: {e}")
        return None

def rewrite_compose_with_absolute_paths(compose_file, compose_dir, host_compose_dir, temp_dir):
    """
    Read a docker-compose.yml file and rewrite paths with absolute paths.
    
    CRITICAL: In DooD (Docker-out-of-Docker), there are two types of paths:
    
    1. BUILD CONTEXTS: Read by Docker CLI (running INSIDE container)
       - Must use absolute CONTAINER paths (/workspace/...)
       - Since override file is in /tmp/, relative paths don't work
       - Must convert to absolute container paths using compose_dir
    
    2. VOLUMES: Read by Docker daemon (running on HOST)
       - Must use absolute host paths (/Users/admin/project/...)
       - Docker daemon can't see container paths like /workspace/...
       - Must convert using host_compose_dir
    
    Args:
        compose_file: Path to the original docker-compose.yml
        compose_dir: Container path to the lab directory (e.g., /workspace/...)
        host_compose_dir: Host path to the lab directory (e.g., /Users/admin/...)
        temp_dir: Temporary directory to write the override file
    
    Returns: path to the temporary compose file with modified paths
    """
    try:
        with open(compose_file, 'r') as f:
            compose_data = yaml.safe_load(f)
        
        # Process each service
        if 'services' in compose_data:
            for service_name, service_config in compose_data['services'].items():
                # Fix build contexts
                # Since the override file is in /tmp/, relative paths would be resolved
                # from /tmp/ instead of the lab directory. We need absolute CONTAINER paths.
                # Build contexts are read by Docker CLI inside the container, so use
                # container paths (compose_dir = /workspace/...)
                if 'build' in service_config:
                    build_config = service_config['build']
                    if isinstance(build_config, dict) and 'context' in build_config:
                        context = build_config['context']
                        if context.startswith('./') or context == '.':
                            # Convert relative path to absolute container path
                            rel_path = context.lstrip('./')
                            abs_context = os.path.join(compose_dir, rel_path)
                            service_config['build']['context'] = abs_context
                            logger.info(f"Converted build context to container path: {abs_context}")
                    elif isinstance(build_config, str):
                        # Build config is just a context string
                        if build_config.startswith('./') or build_config == '.':
                            rel_path = build_config.lstrip('./')
                            abs_context = os.path.join(compose_dir, rel_path)
                            service_config['build'] = abs_context
                            logger.info(f"Converted build context to container path: {abs_context}")
                
                # Fix volume mounts
                if 'volumes' in service_config:
                    new_volumes = []
                    for volume in service_config['volumes']:
                        if isinstance(volume, str):
                            parts = volume.split(':')
                            if len(parts) >= 2:
                                source = parts[0]
                                # Only rewrite if it's a relative path
                                if source.startswith('./') or source.startswith('.'):
                                    rel_path = source.lstrip('./')
                                    abs_source = os.path.join(host_compose_dir, rel_path)
                                    parts[0] = abs_source
                                    new_volumes.append(':'.join(parts))
                                else:
                                    new_volumes.append(volume)
                            else:
                                new_volumes.append(volume)
                        else:
                            new_volumes.append(volume)
                    service_config['volumes'] = new_volumes
        
        # Write the modified compose to a temporary file
        temp_compose = os.path.join(temp_dir, 'docker-compose.override.yml')
        with open(temp_compose, 'w') as f:
            yaml.dump(compose_data, f, default_flow_style=False)
        
        logger.info(f"Created temporary compose file with absolute volume paths: {temp_compose}")
        return temp_compose
    
    except Exception as e:
        logger.error(f"Error rewriting compose file: {e}")
        raise

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
                
                # Try to find the actual port from docker-compose.yml
                port = cat_info['base_port'] + port_offset  # Default fallback
                try:
                    # Look for docker-compose.yml in lab subdirectories
                    for item in os.listdir(lab_path):
                        item_path = os.path.join(lab_path, item)
                        if os.path.isdir(item_path):
                            compose_file = os.path.join(item_path, 'docker-compose.yml')
                            if os.path.exists(compose_file):
                                extracted_port = extract_port_from_compose(compose_file)
                                if extracted_port:
                                    port = extracted_port
                                    break
                except Exception as e:
                    logger.warning(f"Could not extract port for {lab_id}: {e}")
                
                labs[lab_id] = {
                    'name': lab_name,
                    'path': lab_path,
                    'port': port,
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
    return jsonify({'status': 'healthy', 'docker': docker_available})

@app.route('/api/labs', methods=['GET'])
def list_labs():
    """List all available labs with their status"""
    if not docker_available:
        return jsonify({'error': 'Docker not available'}), 500
    
    labs_status = []
    try:
        # Get all containers using Docker CLI
        result = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{json .}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        running_containers = {}
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        container_info = json.loads(line)
                        name = container_info.get('Names', '')
                        status = container_info.get('State', 'unknown')
                        running_containers[name] = status
                    except json.JSONDecodeError:
                        continue
        
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
    """Start a specific lab using docker compose CLI"""
    if not docker_available:
        return jsonify({'error': 'Docker not available'}), 500
    
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        # Check if container already exists and is running
        result = subprocess.run(
            ['docker', 'ps', '--filter', f'name={container_name}', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and container_name in result.stdout:
            return jsonify({
                'status': 'already_running',
                'message': f"Lab {lab_info['name']} is already running",
                'url': f"http://localhost:{lab_info['port']}"
            })
        
        # Check if container exists but is stopped
        result = subprocess.run(
            ['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and container_name in result.stdout:
            # Container exists but is stopped, start it
            logger.info(f"Starting existing container: {container_name}")
            result = subprocess.run(
                ['docker', 'start', container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"Started existing container: {container_name}")
                return jsonify({
                    'status': 'started',
                    'message': f"Lab {lab_info['name']} started successfully",
                    'url': f"http://localhost:{lab_info['port']}"
                })
            else:
                logger.error(f"Failed to start container: {result.stderr}")
                # Try rebuilding below
        
        # Container doesn't exist, build it with docker compose
        logger.info(f"Container {container_name} not found, attempting auto-build with docker compose")
        
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
        
        # Build and start using docker compose
        compose_dir = os.path.dirname(compose_file)
        logger.info(f"Auto-building lab from: {compose_dir}")
        logger.info(f"Compose file: {compose_file}")
        
        # Calculate the actual host path for docker compose
        # The container sees /workspace but the host sees HOST_PROJECT_ROOT
        host_project_root = os.environ.get('HOST_PROJECT_ROOT', os.path.abspath('.'))
        container_project_root = os.path.abspath('.')  # This is /workspace inside container
        
        # Convert container path to host path
        relative_path = os.path.relpath(compose_dir, container_project_root)
        host_compose_dir = os.path.join(host_project_root, relative_path)
        
        logger.info(f"Container compose dir: {compose_dir}")
        logger.info(f"Host compose dir: {host_compose_dir}")
        
        # Create a temporary directory for the modified compose file
        temp_dir = tempfile.mkdtemp(prefix='owasp_lab_')
        
        try:
            # Rewrite the compose file with absolute paths for both build contexts and volumes
            # This solves the DooD path resolution issue when override file is in /tmp/
            temp_compose_file = rewrite_compose_with_absolute_paths(
                compose_file, 
                compose_dir,  # Container path for build contexts
                host_compose_dir,  # Host path for volumes
                temp_dir
            )
            
            logger.info(f"Using temporary compose file: {temp_compose_file}")
            
            # Run docker compose with the rewritten file
            # Use -p flag to specify consistent project name and avoid ghost containers
            # This prevents "port already allocated" errors when override file is in random /tmp/ directory
            project_name = f"owasp-lab-{lab_id}"
            env = os.environ.copy()
            
            result = subprocess.run(
                ['docker', 'compose', '-p', project_name, '-f', temp_compose_file, 'up', '-d', '--build'],
                cwd=compose_dir,  # Still run from compose directory for context
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                env=env
            )
            
            logger.info(f"Using project name: {project_name}")
            
            if result.returncode == 0:
                logger.info(f"Successfully built and started lab: {container_name}")
                
                # Extract the actual port from the original compose file
                actual_port = extract_port_from_compose(compose_file)
                if actual_port:
                    logger.info(f"Lab is running on port: {actual_port}")
                    lab_info['port'] = actual_port  # Update with actual port
                
                return jsonify({
                    'status': 'started',
                    'message': f"Lab {lab_info['name']} built and started successfully",
                    'url': f"http://localhost:{lab_info['port']}",
                    'port': lab_info['port'],  # Explicitly include port
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
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Could not clean up temp directory {temp_dir}: {e}")
        
    except Exception as e:
        logger.error(f"Error starting lab {lab_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>/stop', methods=['POST'])
def stop_lab(lab_id):
    """Stop a specific lab using docker compose down with project name"""
    if not docker_available:
        return jsonify({'error': 'Docker not available'}), 500
    
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    project_name = f"owasp-lab-{lab_id}"
    
    try:
        # Find the lab path and compose file
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
            logger.warning(f"No docker-compose file found for {lab_id}, trying direct docker stop")
            # Fallback to direct docker stop if no compose file
            container_name = lab_info['container']
            result = subprocess.run(
                ['docker', 'stop', container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return jsonify({
                    'status': 'stopped',
                    'message': f"Lab {lab_info['name']} stopped successfully"
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'No docker-compose file found and direct stop failed'
                }), 404
        
        # Stop using docker compose down with the same project name used to start
        compose_dir = os.path.dirname(compose_file)
        logger.info(f"Stopping lab {lab_id} (project: {project_name}) from: {compose_dir}")
        
        result = subprocess.run(
            ['docker', 'compose', '-p', project_name, '-f', compose_file, 'down'],
            cwd=compose_dir,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully stopped lab: {lab_id} (project: {project_name})")
            return jsonify({
                'status': 'stopped',
                'message': f"Lab {lab_info['name']} stopped successfully"
            })
        else:
            logger.error(f"Failed to stop lab {lab_id}: {result.stderr}")
            return jsonify({
                'status': 'error',
                'message': f"Failed to stop lab: {result.stderr}"
            }), 500
            
    except Exception as e:
        logger.error(f"Error stopping lab {lab_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>/status', methods=['GET'])
def lab_status(lab_id):
    """Get status of a specific lab using docker CLI"""
    if not docker_available:
        return jsonify({'error': 'Docker not available'}), 500
    
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        # Check if container exists
        result = subprocess.run(
            ['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{json .}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                container_info = json.loads(result.stdout.strip())
                status = container_info.get('State', 'unknown')
                
                return jsonify({
                    'id': lab_id,
                    'name': lab_info['name'],
                    'status': status,
                    'port': lab_info['port'],
                    'url': f"http://localhost:{lab_info['port']}" if status == 'running' else None
                })
            except json.JSONDecodeError:
                pass
        
        # Container not found
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
