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
    docker_client = docker.from_env()
    logger.info("Docker client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Docker client: {e}")
    docker_client = None

LAB_NETWORK = os.getenv('LAB_NETWORK', 'owasp-network')

# Lab configurations
LABS = {
    'web-01': {
        'name': 'Broken Access Control',
        'path': './OWASP-Web/01-Broken-Access-Control/lab',
        'port': 8001,
        'container': 'owasp-web-lab-01'
    },
    'web-03': {
        'name': 'Injection',
        'path': './OWASP-Web/03-Injection/lab',
        'port': 8003,
        'container': 'owasp-web-lab-03'
    },
    'api-01': {
        'name': 'Broken Object Level Authorization',
        'path': './OWASP-API/API01-Broken-Object-Level-Authorization/lab',
        'port': 9001,
        'container': 'owasp-api-lab-01'
    },
    'api-04': {
        'name': 'Unrestricted Resource Consumption',
        'path': './OWASP-API/API04-Unrestricted-Resource-Consumption/lab',
        'port': 9004,
        'container': 'owasp-api-lab-04'
    },
    'mobile-01': {
        'name': 'Improper Credential Usage',
        'path': './OWASP-Mobile/M01-Improper-Credential-Usage/lab',
        'port': 7001,
        'container': 'owasp-mobile-lab-01'
    },
    'llm-01': {
        'name': 'Prompt Injection',
        'path': './OWASP-LLM/LLM01-Prompt-Injection/lab',
        'port': 6001,
        'container': 'owasp-llm-lab-01'
    }
}

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
                # Run docker-compose up -d
                result = subprocess.run(
                    ['docker-compose', 'up', '-d'],
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
