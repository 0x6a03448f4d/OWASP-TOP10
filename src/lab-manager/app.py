#!/usr/bin/env python3
"""
OWASP Lab Manager API
A simple Flask API to manage Docker-based vulnerable labs using Docker CLI
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import os
import logging
import json

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LAB_NETWORK = os.getenv('LAB_NETWORK', 'owasp-network')

# Lab configurations - Auto-generate from structured data
def generate_lab_configs():
    """Generate lab configurations for all OWASP categories"""
    labs = {}
    
    # Web Labs (01-10)
    web_labs = [
        ('01', 'Broken Access Control', 8001, '01-Broken-Access-Control'),
        ('02', 'Cryptographic Failures', 8002, '02-Cryptographic-Failures'),
        ('03', 'Injection', 8003, '03-Injection'),
        ('04', 'Insecure Design', 8004, '04-Insecure-Design'),
        ('05', 'Security Misconfiguration', 8005, '05-Security-Misconfiguration'),
        ('06', 'Vulnerable Components', 8006, '06-Vulnerable-Outdated-Components'),
        ('07', 'Authentication Failures', 8007, '07-Identification-Authentication-Failures'),
        ('08', 'Software & Data Integrity', 8008, '08-Software-Data-Integrity-Failures'),
        ('09', 'Security Logging Failures', 8009, '09-Security-Logging-Monitoring-Failures'),
        ('10', 'SSRF', 8010, '10-Server-Side-Request-Forgery')
    ]
    
    for num, name, port, path in web_labs:
        labs[f'web-{num}'] = {
            'name': name,
            'path': f'./OWASP-Web/{path}/lab',
            'port': port,
            'container': f'owasp-web-lab-{num}'
        }
    
    # API Labs (API01-API10)
    api_labs = [
        ('api01', 'Broken Object Level Authorization', 9001, 'API01-Broken-Object-Level-Authorization'),
        ('api02', 'Broken Authentication', 9002, 'API02-Broken-Authentication'),
        ('api03', 'Broken Object Property Level Authorization', 9003, 'API03-Broken-Object-Property-Level-Authorization'),
        ('api04', 'Unrestricted Resource Consumption', 9004, 'API04-Unrestricted-Resource-Consumption'),
        ('api05', 'Broken Function Level Authorization', 9005, 'API05-Broken-Function-Level-Authorization'),
        ('api06', 'Unrestricted Access to Sensitive Business Flows', 9006, 'API06-Unrestricted-Access-Sensitive-Business-Flows'),
        ('api07', 'Server Side Request Forgery', 9007, 'API07-Server-Side-Request-Forgery'),
        ('api08', 'Security Misconfiguration', 9008, 'API08-Security-Misconfiguration'),
        ('api09', 'Improper Inventory Management', 9009, 'API09-Improper-Inventory-Management'),
        ('api10', 'Unsafe Consumption of APIs', 9010, 'API10-Unsafe-Consumption-of-APIs')
    ]
    
    for num, name, port, path in api_labs:
        labs[f'api-{num}'] = {
            'name': name,
            'path': f'./OWASP-API/{path}/lab',
            'port': port,
            'container': f'owasp-api-lab-{num}'
        }
    
    # Mobile Labs (M01-M10)
    mobile_labs = [
        ('m01', 'Improper Credential Usage', 7001, 'M01-Improper-Credential-Usage'),
        ('m02', 'Inadequate Supply Chain Security', 7002, 'M02-Inadequate-Supply-Chain-Security'),
        ('m03', 'Insecure Authentication/Authorization', 7003, 'M03-Insecure-Authentication-Authorization'),
        ('m04', 'Insufficient Input/Output Validation', 7004, 'M04-Insufficient-Input-Output-Validation'),
        ('m05', 'Insecure Communication', 7005, 'M05-Insecure-Communication'),
        ('m06', 'Inadequate Privacy Controls', 7006, 'M06-Inadequate-Privacy-Controls'),
        ('m07', 'Insufficient Binary Protections', 7007, 'M07-Insufficient-Binary-Protections'),
        ('m08', 'Security Misconfiguration', 7008, 'M08-Security-Misconfiguration'),
        ('m09', 'Insecure Data Storage', 7009, 'M09-Insecure-Data-Storage'),
        ('m10', 'Insufficient Cryptography', 7010, 'M10-Insufficient-Cryptography')
    ]
    
    for num, name, port, path in mobile_labs:
        labs[f'mobile-{num}'] = {
            'name': name,
            'path': f'./OWASP-Mobile/{path}/lab',
            'port': port,
            'container': f'owasp-mobile-lab-{num}'
        }
    
    # LLM Labs (LLM01-LLM10)
    llm_labs = [
        ('llm01', 'Prompt Injection', 6001, 'LLM01-Prompt-Injection'),
        ('llm02', 'Insecure Output Handling', 6002, 'LLM02-Insecure-Output-Handling'),
        ('llm03', 'Training Data Poisoning', 6003, 'LLM03-Training-Data-Poisoning'),
        ('llm04', 'Model Denial of Service', 6004, 'LLM04-Model-Denial-of-Service'),
        ('llm05', 'Supply Chain Vulnerabilities', 6005, 'LLM05-Supply-Chain-Vulnerabilities'),
        ('llm06', 'Sensitive Information Disclosure', 6006, 'LLM06-Sensitive-Information-Disclosure'),
        ('llm07', 'Insecure Plugin Design', 6007, 'LLM07-Insecure-Plugin-Design'),
        ('llm08', 'Excessive Agency', 6008, 'LLM08-Excessive-Agency'),
        ('llm09', 'Overreliance', 6009, 'LLM09-Overreliance'),
        ('llm10', 'Model Theft', 6010, 'LLM10-Model-Theft')
    ]
    
    for num, name, port, path in llm_labs:
        labs[f'llm-{num}'] = {
            'name': name,
            'path': f'./OWASP-LLM/{path}/lab',
            'port': port,
            'container': f'owasp-llm-lab-{num}'
        }
    
    return labs

LABS = generate_lab_configs()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        result = subprocess.run(['docker', 'ps'], capture_output=True, text=True, timeout=5)
        docker_available = result.returncode == 0
    except Exception as e:
        docker_available = False
        logger.error(f"Docker health check failed: {e}")
    
    return jsonify({'status': 'healthy', 'docker': docker_available})

@app.route('/api/labs', methods=['GET'])
def list_labs():
    """List all available labs with their status"""
    labs_status = []
    try:
        # Get all containers using docker CLI
        result = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{.Names}}|||{{.Status}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        running_containers = {}
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line and '|||' in line:
                    name, status = line.split('|||')
                    running_containers[name] = 'running' if 'Up' in status else 'stopped'
        
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
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        # Check if container already exists
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.State.Status}}', container_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            status = result.stdout.strip()
            if status == 'running':
                return jsonify({
                    'status': 'already_running',
                    'message': f"Lab {lab_info['name']} is already running",
                    'url': f"http://localhost:{lab_info['port']}"
                })
            else:
                # Start existing stopped container
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
                    return jsonify({
                        'status': 'error',
                        'message': f"Failed to start container: {result.stderr}"
                    }), 500
        else:
            # Container doesn't exist, auto-build it
            logger.info(f"Container {container_name} not found, attempting auto-build")
            
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
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        result = subprocess.run(
            ['docker', 'stop', container_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info(f"Stopped container: {container_name}")
            return jsonify({
                'status': 'stopped',
                'message': f"Lab {lab_info['name']} stopped successfully"
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f"Failed to stop lab: {result.stderr}"
            }), 500
    except Exception as e:
        logger.error(f"Error stopping lab {lab_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>/status', methods=['GET'])
def lab_status(lab_id):
    """Get status of a specific lab"""
    if lab_id not in LABS:
        return jsonify({'error': 'Lab not found'}), 404
    
    lab_info = LABS[lab_id]
    container_name = lab_info['container']
    
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.State.Status}}', container_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            status = result.stdout.strip()
            return jsonify({
                'id': lab_id,
                'name': lab_info['name'],
                'status': status,
                'port': lab_info['port'],
                'url': f"http://localhost:{lab_info['port']}" if status == 'running' else None
            })
        else:
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
