"""
OWASP Mobile Top 10 - M06: Inadequate Privacy Controls
Educational Vulnerable Application

WARNING: This application contains INTENTIONAL privacy vulnerabilities for educational purposes.
NEVER use these patterns in production applications!

Privacy Violations Demonstrated:
1. Excessive permission requests
2. Background location tracking
3. PII leakage in logs
4. Contact list harvesting
5. Analytics with sensitive data
6. Third-party data sharing
7. No user consent mechanisms
8. Lack of data minimization

Author: OWASP
License: Educational Use Only
"""

from flask import Flask, render_template, request, jsonify
import logging
import json
import random
from datetime import datetime
import hashlib

# Configure logging (INTENTIONALLY verbose for demonstration)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# FAKE DATA STORAGE - For demonstration only
location_history = []
contact_database = []
user_profiles = {}
analytics_events = []
permission_grants = {}

# Startup banner
print("=" * 80)
print("🔓 M06: INADEQUATE PRIVACY CONTROLS - VULNERABLE LAB")
print("=" * 80)
print("⚠️  WARNING: This application demonstrates PRIVACY VIOLATIONS")
print("⚠️  Educational purposes ONLY - DO NOT use in production!")
print("")
print("Privacy Violations Active:")
print("  ❌ Excessive permission requests")
print("  ❌ Background location tracking")
print("  ❌ PII in application logs")
print("  ❌ Contact harvesting")
print("  ❌ No user consent mechanisms")
print("")
print("🌐 Access the lab at: http://localhost:5106")
print("=" * 80)

# ============================================================================
# VULNERABILITY 1: Excessive Permission Requests
# ============================================================================

@app.route('/api/permissions/request', methods=['POST'])
def request_permissions():
    """
    PRIVACY VIOLATION: Request excessive permissions all at once
    
    Issues:
    - Requests 8+ permissions simultaneously
    - No justification for each permission
    - Many permissions unnecessary for core functionality
    - Overwhelming users (dark pattern)
    """
    data = request.get_json()
    requested_permissions = data.get('permissions', [])
    user_id = data.get('user_id', 'demo_user')
    
    # PRIVACY VIOLATION: Log all permission requests with user ID
    logger.info(f"Permission request from user {user_id}")
    logger.info(f"Permissions requested: {requested_permissions}")
    
    # Simulate granting all permissions
    granted_permissions = []
    for permission in requested_permissions:
        granted_permissions.append({
            'permission': permission,
            'granted': True,
            'timestamp': datetime.now().isoformat()
        })
        
        # PRIVACY VIOLATION: Store permission grants
        if user_id not in permission_grants:
            permission_grants[user_id] = {}
        permission_grants[user_id][permission] = {
            'granted': True,
            'timestamp': datetime.now().isoformat()
        }
    
    # PRIVACY VIOLATION: Log granted permissions
    logger.warning(f"⚠️  PRIVACY VIOLATION: All {len(granted_permissions)} permissions granted to {user_id}")
    
    # Analyze excessive permissions
    unnecessary_permissions = []
    if 'sms' in requested_permissions:
        unnecessary_permissions.append('SMS - Not needed for restaurant app')
    if 'phone_state' in requested_permissions:
        unnecessary_permissions.append('Phone State - No legitimate use case')
    if 'calendar' in requested_permissions:
        unnecessary_permissions.append('Calendar - Not required for core features')
    if 'contacts' in requested_permissions:
        unnecessary_permissions.append('Contacts - Should use contact picker instead')
    
    return jsonify({
        'status': 'success',
        'message': f'Granted {len(granted_permissions)} permissions',
        'granted_permissions': granted_permissions,
        'privacy_violations': {
            'excessive_permissions': len(requested_permissions) > 3,
            'unnecessary_permissions': unnecessary_permissions,
            'bundled_request': len(requested_permissions) > 1,
            'no_justification': True
        }
    })

# ============================================================================
# VULNERABILITY 2: Background Location Tracking
# ============================================================================

@app.route('/api/track-location', methods=['POST'])
def track_location():
    """
    PRIVACY VIOLATION: Continuous background location tracking
    
    Issues:
    - Tracks location even when app is in background
    - High frequency updates (every 30-60 seconds)
    - Stores complete location history
    - No user awareness or control
    - Sends additional metadata (battery, network)
    """
    data = request.get_json()
    
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    timestamp = data.get('timestamp', datetime.now().isoformat())
    app_state = data.get('app_state', 'unknown')
    user_id = data.get('user_id', 'demo_user')
    
    # PRIVACY VIOLATION: Log precise location coordinates
    logger.info(f"📍 Location update from user {user_id}")
    logger.info(f"   Coordinates: {latitude}, {longitude}")
    logger.info(f"   App state: {app_state}")
    logger.info(f"   Timestamp: {timestamp}")
    
    # PRIVACY VIOLATION: Store complete location history
    location_entry = {
        'user_id': user_id,
        'latitude': latitude,
        'longitude': longitude,
        'timestamp': timestamp,
        'app_state': app_state,
        'accuracy': data.get('accuracy', 10.0),
        'speed': data.get('speed', 0.0),
        'bearing': data.get('bearing', 0.0),
        'altitude': data.get('altitude', 0.0),
        # PRIVACY VIOLATION: Collect additional metadata
        'battery_level': data.get('battery_level', random.randint(20, 100)),
        'network_type': data.get('network_type', 'wifi'),
        'device_model': data.get('device_model', 'Unknown')
    }
    
    location_history.append(location_entry)
    
    # PRIVACY VIOLATION: Background tracking warning
    if app_state == 'background':
        logger.warning(f"⚠️  PRIVACY VIOLATION: Tracking user {user_id} in BACKGROUND")
        logger.warning(f"   User likely unaware of continuous tracking")
    
    # Simulate sending to third-party data brokers
    logger.warning(f"📤 Simulating data broker transmission for user {user_id}")
    
    return jsonify({
        'status': 'success',
        'message': 'Location tracked',
        'tracking_session': len(location_history),
        'privacy_violations': {
            'background_tracking': app_state == 'background',
            'precise_location': True,
            'metadata_collection': True,
            'permanent_storage': True,
            'third_party_sharing': True
        }
    })

@app.route('/api/location-history', methods=['GET'])
def get_location_history():
    """
    PRIVACY VIOLATION: Expose complete location history
    """
    user_id = request.args.get('user_id', 'demo_user')
    
    # Filter by user
    user_locations = [loc for loc in location_history if loc.get('user_id') == user_id]
    
    # PRIVACY VIOLATION: Log access to location history
    logger.info(f"Location history accessed for user {user_id}")
    logger.info(f"Total locations stored: {len(user_locations)}")
    
    # Analyze location patterns
    if len(user_locations) >= 3:
        logger.warning(f"⚠️  PRIVACY CONCERN: Enough data to infer:")
        logger.warning(f"   - Home location (most common at night)")
        logger.warning(f"   - Work location (most common during day)")
        logger.warning(f"   - Movement patterns and routines")
    
    return jsonify({
        'status': 'success',
        'user_id': user_id,
        'total_locations': len(user_locations),
        'locations': user_locations[-20:],  # Last 20 for brevity
        'privacy_risk': 'CRITICAL' if len(user_locations) > 10 else 'HIGH'
    })

# ============================================================================
# VULNERABILITY 3: PII Leakage in Logs
# ============================================================================

@app.route('/api/user/profile', methods=['POST'])
def update_profile():
    """
    PRIVACY VIOLATION: PII in application logs
    
    Issues:
    - Logs email addresses, names, phone numbers
    - Logs physical addresses
    - Complete user objects in logs
    - Logs sent to third-party services
    """
    data = request.get_json()
    
    user_id = data.get('user_id', 'demo_user')
    email = data.get('email')
    name = data.get('name')
    phone = data.get('phone')
    address = data.get('address')
    date_of_birth = data.get('date_of_birth')
    
    # PRIVACY VIOLATION: Log ALL PII
    logger.info(f"Profile update request for user: {email}")  # Email = PII
    logger.info(f"User details - Name: {name}, Phone: {phone}")  # PII
    logger.info(f"Address: {address}")  # PII
    logger.info(f"Date of Birth: {date_of_birth}")  # PII
    
    # PRIVACY VIOLATION: Store complete profile
    user_profiles[user_id] = {
        'email': email,
        'name': name,
        'phone': phone,
        'address': address,
        'date_of_birth': date_of_birth,
        'updated_at': datetime.now().isoformat()
    }
    
    # PRIVACY VIOLATION: Log complete user object
    logger.debug(f"Stored profile: {json.dumps(user_profiles[user_id])}")
    
    logger.warning(f"⚠️  PRIVACY VIOLATION: PII logged for user {email}")
    logger.warning(f"   Email, name, phone, address all in plaintext logs")
    
    return jsonify({
        'status': 'success',
        'message': 'Profile updated',
        'privacy_violations': {
            'email_in_logs': True,
            'name_in_logs': True,
            'phone_in_logs': True,
            'address_in_logs': True,
            'dob_in_logs': True,
            'complete_profile_logged': True
        }
    })

@app.route('/api/login', methods=['POST'])
def login():
    """
    PRIVACY VIOLATION: Password in logs (CRITICAL)
    
    Issues:
    - CRITICAL: Plaintext password in logs
    - Email address exposure
    - Failed login attempts reveal valid emails
    """
    data = request.get_json()
    
    email = data.get('email')
    password = data.get('password')
    
    # PRIVACY VIOLATION: Log email (PII)
    logger.info(f"Login attempt for email: {email}")
    
    # CRITICAL PRIVACY + SECURITY VIOLATION: Log password!
    logger.debug(f"Password submitted: {password}")
    logger.warning(f"🚨 CRITICAL VIOLATION: Password logged in plaintext!")
    
    # Simulate login
    success = random.choice([True, False])
    
    if success:
        logger.info(f"Login successful for user: {email}")
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'token': hashlib.md5(f"{email}{datetime.now()}".encode()).hexdigest(),
            'privacy_violations': {
                'email_in_logs': True,
                'password_in_logs': True,  # CRITICAL!
                'severity': 'CRITICAL'
            }
        })
    else:
        # PRIVACY VIOLATION: Failed login reveals valid email
        logger.warning(f"Login failed for user: {email} - Invalid password")
        return jsonify({
            'status': 'error',
            'message': 'Invalid credentials'
        }), 401

# ============================================================================
# VULNERABILITY 4: Contact Harvesting
# ============================================================================

@app.route('/api/contacts/upload', methods=['POST'])
def upload_contacts():
    """
    PRIVACY VIOLATION: Mass contact harvesting
    
    Issues:
    - Uploads ALL contacts, not just selected ones
    - Collects excessive data per contact
    - Stores contacts permanently
    - Shares with third-party data brokers
    - Non-users exposed without consent
    """
    data = request.get_json()
    
    user_id = data.get('user_id', 'demo_user')
    contacts = data.get('contacts', [])
    
    # PRIVACY VIOLATION: Log contact count
    logger.info(f"Contact upload from user {user_id}")
    logger.info(f"Number of contacts: {len(contacts)}")
    
    # PRIVACY VIOLATION: Process and store ALL contacts
    for contact in contacts:
        contact_entry = {
            'uploaded_by': user_id,
            'name': contact.get('name'),
            'phones': contact.get('phones', []),
            'emails': contact.get('emails', []),
            'addresses': contact.get('addresses', []),
            'company': contact.get('company'),
            'birthday': contact.get('birthday'),
            'notes': contact.get('notes'),
            'social_profiles': contact.get('social_profiles', []),
            'uploaded_at': datetime.now().isoformat()
        }
        
        contact_database.append(contact_entry)
        
        # PRIVACY VIOLATION: Log individual contact details
        logger.debug(f"Contact: {contact.get('name')} - {contact.get('emails')}")
    
    logger.warning(f"⚠️  PRIVACY VIOLATION: {len(contacts)} contacts harvested from user {user_id}")
    logger.warning(f"   Contact owners never consented to data collection")
    logger.warning(f"   Creating shadow profiles for non-users")
    
    # PRIVACY VIOLATION: Simulate third-party data sharing
    logger.warning(f"📤 Simulating data broker sale: {len(contacts)} contacts")
    logger.warning(f"   Data brokers: advertiser-data.com, people-search.com")
    
    return jsonify({
        'status': 'success',
        'message': f'Uploaded {len(contacts)} contacts',
        'total_contacts_in_db': len(contact_database),
        'privacy_violations': {
            'mass_collection': len(contacts) > 5,
            'non_user_data': True,
            'excessive_data_per_contact': True,
            'third_party_sharing': True,
            'permanent_storage': True,
            'no_consent_mechanism': True,
            'shadow_profiles': True,
            'severity': 'CRITICAL'
        }
    })

@app.route('/api/contacts/database', methods=['GET'])
def view_contact_database():
    """
    PRIVACY VIOLATION: Expose contact database
    """
    logger.info(f"Contact database accessed")
    logger.info(f"Total contacts in database: {len(contact_database)}")
    
    return jsonify({
        'status': 'success',
        'total_contacts': len(contact_database),
        'contacts': contact_database[-10:],  # Last 10 for brevity
        'privacy_concern': 'Contact owners cannot delete their data'
    })

# ============================================================================
# VULNERABILITY 5: Analytics with PII
# ============================================================================

@app.route('/api/analytics/track', methods=['POST'])
def track_analytics():
    """
    PRIVACY VIOLATION: Send PII to analytics services
    
    Issues:
    - Sends email, name, phone to third-party analytics
    - No anonymization
    - User identifiers shared
    - Behavioral profiling enabled
    """
    data = request.get_json()
    
    event_name = data.get('event', 'unknown_event')
    user_email = data.get('user_email')
    user_name = data.get('user_name')
    user_phone = data.get('user_phone')
    properties = data.get('properties', {})
    
    # PRIVACY VIOLATION: Log analytics event with PII
    logger.info(f"Analytics event: {event_name}")
    logger.info(f"User: {user_email} ({user_name})")  # PII
    logger.info(f"Phone: {user_phone}")  # PII
    logger.info(f"Properties: {json.dumps(properties)}")
    
    # PRIVACY VIOLATION: Store analytics with PII
    analytics_event = {
        'event': event_name,
        'user_email': user_email,  # PII sent to third party
        'user_name': user_name,    # PII
        'user_phone': user_phone,  # PII
        'properties': properties,
        'timestamp': datetime.now().isoformat(),
        'user_agent': request.headers.get('User-Agent'),
        'ip_address': request.remote_addr  # PII
    }
    
    analytics_events.append(analytics_event)
    
    logger.warning(f"⚠️  PRIVACY VIOLATION: PII sent to analytics service")
    logger.warning(f"   Email, name, phone shared with third party")
    logger.warning(f"   Data can be used for cross-site tracking")
    
    return jsonify({
        'status': 'success',
        'message': 'Analytics event tracked',
        'privacy_violations': {
            'pii_in_analytics': True,
            'third_party_sharing': True,
            'cross_site_tracking_enabled': True,
            'no_anonymization': True,
            'user_profiling_enabled': True
        }
    })

# ============================================================================
# VULNERABILITY 6: No Consent Management
# ============================================================================

@app.route('/api/privacy/consent', methods=['GET'])
def get_consent_status():
    """
    PRIVACY VIOLATION: No consent mechanism implemented
    """
    return jsonify({
        'status': 'error',
        'message': 'No consent management system implemented',
        'privacy_violations': {
            'no_consent_ui': True,
            'no_opt_out': True,
            'no_data_deletion': True,
            'no_data_export': True,
            'gdpr_violation': True,
            'ccpa_violation': True
        }
    })

# ============================================================================
# Privacy Violation Summary
# ============================================================================

@app.route('/api/privacy/violations', methods=['GET'])
def privacy_violations_summary():
    """
    Summary of all privacy violations in this application
    """
    violations = {
        'excessive_permissions': {
            'severity': 'HIGH',
            'description': 'Requests 8+ permissions simultaneously without justification',
            'impact': 'User overwhelmed, grants without reading',
            'compliance': 'Violates GDPR consent requirements'
        },
        'background_tracking': {
            'severity': 'CRITICAL',
            'description': 'Continuous location tracking even when app in background',
            'impact': 'Complete user movement history, home/work locations revealed',
            'compliance': 'Violates GDPR purpose limitation, CCPA disclosure requirements'
        },
        'pii_in_logs': {
            'severity': 'CRITICAL',
            'description': 'Email, name, phone, passwords logged in plaintext',
            'impact': 'PII exposed to anyone with log access, sent to third-party logging services',
            'compliance': 'Violates GDPR data protection principles'
        },
        'contact_harvesting': {
            'severity': 'CRITICAL',
            'description': 'Entire contact list uploaded, non-users exposed without consent',
            'impact': 'Shadow profiles created, data sold to brokers, relationship graphs built',
            'compliance': 'Violates GDPR (no legal basis), creates liability for non-user data'
        },
        'analytics_pii': {
            'severity': 'HIGH',
            'description': 'PII sent to third-party analytics without anonymization',
            'impact': 'Cross-site tracking, behavioral profiling, data resold',
            'compliance': 'Violates GDPR data minimization, CCPA disclosure'
        },
        'no_consent': {
            'severity': 'HIGH',
            'description': 'No consent management, opt-out, or user controls',
            'impact': 'Users cannot exercise privacy rights, forced data collection',
            'compliance': 'Violates GDPR Articles 7, 15-22; CCPA consumer rights'
        },
        'no_data_deletion': {
            'severity': 'MEDIUM',
            'description': 'No ability for users to delete their data',
            'impact': 'Permanent data retention, no right to erasure',
            'compliance': 'Violates GDPR Article 17 (Right to Erasure), CCPA deletion rights'
        },
        'third_party_sharing': {
            'severity': 'HIGH',
            'description': 'Data shared with data brokers without disclosure',
            'impact': 'User data monetized, used by unknown parties',
            'compliance': 'Violates GDPR transparency, CCPA "Do Not Sell"'
        }
    }
    
    statistics = {
        'total_violations': len(violations),
        'critical_violations': sum(1 for v in violations.values() if v['severity'] == 'CRITICAL'),
        'high_violations': sum(1 for v in violations.values() if v['severity'] == 'HIGH'),
        'location_tracking_sessions': len(location_history),
        'contacts_harvested': len(contact_database),
        'analytics_events_with_pii': len(analytics_events),
        'users_tracked': len(set(loc.get('user_id') for loc in location_history))
    }
    
    return jsonify({
        'violations': violations,
        'statistics': statistics,
        'regulatory_risk': 'CRITICAL',
        'estimated_gdpr_fine': 'Up to €20M or 4% of global revenue',
        'estimated_ccpa_fine': '$2,500-$7,500 per violation',
        'recommendation': 'Implement privacy-by-design principles immediately'
    })

# ============================================================================
# Health Check
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'M06 Privacy Controls Lab',
        'version': '1.0.0'
    })

# ============================================================================
# Main Interface
# ============================================================================

@app.route('/')
def index():
    """Main demo page"""
    return render_template('index.html')

# ============================================================================
# Application Startup
# ============================================================================

if __name__ == '__main__':
    # SECURITY NOTE: Debug mode enabled for EDUCATIONAL LAB ONLY
    # This is an intentionally vulnerable application for learning purposes.
    # 
    # In production applications:
    # - NEVER use debug=True (exposes arbitrary code execution risk)
    # - Set FLASK_ENV=production
    # - Use proper WSGI server (gunicorn, uWSGI)
    # - Implement proper error handling
    # 
    # This lab demonstrates privacy violations, not production deployment.
    app.run(host='0.0.0.0', port=5000, debug=True)  # nosec B201 - Educational lab only
