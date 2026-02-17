from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABLE: Blindly trust third-party weather API
@app.route('/api/weather', methods=['GET'])
def get_weather():
    # Simulate third-party weather API
    city = request.args.get('city', 'London')
    
    # In real scenario, would call external API
    # For demo, simulate response
    weather_data = {
        'city': city,
        # VULNERABLE: Malicious HTML from simulated "third-party" API
        # In reality, this would come from external source
        'description': '&lt;script&gt;alert("XSS")&lt;/script&gt; Sunny'  # Malicious data
    }
    
    # VULNERABLE: Return without sanitization!
    return f"<div>Weather in {city}: {weather_data['description']}</div>"

# VULNERABLE: Import user data from external CRM
@app.route('/api/import-users', methods=['POST'])
def import_users():
    # Simulate third-party CRM API response
    crm_data = {
        'users': [
            {'name': "'; DROP TABLE users; --", 'email': 'attacker@evil.com'}  # SQLi payload
        ]
    }
    
    # VULNERABLE: Would insert into DB without validation!
    # db.execute(f"INSERT INTO users VALUES ('{user['name']}')")
    
    return jsonify({'imported': len(crm_data['users']), 'data': crm_data})

# VULNERABLE: Process payment without verifying response
@app.route('/api/process-payment', methods=['POST'])
def process_payment():
    order = request.json
    
    # Simulate payment API call
    # In real attack, attacker intercepts and modifies response
    payment_response = {
        'status': 'success',  # Attacker changed from 'failed' to 'success'
        'amount': 0.01  # Attacker changed from correct amount
    }
    
    # VULNERABLE: Blindly trust response!
    if payment_response['status'] == 'success':
        return jsonify({'access_granted': True, 'message': 'Payment successful'})
    
    return jsonify({'access_granted': False})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
