from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html', vuln_name='Data and Model Poisoning')

@app.route('/api/chat', methods=['POST'])
def chat():
    user_input = request.json.get('message', '')
    
    # Vulnerable: No validation (for educational purposes)
    response = simulate_llm_response(user_input)
    
    return jsonify({'response': response})

def simulate_llm_response(prompt):
    # Simulated LLM behavior showing vulnerability
    if 'ignore previous' in prompt.lower():
        return "SYSTEM PROMPT EXPOSED: You are a helpful assistant..."
    return f"Processing: {prompt}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
