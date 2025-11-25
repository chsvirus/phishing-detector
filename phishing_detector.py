"""
Phishing URL Detection System - Backend Server
Created for ESP32-CAM Project
"""

from flask import Flask, request, jsonify
import re
from urllib.parse import urlparse
import socket

app = Flask(__name__)

class PhishingDetector:
    def __init__(self):
        # Common phishing patterns
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'banking', 'paypal', 'amazon', 'apple', 'microsoft',
            'suspended', 'locked', 'unusual', 'clicked'
        ]
        
        self.dangerous_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address instead of domain
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+',  # Multiple hyphens
            r'@',  # @ symbol (URL obfuscation)
        ]
        
        self.trusted_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'github.com', 'stackoverflow.com', 'wikipedia.org'
        ]
    
    def analyze_url(self, url):
        """
        Analyze URL and return risk level
        Returns: dict with status, risk_level, and reasons
        """
        if not url or not isinstance(url, str):
            return {
                'status': 'error',
                'risk_level': 'unknown',
                'message': 'Invalid URL provided'
            }
        
        # Add http:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
            
            risk_score = 0
            reasons = []
            
            # Check 1: HTTPS
            if not url.startswith('https://'):
                risk_score += 20
                reasons.append("No HTTPS encryption")
            
            # Check 2: Trusted domain
            is_trusted = any(trusted in domain for trusted in self.trusted_domains)
            if is_trusted:
                risk_score -= 30
                reasons.append("Trusted domain")
            
            # Check 3: IP address in URL
            if re.search(self.dangerous_patterns[0], domain):
                risk_score += 40
                reasons.append("Uses IP address instead of domain name")
            
            # Check 4: Suspicious keywords
            keyword_count = sum(1 for keyword in self.suspicious_keywords 
                              if keyword in full_url)
            if keyword_count >= 2:
                risk_score += 30
                reasons.append(f"Contains {keyword_count} suspicious keywords")
            elif keyword_count == 1:
                risk_score += 15
                reasons.append("Contains suspicious keyword")
            
            # Check 5: Excessive hyphens
            if domain.count('-') > 2:
                risk_score += 25
                reasons.append("Excessive hyphens in domain")
            
            # Check 6: URL length
            if len(url) > 75:
                risk_score += 15
                reasons.append("Unusually long URL")
            
            # Check 7: @ symbol (obfuscation technique)
            if '@' in url:
                risk_score += 35
                reasons.append("Contains @ symbol (possible obfuscation)")
            
            # Check 8: Subdomain count
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                risk_score += 20
                reasons.append("Too many subdomains")
            
            # Determine risk level
            if risk_score >= 60:
                risk_level = 'dangerous'
                status = 'DANGEROUS - Likely Phishing!'
                color = 'red'
            elif risk_score >= 30:
                risk_level = 'suspicious'
                status = 'SUSPICIOUS - Proceed with Caution'
                color = 'yellow'
            else:
                risk_level = 'safe'
                status = 'SAFE - URL appears legitimate'
                color = 'green'
            
            return {
                'status': 'success',
                'risk_level': risk_level,
                'risk_score': risk_score,
                'message': status,
                'color': color,
                'url': url,
                'domain': domain,
                'reasons': reasons if reasons else ['No suspicious patterns detected']
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'risk_level': 'unknown',
                'message': f'Error analyzing URL: {str(e)}'
            }

# Initialize detector
detector = PhishingDetector()

@app.route('/')
def home():
    return """
    <h1>🛡️ Phishing URL Detection System</h1>
    <p>ESP32-CAM Backend Server</p>
    <p>Status: <strong style="color: green;">Online</strong></p>
    <hr>
    <h3>API Endpoints:</h3>
    <ul>
        <li><code>POST /api/check</code> - Check URL for phishing</li>
        <li><code>GET /api/test</code> - Test the API</li>
    </ul>
    <hr>
    <h3>Test the API:</h3>
    <form action="/api/check" method="post">
        <input type="text" name="url" placeholder="Enter URL to check" size="50">
        <button type="submit">Check URL</button>
    </form>
    """

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        'status': 'success',
        'message': 'API is working!',
        'server': 'Phishing Detection System v1.0'
    })

@app.route('/api/check', methods=['POST'])
def check_url():
    """
    API endpoint to check URL for phishing
    Accepts: JSON with 'url' field or form data
    Returns: JSON with analysis results
    """
    # Try to get URL from JSON or form data
    if request.is_json:
        data = request.get_json()
        url = data.get('url', '')
    else:
        url = request.form.get('url', '')
    
    if not url:
        return jsonify({
            'status': 'error',
            'message': 'No URL provided'
        }), 400
    
    # Analyze URL
    result = detector.analyze_url(url)
    
    return jsonify(result)

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    
    local_ip = get_local_ip()
    print("\n" + "="*60)
    print("🛡️  PHISHING URL DETECTION SYSTEM")
    print("="*60)
    print(f"✅ Server starting on port: {port}")
    print(f"✅ Local access: http://127.0.0.1:{port}")
    print("="*60)
    print("\n🔧 API Endpoint: POST /api/check")
    print("   Body: {'url': 'website-to-check.com'}")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=False)
