"""
Scam Shield - Machine Learning Based Scam Detection Using Multi Modal Content Analysis
Flask backend application using Google Gemini API
"""

import os
import base64
import json
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configure Gemini API
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_TEXT_LENGTH = 10000
MAX_URL_LENGTH = 2048


def error_response(reason, status_code=400):
    """Return a normalized JSON error response."""
    return jsonify({
        'prediction': 'Error',
        'confidence': 0,
        'reason': reason,
        'suspicious_parts': []
    }), status_code


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def normalize_url(url):
    """Validate URL and normalize scheme when missing."""
    cleaned = url.strip()
    if not cleaned:
        return None

    if len(cleaned) > MAX_URL_LENGTH:
        return None

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
        cleaned = f'https://{cleaned}'

    parsed = urlparse(cleaned)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return None

    return cleaned


def detect_image_format(image_bytes):
    """Detect image type from file signature (magic bytes)."""
    if image_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if image_bytes.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if image_bytes.startswith((b'GIF87a', b'GIF89a')):
        return 'gif'
    if image_bytes.startswith(b'RIFF') and image_bytes[8:12] == b'WEBP':
        return 'webp'
    return None


def create_scam_detection_prompt(content_type, content):
    """Create a structured prompt for scam detection"""
    base_prompt = """You are an expert scam detection system. Analyze the following content and determine if it is a SCAM or LEGITIMATE.

IMPORTANT: You must respond ONLY with a valid JSON object in this exact format:
{
    "prediction": "Scam" or "Legitimate",
    "confidence": <number between 0 and 1>,
    "reason": "<brief explanation in 1-2 sentences>",
    "suspicious_parts": ["<specific suspicious phrase/pattern>", "..."]
}

Rules for suspicious_parts:
- Include 2-6 concise strings when prediction is "Scam".
- For text, quote exact suspicious words/phrases from the message when possible.
- For URL, include suspicious URL patterns (e.g., typo-domain, odd path, misleading subdomain).
- For image, include visual cues (e.g., fake logo, urgent threat text, payment demand).
- If prediction is "Legitimate", return an empty list.

Analysis criteria for SCAM detection:
- Urgency or pressure tactics ("Act now!", "Limited time!")
- Requests for personal information (passwords, SSN, bank details)
- Suspicious links or URLs with typos/misspellings
- Too good to be true offers (lottery wins, inheritance)
- Grammar and spelling errors
- Impersonation of legitimate organizations
- Threats or fear-based messaging
- Requests for unusual payment methods (gift cards, crypto)
- Phishing attempts
- Fake job offers or investment schemes

"""
    
    if content_type == 'text':
        return base_prompt + f"""
Content Type: TEXT MESSAGE/EMAIL
Content to analyze:
\"\"\"
{content}
\"\"\"

Analyze this text and provide your assessment."""

    elif content_type == 'url':
        return base_prompt + f"""
Content Type: URL/WEBSITE LINK
URL to analyze:
\"\"\"
{content}
\"\"\"

Analyze this URL for potential phishing or scam indicators. Check for:
- Domain reputation and legitimacy
- Suspicious subdomains or typosquatting
- URL structure and patterns
- Known scam patterns

Provide your assessment."""

    elif content_type == 'image':
        return base_prompt + """
Content Type: IMAGE
An image has been provided for analysis.

Analyze this image for scam indicators such as:
- Fake logos or brand impersonation
- Screenshots of suspicious messages
- QR codes leading to scam sites
- Fake receipts or documents
- Phishing page screenshots

Provide your assessment."""

    return base_prompt


def parse_gemini_response(response_text):
    """Parse the Gemini response and extract JSON"""
    try:
        # Try to find JSON in the response
        json_match = re.search(r'\{[^{}]*"prediction"[^{}]*\}', response_text, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            # Validate and normalize the response
            prediction = result.get('prediction', 'Unknown')
            if prediction.lower() in ['scam', 'spam', 'malicious', 'fraudulent']:
                prediction = 'Scam'
            elif prediction.lower() in ['legitimate', 'safe', 'genuine', 'valid']:
                prediction = 'Legitimate'
            
            confidence = float(result.get('confidence', 0.5))
            confidence = max(0, min(1, confidence))  # Clamp between 0 and 1
            
            reason = result.get('reason', 'No explanation provided')
            suspicious_parts = result.get('suspicious_parts', [])

            if not isinstance(suspicious_parts, list):
                suspicious_parts = []

            normalized_parts = [
                str(part).strip()
                for part in suspicious_parts
                if isinstance(part, (str, int, float)) and str(part).strip()
            ][:6]
            
            return {
                'prediction': prediction,
                'confidence': round(confidence, 2),
                'reason': reason,
                'suspicious_parts': normalized_parts
            }
    except (json.JSONDecodeError, ValueError, AttributeError):
        pass
    
    # Fallback parsing if JSON extraction fails
    response_lower = response_text.lower()
    if 'scam' in response_lower or 'fraudulent' in response_lower or 'phishing' in response_lower:
        return {
            'prediction': 'Scam',
            'confidence': 0.7,
            'reason': 'Analysis suggests potential scam indicators present.',
            'suspicious_parts': ['Potential phishing or fraud language detected.']
        }
    elif 'legitimate' in response_lower or 'safe' in response_lower or 'genuine' in response_lower:
        return {
            'prediction': 'Legitimate',
            'confidence': 0.7,
            'reason': 'Analysis suggests content appears legitimate.',
            'suspicious_parts': []
        }
    
    return {
        'prediction': 'Unknown',
        'confidence': 0.5,
        'reason': 'Unable to determine with certainty. Please review manually.',
        'suspicious_parts': []
    }


def analyze_with_gemini(content_type, content, image_data=None):
    """Send content to Gemini API for analysis"""
    if not GEMINI_API_KEY:
        return {
            'prediction': 'Error',
            'confidence': 0,
            'reason': 'Gemini API key not configured. Please set GEMINI_API_KEY in .env file.',
            'suspicious_parts': []
        }
    
    try:
        # Use model from environment variable
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        prompt = create_scam_detection_prompt(content_type, content)
        
        if content_type == 'image' and image_data:
            # For image analysis, include the image
            response = model.generate_content([
                prompt,
                {
                    'mime_type': image_data['mime_type'],
                    'data': image_data['base64']
                }
            ])
        else:
            # For text and URL analysis
            response = model.generate_content(prompt)
        
        if response and response.text:
            return parse_gemini_response(response.text)
        else:
            return {
                'prediction': 'Error',
                'confidence': 0,
                'reason': 'No response received from Gemini API.',
                'suspicious_parts': []
            }
            
    except Exception as e:
        return {
            'prediction': 'Error',
            'confidence': 0,
            'reason': f'API Error: {str(e)}',
            'suspicious_parts': []
        }


@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    """Main prediction endpoint"""
    try:
        content_type = request.form.get('content_type', 'text')
        
        if content_type == 'text':
            content = request.form.get('content', '').strip()
            if not content:
                return error_response('No text content provided.')

            if len(content) > MAX_TEXT_LENGTH:
                return error_response(f'Text is too long. Maximum allowed is {MAX_TEXT_LENGTH} characters.')

            result = analyze_with_gemini('text', content)
            
        elif content_type == 'url':
            url = request.form.get('content', '').strip()
            if not url:
                return error_response('No URL provided.')

            normalized_url = normalize_url(url)
            if not normalized_url:
                return error_response('Please provide a valid URL (example: https://example.com).')

            result = analyze_with_gemini('url', normalized_url)
            
        elif content_type == 'image':
            if 'image' not in request.files:
                return error_response('No image file provided.')
            
            file = request.files['image']
            if file.filename == '':
                return error_response('No image file selected.')
            
            if not allowed_file(file.filename):
                return error_response('Invalid file extension. Allowed: PNG, JPG, JPEG, GIF, WEBP')
            
            # Read and encode image as base64
            image_bytes = file.read()
            if not image_bytes:
                return error_response('Uploaded file is empty.')

            detected_format = detect_image_format(image_bytes)
            if not detected_format:
                return error_response('Invalid image data. Upload a valid PNG, JPEG, GIF, or WEBP file.')

            image_base64 = base64.b64encode(image_bytes).decode('utf-8')
            
            # Determine MIME type
            mime_types = {
                'png': 'image/png',
                'jpeg': 'image/jpeg',
                'gif': 'image/gif',
                'webp': 'image/webp'
            }
            mime_type = mime_types.get(detected_format, 'image/jpeg')
            
            image_data = {
                'base64': image_base64,
                'mime_type': mime_type
            }
            
            result = analyze_with_gemini('image', '', image_data)
            
        else:
            return error_response('Invalid content type specified.')
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.exception('Unhandled error in /predict: %s', e)
        return error_response('Unexpected server error occurred. Please try again.', 500)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'api_configured': bool(GEMINI_API_KEY),
        'model': GEMINI_MODEL
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Scam Shield - ML Based Scam Detection System")
    print("="*60)
    print(f"  API Key Configured: {'Yes' if GEMINI_API_KEY else 'No'}")
    print("  Server starting on http://127.0.0.1:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
