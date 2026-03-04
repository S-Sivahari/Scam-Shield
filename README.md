# Scam Shield

## Machine Learning Based Scam Detection Using Multi-Modal Content Analysis

A Flask web application that uses Google Gemini AI to detect scams in text messages, URLs, and images.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![Gemini](https://img.shields.io/badge/Google-Gemini%20AI-orange.svg)

---

## Features

- **Text Analysis**: Analyze SMS messages, emails, and other text content for scam indicators
- **URL Analysis**: Check suspicious URLs for phishing and scam patterns
- **Image Analysis**: Upload screenshots or images to detect visual scam indicators
- **Real-time Results**: Get instant AI-powered analysis without page reloading
- **Confidence Scoring**: See how confident the AI is in its prediction (0-100%)
- **Detailed Reasoning**: Understand why content was classified as scam or legitimate

---

## Project Structure

```
Scam/
├── app.py                 # Flask backend application
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (API key)
├── .env.example          # Example environment file
├── README.md             # This file
├── templates/
│   └── index.html        # Frontend HTML template
└── static/
    └── style.css         # Custom CSS styles
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key ([Get one here](https://aistudio.google.com/app/apikey))

### Step 1: Clone or Navigate to the Project

```bash
cd d:\Projects\Scam
```

### Step 2: Create a Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Edit the `.env` file and add your Gemini API key:

```env
GEMINI_API_KEY=your_actual_api_key_here
```

---

## Running the Application

### Development Server

```bash
python app.py
```

The application will start at: **http://127.0.0.1:5000**

### Production Server (Windows)

```bash
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

### Production Server (Linux/macOS)

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## Usage

1. **Open the Application**: Navigate to `http://127.0.0.1:5000` in your browser

2. **Select Content Type**:
   - **Text/SMS**: For analyzing text messages or emails
   - **URL**: For checking suspicious links
   - **Image**: For analyzing screenshots or images

3. **Enter/Upload Content**:
   - Paste text content in the text area
   - Enter a URL in the URL field
   - Click or drag to upload an image

4. **Click "Analyze with AI"**: The system will send your content to Gemini AI for analysis

5. **View Results**:
   - **Prediction**: Scam or Legitimate
   - **Confidence Score**: How confident the AI is (0-100%)
   - **Reasoning**: Brief explanation of why

---

## API Endpoints

### POST `/predict`

Analyze content for scam detection.

**Request (Form Data):**

| Field | Type | Description |
|-------|------|-------------|
| `content_type` | string | `text`, `url`, or `image` |
| `content` | string | Text content or URL (for text/url types) |
| `image` | file | Image file (for image type) |

**Response (JSON):**

```json
{
    "prediction": "Scam",
    "confidence": 0.92,
    "reason": "Message contains urgent language and requests personal information."
}
```

### GET `/health`

Health check endpoint.

**Response:**

```json
{
    "status": "healthy",
    "api_configured": true
}
```

---

## Example Scam Indicators Detected

- Urgency or pressure tactics
- Requests for personal information
- Suspicious or misspelled URLs
- Too-good-to-be-true offers
- Grammar and spelling errors
- Impersonation of legitimate organizations
- Threats or fear-based messaging
- Unusual payment method requests
- Phishing attempts
- Fake job offers or investment schemes

---

## Technology Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **UI Framework**: Bootstrap 5.3
- **Icons**: Bootstrap Icons
- **AI**: Google Gemini 1.5 Flash
- **API Communication**: Fetch API (async)

---

## Security Notes

- Never share your API key publicly
- The `.env` file is gitignored by default
- Images are processed in memory and not stored
- Maximum file upload size is 16MB

---

## Troubleshooting

### "Gemini API key not configured"
- Make sure your `.env` file exists and contains `GEMINI_API_KEY=your_key`
- Restart the Flask server after adding the key

### "API Error" messages
- Verify your API key is valid
- Check your internet connection
- Ensure you haven't exceeded API rate limits

### Images not uploading
- Check file size (max 16MB)
- Ensure file format is supported (PNG, JPG, JPEG, GIF, WEBP)

---

## License

This project is for educational and research purposes.

---

## Disclaimer

This tool is designed to assist in identifying potential scams but should not be used as the sole method for determining legitimacy. Always exercise caution and verify information through official channels.
