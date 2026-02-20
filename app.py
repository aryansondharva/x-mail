from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
import numpy as np
import re
import base64
from email import policy
from email.parser import BytesParser
from datetime import datetime
import ipaddress
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib
from nltk.corpus import stopwords
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import nltk
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

app = Flask(__name__)

# Enable CORS
CORS(app)

# Initialize rate limiter after app creation
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"]
)

# Setup comprehensive logging
def setup_logging():
    """Configure logging for the application"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Main application log
    app_handler = RotatingFileHandler('logs/xmail.log', maxBytes=10240000, backupCount=10)
    app_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    app_handler.setLevel(logging.INFO)
    app.logger.addHandler(app_handler)
    app.logger.setLevel(logging.INFO)
    
    # Security log
    security_handler = RotatingFileHandler('logs/security.log', maxBytes=10240000, backupCount=10)
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s SECURITY: %(message)s [IP: %(client_ip)s]'
    ))
    security_handler.setLevel(logging.WARNING)
    
    # Create security logger
    security_logger = logging.getLogger('security')
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    # Model performance log
    model_handler = RotatingFileHandler('logs/model.log', maxBytes=10240000, backupCount=5)
    model_handler.setFormatter(logging.Formatter(
        '%(asctime)s MODEL: %(message)s'
    ))
    model_handler.setLevel(logging.INFO)
    
    # Create model logger
    model_logger = logging.getLogger('model')
    model_logger.addHandler(model_handler)
    model_logger.setLevel(logging.INFO)
    
    return security_logger, model_logger

security_logger, model_logger = setup_logging()

# Download NLTK data
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

# Load stopwords
STOPWORDS = set(stopwords.words("english"))

import bleach
from html import unescape

def validate_and_sanitize_email(email_body):
    if not email_body or not isinstance(email_body, str):
        raise ValueError("Email content must be a non-empty string")
    
    if len(email_body.strip()) < 5:
        raise ValueError("Email content is too short for meaningful analysis")
    
    if len(email_body) > 50000:
        raise ValueError("Email content is too long (max 50,000 characters)")
    
    sanitized = bleach.clean(
        email_body, 
        tags=[], 
        attributes={}, 
        strip=True
    )
    
    sanitized = unescape(sanitized)
    
    if len(sanitized.strip()) < 5:
        raise ValueError("Email content contains insufficient valid text after sanitization")
    
    return sanitized

def clean_email_body(email_body):
    try:
        sanitized_body = validate_and_sanitize_email(email_body)
    except ValueError as e:
        raise ValueError(str(e))
    
    cleaned_body = re.sub(r'[^a-zA-Z\s]', '', sanitized_body)
    cleaned_body = ' '.join([word.lower() for word in cleaned_body.split() if word.lower() not in STOPWORDS])
    
    if len(cleaned_body.strip()) < 3:
        raise ValueError("Email content contains insufficient meaningful text after processing")
    
    return cleaned_body

def extract_url_features(email_body):
    urls = re.findall(r'(https?://[^\s]+)', email_body)
    features = []
    
    for url in urls:
        parsed_url = urlparse(url)
        domain_length = len(parsed_url.netloc)
        path_length = len(parsed_url.path)
        protocol = 1 if parsed_url.scheme in ['http', 'https'] else 0
        
        features.extend([domain_length, path_length, protocol])
        
        try:
            response = requests.get(url, timeout=3)
            features.append(response.status_code)
        except:
            features.append(0)
    
    return np.mean(features) if features else 0

def extract_email_headers(email_content):
    """Extract and analyze email headers for phishing indicators"""
    header_features = {}
    
    try:
        # Try to parse as raw email with headers
        if '--' in email_content and 'Content-Type:' in email_content:
            # Parse as MIME email
            msg = BytesParser(policy=policy.default).parsebytes(email_content.encode('utf-8'))
            
            # Extract common headers
            header_features['from_domain'] = extract_domain_from_email(msg.get('From', ''))
            header_features['reply_to_domain'] = extract_domain_from_email(msg.get('Reply-To', ''))
            header_features['return_path_domain'] = extract_domain_from_email(msg.get('Return-Path', ''))
            header_features['received_count'] = len(msg.get_all('Received') or [])
            header_features['has_authentication'] = bool(msg.get('Authentication-Results') or msg.get('DKIM-Signature') or msg.get('SPF'))
            header_features['subject_length'] = len(msg.get('Subject', ''))
            header_features['has_attachments'] = 'attachment' in msg.get('Content-Type', '').lower()
            
            # Check for suspicious patterns
            subject = msg.get('Subject', '').lower()
            header_features['urgent_keywords'] = int(any(keyword in subject for keyword in ['urgent', 'immediate', 'action required', 'verify', 'suspend', 'account']))
            header_features['suspicious_from'] = int(is_suspicious_from_address(msg.get('From', '')))
            
        else:
            # For plain text emails, do basic analysis
            header_features['from_domain'] = 'unknown'
            header_features['reply_to_domain'] = 'unknown'
            header_features['return_path_domain'] = 'unknown'
            header_features['received_count'] = 0
            header_features['has_authentication'] = 0
            header_features['subject_length'] = 0
            header_features['has_attachments'] = 0
            header_features['urgent_keywords'] = int(any(keyword in email_content.lower() for keyword in ['urgent', 'immediate', 'action required', 'verify', 'suspend', 'account']))
            header_features['suspicious_from'] = 0
            
    except Exception as e:
        # Fallback to basic analysis if parsing fails
        header_features = {
            'from_domain': 'parse_error',
            'reply_to_domain': 'parse_error',
            'return_path_domain': 'parse_error',
            'received_count': 0,
            'has_authentication': 0,
            'subject_length': 0,
            'has_attachments': 0,
            'urgent_keywords': int(any(keyword in email_content.lower() for keyword in ['urgent', 'immediate', 'action required', 'verify', 'suspend', 'account'])),
            'suspicious_from': 0
        }
    
    return header_features

def extract_domain_from_email(email_string):
    """Extract domain from email address"""
    if not email_string:
        return 'unknown'
    
    # Extract email address using regex
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', email_string)
    if email_match:
        email_addr = email_match.group()
        return email_addr.split('@')[-1].lower()
    
    return 'unknown'

def is_suspicious_from_address(from_string):
    """Check if from address is suspicious"""
    if not from_string:
        return False
    
    suspicious_patterns = [
        r'noreply@.*\.gov',
        r'security@.*\.gov',
        r'admin@.*\.gov',
        r'support@.*\.gov',
        r'.*@.*\.onion',
        r'.*@.*\.bit',
        r'.*@.*\d{3,}.*\..*',  # Domains with lots of numbers
        r'.*@.*[0-9]{3,}.*'    # Email with lots of numbers
    ]
    
    from_lower = from_string.lower()
    return any(re.search(pattern, from_lower) for pattern in suspicious_patterns)

def analyze_header_risks(header_features):
    """Analyze header features for risk indicators"""
    risk_score = 0
    risk_factors = []
    
    # Check for missing authentication
    if header_features.get('has_authentication') == 0:
        risk_score += 20
        risk_factors.append("Missing email authentication (SPF/DKIM)")
    
    # Check for excessive hops
    if header_features.get('received_count', 0) > 5:
        risk_score += 15
        risk_factors.append("Excessive email forwarding hops")
    
    # Check for urgent keywords
    if header_features.get('urgent_keywords', 0) == 1:
        risk_score += 10
        risk_factors.append("Urgent or suspicious keywords detected")
    
    # Check for suspicious from address
    if header_features.get('suspicious_from', 0) == 1:
        risk_score += 25
        risk_factors.append("Suspicious sender address")
    
    # Check for mismatched domains
    from_domain = header_features.get('from_domain', '')
    reply_domain = header_features.get('reply_to_domain', '')
    
    if from_domain != 'unknown' and reply_domain != 'unknown' and from_domain != reply_domain:
        risk_score += 15
        risk_factors.append("Mismatched reply-to domain")
    
    return {
        'risk_score': min(risk_score, 100),
        'risk_factors': risk_factors,
        'risk_level': 'High' if risk_score > 50 else 'Medium' if risk_score > 25 else 'Low'
    }

def predict_phishing(model, email_body):
    if len(model) == 3:
        vectorizer, classifier, metrics = model
    else:
        vectorizer, classifier = model
        metrics = None
    
    cleaned_body = clean_email_body(email_body)
    url_features = extract_url_features(email_body)
    header_features = extract_email_headers(email_body)
    header_risks = analyze_header_risks(header_features)
    
    X_transformed = vectorizer.transform([cleaned_body])
    prediction = classifier.predict(X_transformed)
    probabilities = classifier.predict_proba(X_transformed)
    
    result = 'Phishing' if prediction[0] == 1 else 'Safe'
    confidence = max(probabilities[0]) * 100
    
    # Adjust confidence based on header analysis
    if header_risks['risk_level'] == 'High':
        confidence = min(confidence + 10, 100)
        if result == 'Safe':
            result = 'Phishing'
            confidence = max(confidence, 60)
    elif header_risks['risk_level'] == 'Medium':
        confidence = min(confidence + 5, 100)
    
    return {
        'result': result,
        'confidence': round(confidence, 2),
        'probabilities': {
            'safe': round(probabilities[0][0] * 100, 2),
            'phishing': round(probabilities[0][1] * 100, 2)
        },
        'header_analysis': {
            'risk_level': header_risks['risk_level'],
            'risk_score': header_risks['risk_score'],
            'risk_factors': header_risks['risk_factors'],
            'features': header_features
        }
    }

from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64

def train_model(data):
    data['cleaned_body'] = data['email_body'].apply(clean_email_body)
    data['url_features'] = data['email_body'].apply(extract_url_features)
    X_train, X_test, y_train, y_test = train_test_split(
        data[['cleaned_body', 'url_features']], data['label'], test_size=0.2, random_state=42)
    
    vectorizer = TfidfVectorizer()
    X_train_body = vectorizer.fit_transform(X_train['cleaned_body'])
    X_test_body = vectorizer.transform(X_test['cleaned_body'])
    
    model = MultinomialNB()
    model.fit(X_train_body, y_train)
    
    y_pred = model.predict(X_test_body)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    # Generate confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    # Create visualization
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Safe', 'Phishing'], 
                yticklabels=['Safe', 'Phishing'])
    plt.title('Confusion Matrix')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    
    # Save plot to base64 string
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
    img_buffer.seek(0)
    img_str = base64.b64encode(img_buffer.read()).decode()
    plt.close()
    
    # Generate classification report
    report = classification_report(y_test, y_pred, target_names=['Safe', 'Phishing'], output_dict=True)
    
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm.tolist(),
        'classification_report': report,
        'confusion_matrix_plot': img_str
    }
    
    joblib.dump((vectorizer, model, metrics), 'phishing_model.pkl')
    return metrics

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
@limiter.limit("30 per minute")
def detect_phishing():
    client_ip = request.remote_addr
    try:
        model = joblib.load('phishing_model.pkl')
        email_content = request.json.get('email_content', '')
        
        if not email_content:
            app.logger.warning(f"Empty email content submitted from IP: {client_ip}")
            return jsonify({'error': 'Please enter email content for analysis'}), 400
        
        result_data = predict_phishing(model, email_content)
        
        # Log detection request
        app.logger.info(f"Email analysis from IP: {client_ip} - Result: {result_data['result']} - Confidence: {result_data['confidence']}%")
        
        # Log high-confidence phishing attempts
        if result_data['result'] == 'Phishing' and result_data['confidence'] > 80:
            security_logger.warning(f"High confidence phishing detection from IP: {client_ip} - Confidence: {result_data['confidence']}%")
        
        return jsonify(result_data)
    
    except FileNotFoundError:
        app.logger.error("Model file not found during detection request")
        return jsonify({'error': 'No trained model found. Please train the model first'}), 400
    except Exception as e:
        app.logger.error(f"Error during detection from IP {client_ip}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/batch_detect', methods=['POST'])
@limiter.limit("10 per minute")
def batch_detect_phishing():
    client_ip = request.remote_addr
    try:
        model = joblib.load('phishing_model.pkl')
        data = request.get_json()
        
        if not data or 'emails' not in data:
            app.logger.warning(f"Invalid batch request from IP: {client_ip} - no emails array")
            return jsonify({'error': 'Please provide emails array for analysis'}), 400
        
        emails = data['emails']
        if not isinstance(emails, list):
            app.logger.warning(f"Invalid batch request from IP: {client_ip} - emails not an array")
            return jsonify({'error': 'Emails must be provided as an array'}), 400
        
        if len(emails) > 100:
            app.logger.warning(f"Batch size limit exceeded from IP: {client_ip} - {len(emails)} emails")
            return jsonify({'error': 'Maximum 100 emails allowed per batch request'}), 400
        
        results = []
        for i, email_content in enumerate(emails):
            try:
                if not email_content or not isinstance(email_content, str):
                    results.append({
                        'index': i,
                        'error': 'Invalid email content'
                    })
                    continue
                
                result_data = predict_phishing(model, email_content)
                results.append({
                    'index': i,
                    'result': result_data
                })
            except Exception as e:
                results.append({
                    'index': i,
                    'error': str(e)
                })
        
        summary = {
            'total': len(emails),
            'safe': len([r for r in results if 'result' in r and r['result']['result'] == 'Safe']),
            'phishing': len([r for r in results if 'result' in r and r['result']['result'] == 'Phishing']),
            'errors': len([r for r in results if 'error' in r])
        }
        
        # Log batch analysis
        app.logger.info(f"Batch analysis from IP: {client_ip} - Total: {summary['total']}, Safe: {summary['safe']}, Phishing: {summary['phishing']}, Errors: {summary['errors']}")
        
        return jsonify({
            'results': results,
            'summary': summary
        })
    
    except FileNotFoundError:
        app.logger.error("Model file not found during batch detection")
        return jsonify({'error': 'No trained model found. Please train the model first'}), 400
    except Exception as e:
        app.logger.error(f"Error during batch detection from IP {client_ip}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/train', methods=['POST'])
@limiter.limit("5 per hour")
def train():
    client_ip = request.remote_addr
    try:
        if 'file' not in request.files:
            app.logger.warning(f"Training request without file from IP: {client_ip}")
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            app.logger.warning(f"Training request with empty filename from IP: {client_ip}")
            return jsonify({'error': 'No file selected'}), 400
        
        if file and file.filename.endswith('.csv'):
            app.logger.info(f"Model training started from IP: {client_ip} - File: {file.filename}")
            data = pd.read_csv(file)
            
            if 'email_body' not in data.columns or 'label' not in data.columns:
                app.logger.error(f"Invalid CSV format from IP: {client_ip} - Missing required columns")
                return jsonify({'error': 'Invalid dataset format. Ensure email_body and label columns are present'}), 400
            
            accuracy = train_model(data)
            
            # Log training completion
            model_logger.info(f"Model trained successfully - Accuracy: {accuracy['accuracy']:.4f}, Precision: {accuracy['precision']:.4f}, Recall: {accuracy['recall']:.4f}, F1: {accuracy['f1_score']:.4f}")
            app.logger.info(f"Model training completed from IP: {client_ip} - Accuracy: {(accuracy['accuracy'] * 100):.2f}%")
            
            return jsonify({
                'success': True, 
                'accuracy': accuracy['accuracy'],
                'precision': accuracy['precision'],
                'recall': accuracy['recall'],
                'f1_score': accuracy['f1_score'],
                'confusion_matrix_plot': accuracy['confusion_matrix_plot'],
                'classification_report': accuracy['classification_report']
            })
        
        app.logger.warning(f"Non-CSV file upload attempt from IP: {client_ip} - File: {file.filename}")
        return jsonify({'error': 'Please upload a CSV file'}), 400
    
    except Exception as e:
        app.logger.error(f"Error during model training from IP {client_ip}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/docs')
@limiter.limit("60 per minute")
def api_docs():
    """API Documentation Endpoint"""
    docs = {
        "title": "X-Mail Phishing Detection API",
        "version": "1.0.0",
        "description": "Advanced phishing detection system with machine learning",
        "endpoints": {
            "POST /detect": {
                "description": "Analyze a single email for phishing",
                "request_body": {
                    "type": "application/json",
                    "schema": {
                        "email_content": "string (required) - The email content to analyze"
                    }
                },
                "response": {
                    "200": {
                        "result": "string - 'Safe' or 'Phishing'",
                        "confidence": "number - Confidence percentage (0-100)",
                        "probabilities": {
                            "safe": "number - Probability percentage for safe",
                            "phishing": "number - Probability percentage for phishing"
                        }
                    },
                    "400": {"error": "string - Error message"},
                    "500": {"error": "string - Server error"}
                }
            },
            "POST /batch_detect": {
                "description": "Analyze multiple emails for phishing",
                "request_body": {
                    "type": "application/json",
                    "schema": {
                        "emails": "array (required) - Array of email strings (max 100)"
                    }
                },
                "response": {
                    "200": {
                        "results": [
                            {
                                "index": "number - Email index in array",
                                "result": {
                                    "result": "string - 'Safe' or 'Phishing'",
                                    "confidence": "number - Confidence percentage",
                                    "probabilities": {
                                        "safe": "number - Safe probability",
                                        "phishing": "number - Phishing probability"
                                    }
                                }
                            }
                        ],
                        "summary": {
                            "total": "number - Total emails processed",
                            "safe": "number - Safe emails count",
                            "phishing": "number - Phishing emails count",
                            "errors": "number - Error count"
                        }
                    },
                    "400": {"error": "string - Error message"},
                    "500": {"error": "string - Server error"}
                }
            },
            "POST /train": {
                "description": "Train a new phishing detection model",
                "request_body": {
                    "type": "multipart/form-data",
                    "schema": {
                        "file": "file (required) - CSV file with 'email_body' and 'label' columns"
                    }
                },
                "response": {
                    "200": {
                        "success": "boolean - Training status",
                        "accuracy": "number - Model accuracy percentage"
                    },
                    "400": {"error": "string - Error message"},
                    "500": {"error": "string - Server error"}
                }
            },
            "GET /logo": {
                "description": "Serve application logo",
                "response": {
                    "200": "image/jpeg - Application logo"
                }
            }
        },
        "usage_examples": {
            "single_email": {
                "curl": "curl -X POST http://localhost:5000/detect -H 'Content-Type: application/json' -d '{\"email_content\": \"Your account will be suspended...\"}'",
                "python": "import requests\\nresponse = requests.post('http://localhost:5000/detect', json={'email_content': 'Your account will be suspended...'})\\nprint(response.json())"
            },
            "batch_analysis": {
                "curl": "curl -X POST http://localhost:5000/batch_detect -H 'Content-Type: application/json' -d '{\"emails\": [\"Email 1...\", \"Email 2...\"]}'",
                "python": "import requests\\nresponse = requests.post('http://localhost:5000/batch_detect', json={'emails': ['Email 1...', 'Email 2...']})\\nprint(response.json())"
            }
        },
        "notes": [
            "Maximum email content length: 50,000 characters",
            "Maximum emails per batch: 100",
            "Minimum email content length: 10 characters",
            "All email content is automatically sanitized and validated",
            "Model uses Naive Bayes classifier with TF-IDF vectorization",
            "URL features are extracted for enhanced detection"
        ]
    }
    return jsonify(docs)

@app.route('/logo')
def logo():
    return send_from_directory('.', 'logo.JPEG')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
