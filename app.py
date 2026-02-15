from flask import Flask, render_template, request, jsonify, send_from_directory
import pandas as pd
import numpy as np
import re
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
import os

# Download NLTK data
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

# Load stopwords
STOPWORDS = set(stopwords.words("english"))

app = Flask(__name__)

def clean_email_body(email_body):
    email_body = re.sub(r'[^a-zA-Z\s]', '', email_body)
    email_body = ' '.join([word.lower() for word in email_body.split() if word.lower() not in STOPWORDS])
    return email_body

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

def predict_phishing(model, email_body):
    vectorizer, classifier = model
    cleaned_body = clean_email_body(email_body)
    url_features = extract_url_features(email_body)
    
    X_transformed = vectorizer.transform([cleaned_body])
    prediction = classifier.predict(X_transformed)
    
    return 'Phishing' if prediction[0] == 1 else 'Safe'

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
    
    accuracy = model.score(X_test_body, y_test)
    
    joblib.dump((vectorizer, model), 'phishing_model.pkl')
    return accuracy

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect_phishing():
    try:
        model = joblib.load('phishing_model.pkl')
        email_content = request.json.get('email_content', '')
        
        if not email_content:
            return jsonify({'error': 'Please enter email content for analysis'}), 400
        
        result = predict_phishing(model, email_content)
        return jsonify({'result': result})
    
    except FileNotFoundError:
        return jsonify({'error': 'No trained model found. Please train the model first'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/train', methods=['POST'])
def train():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and file.filename.endswith('.csv'):
            data = pd.read_csv(file)
            
            if 'email_body' not in data.columns or 'label' not in data.columns:
                return jsonify({'error': 'Invalid dataset format. Ensure email_body and label columns are present'}), 400
            
            accuracy = train_model(data)
            return jsonify({'success': True, 'accuracy': accuracy})
        
        return jsonify({'error': 'Please upload a CSV file'}), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logo')
def logo():
    return send_from_directory('.', 'logo.JPEG')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
