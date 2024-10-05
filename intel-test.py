import re
import socket
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import joblib
import requests
import pandas as pd
from bs4 import BeautifulSoup
import whois
import pickle
import numpy as np
with open('phishing_model.pkl', 'rb') as file:
    model = pickle.load(file)
app = Flask(__name__)

def check_dns_record(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except socket.error:
        return 0

def check_web_traffic(domain):
    return 1

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days / 365
        return 1 if age > 1 else 0
    except:
        return 0

def get_domain_end(domain):
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        time_left = (expiration_date - datetime.now()).days
        return 1 if time_left > 180 else 0
    except:
        return 0

def check_iframe(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        if soup.find_all('iframe'):
            return 1
        else:
            return 0
    except:
        return 0

def check_web_forwards(url):
    try:
        response = requests.get(url, timeout=5)
        if len(response.history) > 2:
            return 1
        else:
            return 0
    except:
        return 0
def check_mouse_over(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        if soup.find_all(onmouseover=True):
            return 1
        else:
            return 0
    except Exception as e:
        print(f"Error checking Mouse Over: {e}")
        return 0
def check_right_click(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if 'contextmenu' in script.text:
                return 1
        return 0
    except Exception as e:
        print(f"Error checking Right Click: {e}")
        return 0



def extract_features(url):
    features = {}
    domain = urlparse(url).netloc

    features['Have_IP'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['Have_At'] = 1 if '@' in url else 0
    features['URL_Length'] = 1 if len(url) >= 54 else 0
    features['URL_Depth'] = urlparse(url).path.count('/')
    features['Redirection'] = 1 if '//' in urlparse(url).path else 0
    features['https_Domain'] = 1 if 'https' in urlparse(url).scheme else 0
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2\.l|x\.co|ow\.ly|t\.co|tinyurl"
    features['TinyURL'] = 1 if re.search(shortening_services, url) else 0
    features['Prefix/Suffix'] = 1 if '-' in domain else 0
    features['DNS_Record'] = check_dns_record(domain)
    features['Web_Traffic'] = check_web_traffic(domain)
    features['Domain_Age'] = get_domain_age(domain)
    features['Domain_End'] = get_domain_end(domain)
    features['iFrame'] = check_iframe(url)
    features['Mouse_Over'] = check_mouse_over(url)
    features['Right_Click'] = check_right_click(url)
    features['Web_Forwards'] = check_web_forwards(url)

    return features

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    features = extract_features(url)
    print(f"Features for {url}: {features}")  # Print extracted features
    url_features_df = pd.DataFrame([features])
    url_prediction = model.predict(url_features_df)

    prediction_result = int(url_prediction[0])
    confidence = "85.43%"  # Replace with actual confidence score calculation if available

    return jsonify({'url': url, 'prediction': prediction_result, 'confidence': confidence})

if __name__ == '__main__':
    app.run(debug=True)
