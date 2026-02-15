# 🚨 X-Mail - Phishing Detector

## What It Does

X-Mail is an AI tool that checks if emails are **phishing scams** or **safe**. It uses machine learning to analyze email content and links.

## Main Features

- **Text Analysis**: Reads email content to spot suspicious patterns
- **Link Checking**: Examines URLs to find dangerous links
- **Smart Learning**: Trained on thousands of real phishing examples
- **Easy to Use**: Simple web interface for instant results

## How to Use

### 1. Train the Model
- Upload a CSV file with labeled emails (phishing/safe)
- Click "Train Model" to teach the AI

### 2. Check Emails
- Paste any email content in the text box
- Click "Detect Phishing"
- Get instant results: **Phishing** or **Safe**

## Test Examples

**Try this phishing email:**
```
Congratulations! You've won a $1000 gift card. Click here to claim your prize: http://phishing.com
```

**Try this safe email:**
```
Hey, just checking in on our project. Let me know your availability for a meeting.
```

## How It Works

The system analyzes:
- Email text content
- Embedded links and URLs
- Common phishing patterns
- Suspicious keywords

## Built With

- Python (programming language)
- Streamlit (web interface)
- scikit-learn (machine learning)
- NLTK (text processing)

## Results

You'll see a clear prediction:
- 🚨 **Phishing** - This email is dangerous
- ✅ **Safe** - This email looks legitimate


## 📞 Contact

### Created by
Biprajeet Sen & Amritangshu Dey
