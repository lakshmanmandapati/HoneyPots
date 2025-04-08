from flask import Flask, request, render_template_string, redirect
import logging
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# Set up logging
logging.basicConfig(filename='honeypot.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s')

# Predefined valid credentials
VALID_CREDENTIALS = {
    "admin": "admin123",
    "238t1a4267": "123456789"
}

# Patterns to detect malicious activity with their corresponding attack types
MALICIOUS_PATTERNS = {
    r"<script>": "XSS Attempt",  # Detects XSS attempts
    r"union.*select": "SQL Injection Attempt",  # Detects SQL injection attempts
    r"http[s]?://": "External URL Injection Attempt",  # Detects external URL injections
    r"eval\(": "Eval Function Usage Attempt",  # Detects eval() function usage
    r"alert\(": "Alert Function Usage Attempt",  # Detects alert() function usage
    r"drop\s+table": "SQL Drop Table Attempt",  # Detects SQL drop table attempts
    r";--": "SQL Comment Attempt",  # Detects SQL comment attempts
}

# Email configuration
EMAIL_HOST = 'smtp.gmail.com'  # Replace with your SMTP server
EMAIL_PORT = 587  
EMAIL_USER = 'mlkreddym6@gmail.com'  # Replace with your email
EMAIL_PASSWORD = 'nhly lhko naux pxaq'  # Replace with your email password
EMAIL_RECEIVER = 'mlkreddym6@gmail.com'  # Replace with the receiver's email

# HTML template for the fake login page
D_login_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Honey Pot</title>
    <style>
        /* Body styling with background image */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-image: url('https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT-ps3bkEXJffYfiMv-2OSsHGC5To3ffA5rI7543tLiovpTfUKr');
            background-size: cover; 
            background-repeat: no-repeat;
        }

        /* Navigation bar styling */
        .navbar {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            padding: 10px 20px;
            display: flex;
            align-items: center;
        }

        .navbar img {
            height: 90%; /* Image will stretch to fill the navbar height */
            width: 100%;
        }

        .navbar h1 {
            color: white;
            font-size: 24px;
            margin: 0;
        }

        /* Login container styling */
        .login-container {
            background-color: rgba(255, 255, 255, 0.9); /* Semi-transparent white */
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 300px;
            text-align: center;
            margin-top: 200px;
        }

        .login-container h2 {
            margin-bottom: 20px;
            font-size: 24px;
            color: #333;
        }

        .login-container input[type="text"],
        .login-container input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }

        .login-container input[type="submit"] {
            width: 100%;
            padding: 10px;
            background-color: #28a745;
            border: none;
            border-radius: 4px;
            color: #fff;
            font-size: 16px;
            cursor: pointer;
        }

        .login-container input[type="submit"]:hover {
            background-color: #218838;
        }

        .login-container .logo {
            margin-bottom: 20px;
        }

        .login-container .logo img {
            width: 100px;
        }
    </style>
</head>
<body>
    <!-- Navigation bar -->
    <div class="navbar">
        <img src="https://dietportal.in:8443/ExamClick/images/logo%20header.jpg" alt="Company Logo">
    </div>

    <!-- Login container -->
    <div class="login-container">
        <div class="logo">
            <img src="https://facultytub.com/wp-content/uploads/2024/12/DIET-512x445.png" alt="Company Logo">
        </div>
        <h2>Login</h2>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
"""
def send_email(subject, body):
    """
    Send an email alert.
    """
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_USER, EMAIL_RECEIVER, text)
        server.quit()
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def detect_attack_type(input_string):
    """
    Detect the type of attack based on malicious patterns.
    """
    for pattern, attack_type in MALICIOUS_PATTERNS.items():
        if re.search(pattern, input_string, re.IGNORECASE):
            return attack_type
    return None

@app.before_request
def log_malicious_activity():
    """
    Log malicious activity silently without interrupting the user experience.
    """
    # Skip logging for valid login attempts
    if request.path == "/login" and request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
            return  # Skip logging for valid credentials

    # Check the URL for malicious patterns
    attack_type = detect_attack_type(request.url)
    if attack_type:
        logging.warning(f"Malicious activity detected from {request.remote_addr} - Attack Type: {attack_type}, URL: {request.url}")
        send_email("Malicious Activity Detected", f"Attack Type: {attack_type}\nURL: {request.url}\nIP: {request.remote_addr}")

    # Check query parameters for malicious patterns
    for key, value in request.args.items():
        attack_type = detect_attack_type(value)
        if attack_type:
            logging.warning(f"Malicious activity detected from {request.remote_addr} - Attack Type: {attack_type}, Parameter: {key}={value}")
            send_email("Malicious Activity Detected", f"Attack Type: {attack_type}\nParameter: {key}={value}\nIP: {request.remote_addr}")

@app.route('/')
def index():
    # Log the request details
    logging.info(f"Connection from {request.remote_addr} - {request.headers.get('User-Agent')}")
    return render_template_string(D_login_html)

@app.route('/login', methods=['POST'])
def login():
    # Get the submitted username and password
    username = request.form.get('username')
    password = request.form.get('password')

    # Log the login attempt
    logging.info(f"Login attempt from {request.remote_addr} - Username: {username}, Password: {password}")

    # Check if the credentials are valid
    if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
        # Redirect to another website if credentials are correct
        return redirect("https://dietportal.in:8443/ExamClick/") 
    else:
        # Return a failure message if credentials are incorrect
        return "Login failed. Please try again."

@app.route('/admin')
def admin():
    # Log the request details
    logging.info(f"Admin access attempt from {request.remote_addr} - {request.headers.get('User-Agent')}")
    return "You shouldn't be here!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)  # Enable debug mode