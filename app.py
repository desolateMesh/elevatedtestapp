from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyodbc
import os
import requests
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from msal import ConfidentialClientApplication

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Set Flask app configuration from environment variables
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

def get_db_connection():
    server = os.getenv('DB_SERVER')
    database = os.getenv('DB_NAME')
    username = os.getenv('DB_USERNAME')
    password = os.getenv('DB_PASSWORD')
    driver = '{ODBC Driver 18 for SQL Server}'
    
    connection_string = f'DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password}'
    return pyodbc.connect(connection_string)

def check_credentials(username, password):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT UserID, PasswordHash, Role FROM Users WHERE Username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            is_password_correct = (user.PasswordHash == password)
            if is_password_correct:
                return {'id': user.UserID, 'role': user.Role}
        return None
    except Exception as e:
        print(f"Error in check_credentials: {str(e)}")
        return None
    
class Config:
    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    AUTHORITY = os.getenv('AUTHORITY')
    SCOPE = [os.getenv('SCOPE')]

def build_msal_app():
    return ConfidentialClientApplication(
        Config.CLIENT_ID,
        authority=Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET
    )

def get_access_token():
    client = build_msal_app()
    result = client.acquire_token_for_client(scopes=Config.SCOPE)
    if 'access_token' in result:
        return result['access_token']
    else:
        print(f"Failed to acquire token: {result.get('error')}")
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = check_credentials(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/request_access_form', methods=['GET'])
def request_access_form():
    return render_template('request_access_form.html')

@app.route('/submit_request_access', methods=['POST'])
def submit_request_access():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        notes = request.form['notes']
        subject = "Access Request"
        body = f"First Name: {firstname}\nLast Name: {lastname}\nEmail: {email}\nNotes: {notes}"
        payload = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "Text",
                    "content": body
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": app.config['MAIL_DEFAULT_SENDER']
                        }
                    }
                ]
            },
            "saveToSentItems": "false"
        }
        try:
            token = get_access_token()
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            send_mail_url = f'https://graph.microsoft.com/v1.0/users/{app.config["MAIL_USERNAME"]}/sendMail'
            response = requests.post(send_mail_url, json=payload, headers=headers)
            response.raise_for_status()
            flash('Your request has been sent successfully!', 'success')
        except Exception as e:
            flash(f'Failed to send your request. Error: {e}', 'error')

        return redirect(url_for('request_access_form'))

    return render_template('request_access_form.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_dashboard.html', user_id=session['user_id'], username=session['username'])

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', user_id=session['user_id'], username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_id=session['user_id'], username=session['username'])

@app.route('/tests')
def tests():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tests.html', user_id=session['user_id'], username=session['username'])

@app.route('/userstats')
def userstats():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('userstats.html', user_id=session['user_id'], username=session['username'])

@app.route('/accountmanagement')
def accountmanagement():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('accountmanagement.html', user_id=session['user_id'], username=session['username'])

if __name__ == '__main__':
    app.run(debug=True)
