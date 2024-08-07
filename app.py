from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyodbc
import os
import requests
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from msal import ConfidentialClientApplication

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

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

        print(f"Database query result: {user}")  

        if user:
            print(f"Stored password: {user.PasswordHash}")  
            print(f"Provided password: {password}")  
            is_password_correct = (user.PasswordHash == password)
            print(f"Password check result: {is_password_correct}")  
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
        token = result['access_token']
        print(f"Access Token: {token}")
        return token
    else:
        print(f"Failed to acquire token: {result.get('error')}")
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Login attempt: username={username}, password={'*' * len(password)}")  
        user = check_credentials(username, password)
        if user:
            print(f"User authenticated: {user}")  
            session['user_id'] = user['id']  
            session['username'] = username
            if user['role'] == 'admin':  
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            print("Authentication failed")  
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


# Routes for pages
@app.route('/request_access_form.html')
def request_access():
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