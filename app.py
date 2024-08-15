from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response 
from flask_mail import Mail, Message
from flask import jsonify
import pyodbc, logging, os, requests, json
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from msal import ConfidentialClientApplication

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

def add_headers(response):
    response.headers['Cache-Control'] = 'public, max-age=300'  # Cache for 5 minutes
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

app.after_request(add_headers)

# Set Flask app configuration from environment variables
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

def get_db_connection():
    server = os.getenv('DB_SERVER')
    database = os.getenv('DB_NAME')
    username = os.getenv('DB_USERNAME')
    password = os.getenv('DB_PASSWORD')
    driver = '{ODBC Driver 18 for SQL Server}'
    
    connection_string = f'DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password}'
    logging.info(f"Attempting to connect with string: DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD=****")
    try:
        conn = pyodbc.connect(connection_string)
        logging.info("Database connection successful")
        return conn
    except pyodbc.Error as e:
        logging.error(f"Database connection failed: {str(e)}")
        raise

def check_credentials(username, password):
    logging.info(f"Attempting login for username: {username}")
    try:
        logging.info("Attempting to establish database connection")
        conn = get_db_connection()
        logging.info("Database connection established successfully")
        cursor = conn.cursor()
        logging.info(f"Executing query for username: {username}")
        cursor.execute("SELECT UserID, PasswordHash, Role FROM Users WHERE Username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        logging.info(f"Query executed, user data found: {user is not None}")
        
        if user and check_password_hash(user.PasswordHash, password):
            logging.info("Password verified successfully")
            return {'id': user.UserID, 'role': user.Role}
        else:
            logging.info("Invalid credentials")
            return None
    except Exception as e:
        logging.error(f"Error in check_credentials: {str(e)}")
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
        logging.info(f"Login attempt for username: {username}")
        try:
            user = check_credentials(username, password)
            logging.info(f"check_credentials returned: {user}")
            if user:
                session['user_id'] = user['id']
                session['username'] = username
                logging.info(f"User authenticated. Role: {user['role']}")
                if user['role'] == 'admin':
                    logging.info("Redirecting to admin dashboard")
                    return redirect(url_for('admin_dashboard'))
                else:
                    logging.info("Redirecting to user dashboard")
                    return redirect(url_for('user_dashboard'))
            else:
                logging.info("Invalid credentials")
                flash('Invalid credentials', 'error')
        except Exception as e:
            logging.error(f"Login error: {str(e)}", exc_info=True)
            flash(f'An error occurred: {str(e)}', 'error')
    return render_template('login.html')

#@app.route('/request_access_form', methods=['GET'])
#def request_access_form():
    #return render_template('request_access_form.html')

@app.route('/request_access_form', methods=['GET', 'POST'])
def request_access():
    if request.method == 'POST':
        try:
            recaptcha_response = request.form['g-recaptcha-response']
            secret_key = os.getenv('RECAPTCHA_SECRET_KEY')
            verification_url = "https://www.google.com/recaptcha/api/siteverify"
            response = requests.post(verification_url, data={
                'secret': secret_key,
                'response': recaptcha_response
            })
            result = response.json()

            if not result.get('success'):
                flash('reCAPTCHA verification failed. Please try again.', 'error')
                return redirect(url_for('request_access'))
            
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            comments = request.form['comments']
            subject = "New Access Request"
            body = f"First Name: {first_name}\nLast Name: {last_name}\nEmail: {email}\nComments: {comments}"
            
            access_token = get_access_token()
            if access_token is None:
                raise Exception("Failed to get access token")
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            email_payload = {
                "message": {
                    "subject": subject,
                    "body": {
                        "contentType": "Text",
                        "content": body
                    },
                    "toRecipients": [
                        {
                            "emailAddress": {
                                "address": os.getenv('MAIL_DEFAULT_SENDER')
                            }
                        }
                    ]
                }
            }
            send_mail_url = f'https://graph.microsoft.com/v1.0/users/{os.getenv("MAIL_USERNAME")}/sendMail'
            response = requests.post(send_mail_url, json=email_payload, headers=headers)
            response.raise_for_status()
            flash('Your access request has been submitted for review', 'success')
            return redirect(url_for('login'))  # Redirect to login page after successful submission

        except Exception as e:
            logging.error(f"Error in request_access: {str(e)}")
            flash('There was an error submitting your request. Please try again later.', 'error')
    
    # For GET requests or if there's an error in POST
    recaptcha_site_key = os.getenv('RECAPTCHA_SITE_KEY')
    return render_template('request_access_form.html', recaptcha_site_key=recaptcha_site_key)

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

# Routes for user_dashboard
@app.route('/tests', methods=['GET', 'POST'])
def tests():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            test_type = request.form.get('test_type')
            category = request.form.get('category')
            sub_category = request.form.get('sub_category')
            num_questions = int(request.form.get('num_questions'))
            confidence_level = float(request.form.get('confidence_level'))
            user_id = session['user_id']
            
            if not category:
                return "Category is required", 400
            
            # You'll need to implement these functions
            # attempt_number = get_or_increment_category_attempt(user_id, category)
            # questions = get_test_questions(category, num_questions, sub_category)
            
            # For now, let's just return a success message
            return jsonify({"message": "Test created successfully"}), 200
        
        except Exception as e:
            logging.error(f"Error in test creation: {str(e)}", exc_info=True)
            return str(e), 500
    
    else:  # GET request
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT Category FROM MultipleChoiceQuestions WHERE Category IS NOT NULL")
            categories = [row.Category for row in cursor.fetchall()]
            
            cursor.execute("SELECT DISTINCT SubCategory FROM MultipleChoiceQuestions WHERE SubCategory IS NOT NULL")
            sub_categories = [row.SubCategory for row in cursor.fetchall()]
            
            conn.close()

            return render_template('tests.html', 
                                   user_id=session['user_id'], 
                                   username=session['username'], 
                                   categories=categories, 
                                   sub_categories=sub_categories)
        except Exception as e:
            logging.error(f"Error in tests route: {str(e)}", exc_info=True)
            return render_template('tests.html', 
                                   user_id=session['user_id'], 
                                   username=session['username'], 
                                   categories=[], 
                                   sub_categories=[])
        
@app.route('/userstats')
def userstats():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_stats.html', user_id=session['user_id'], username=session['username'])

@app.route('/accountmanagement')
def accountmanagement():
    print("Account management route called")  # For debugging
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('account_management.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Routes for admin_dashboard pages
@app.route('/questionmanagement')
def questionmanagement():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('question_management.html', user_id=session['user_id'], username=session['username'])

@app.route('/usermanagement')
def usermanagement():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_management.html', user_id=session['user_id'], username=session['username'])

# Routes for API endpoints
@app.route('/add_question', methods=['POST'])
def add_question():
    if 'user_id' not in session:
        logging.warning('User not logged in, redirecting to login page')
        return redirect(url_for('login'))

    try:
        question_text = request.form['questionText']
        category = request.form['category']
        sub_category = request.form['subCategory']
        answer1 = request.form['answer1']
        answer2 = request.form['answer2']
        answer3 = request.form['answer3']
        answer4 = request.form['answer4']
        correct_answer = int(request.form['correctAnswer'])

        logging.info(f'Received form data: {request.form}')

        conn = get_db_connection()
        cursor = conn.cursor()

        logging.info('Database connection established')

        cursor.execute("""
            INSERT INTO MultipleChoiceQuestions (QuestionText, Category, SubCategory, Answer1, Answer2, Answer3, Answer4, CorrectAnswer)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (question_text, category, sub_category, answer1, answer2, answer3, answer4, correct_answer))

        logging.info('SQL query executed')

        conn.commit()
        logging.info('Changes committed to database')
        conn.close()
        logging.info('Database connection closed')

        flash('Question added successfully!', 'success')
        return redirect(url_for('admin_dashboard.html/questionmanagement'))

    except Exception as e:
        logging.error(f'Error adding question: {str(e)}', exc_info=True)
        flash(f'Error adding question: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard.html/questionmanagement'))

@app.route('/check_db')
def check_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users")
        users = cursor.fetchall()
        conn.close()
        return f"Database connection successful. Found {len(users)} users.", 200
    except Exception as e:
        return f"Database error: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
