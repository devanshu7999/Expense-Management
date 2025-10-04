from flask import Flask, render_template, request, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import mysql.connector

import uuid  
from flask_mail import Mail, Message

import smtplib
from email.message import EmailMessage
import random
import string

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="expense"
)
cursor = db.cursor(dictionary=True)

def get_country_currency():
    url = "https://restcountries.com/v3.1/all?fields=name,currencies"
    response = requests.get(url)
    data = response.json()

    countries = []
    for item in data:
        name = item['name']['common']
        currencies = item.get('currencies', {})
        currency_code = list(currencies.keys())[0] if currencies else 'N/A'
        countries.append({'name': name, 'currency': currency_code})

    return sorted(countries, key=lambda x: x['name'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        country_currency = request.form['country_currency']

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect('/register')

        country, currency = country_currency.split('|')
        hashed_password = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users (name, email, password, role, country, currency)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (name, email, hashed_password, 'employee', country, currency))
        db.commit()
        flash("Registration successful!")
        return redirect('/login')

    countries = get_country_currency()
    return render_template('register.html', countries=countries)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            flash("Login successful!")
            return redirect('/')
        else:
            flash("Invalid email or password")
            return redirect('/login')

    return render_template('login.html')



# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email'  
app.config['MAIL_PASSWORD'] = 'your_email_pass'  
mail = Mail(app)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            token = str(uuid.uuid4())  
            cursor.execute("UPDATE users SET reset_token = %s WHERE email = %s", (token, email))
            db.commit()

            reset_link = request.url_root + "reset-password/" + token
            msg = Message("Password Reset Request", sender="your_email", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"
            mail.send(msg)

            flash("Password reset link sent to your email.")
            return redirect('/login')
        else:
            flash("Email not found.")
            return redirect('/forgot-password')

    return render_template('forgot_password.html')



@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    cursor.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    user = cursor.fetchone()

    if not user:
        flash("Invalid or expired token.")
        return redirect('/login')

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(request.url)

        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password = %s, reset_token = NULL WHERE id = %s", 
                       (hashed_password, user['id']))
        db.commit()

        flash("Password reset successful. Please login.")
        return redirect('/login')

    return render_template('reset_password.html', token=token)




def generate_password(length=10):
    chars = string.ascii_letters + string.digits + "@#$"
    return ''.join(random.choice(chars) for _ in range(length))

def send_email(recipient, password):
    msg = EmailMessage()
    msg.set_content(f"Your login password is: {password}")
    msg['Subject'] = 'Your Login Credentials'
    msg['From'] = 'your_email'
    msg['To'] = recipient

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login('your_email', 'bakwfecmkgoqlolx')
        smtp.send_message(msg)


@app.route('/')
def index():
    return render_template('index_admin.html')  

@app.route('/add_user', methods=['POST'])
def add_user():
    name = request.form['username']
    role = request.form['role']
    manager = request.form['manager']
    email = request.form['email']
    password = generate_password()

    send_email(email, password)


    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO users (name, role, manager, email, password)
        VALUES (%s, %s, %s, %s, %s)
    """, (name, role, manager, email, password))
    db.commit()
    cursor.close()
    db.close()

    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)


