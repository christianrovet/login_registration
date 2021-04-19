from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
import re
from flask_bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "christiano wuz here"
EMAIL_REGEX= re.compile('^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/profile')
def login():
    query = "SELECT * FROM users WHERE id = %(id)s"
    data = {
        'id': session['id']
    }
    user = connectToMySQL('login_registration').query_db(query,data)
    return render_template('profile.html', user=user)

@app.route('/generate', methods=['post'])
def generate():
    is_valid = True
    # Registration
    if (request.form['type'] == 'register'):
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        if len(first_name) < 2:
            flash("First Name needs at least 2 characters.", "register")
            is_valid = False
        if not first_name.isalpha():
            flash("First Name must be letters only.")
            is_valid = False
        if len(last_name) < 2:
            flash("Last Name needs at least 2 characters.", "register")
            is_valid = False
        if not last_name.isalpha():
            flash("Last Name must be letters only.", "register")
            is_valid = False
        if len(email) < 1:
            flash("Email field is required.", "register")
            is_valid = False
        if not EMAIL_REGEX.match(email):
            flash("Invalid Email Address.", "register")
            is_valid = False
        if len(password) < 8 or len(password) > 15:
            flash("Password must be between 8-15 characters.", "register")
            is_valid = False
        if password != password_confirm:
            flash("Passwords must match.", "register")
            is_valid = False
        if (is_valid):
            flash("Successfully Registered User! Please, login.")
            query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
            pw_hash = bcrypt.generate_password_hash(password)
            data = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': pw_hash
            }
            connectToMySQL('login_registration').query_db(query,data)
            return redirect('/')
    # Login
    elif (request.form['type'] == 'login'):
        email = request.form['email']
        password = request.form['password']
        if len(email) < 1:
            flash("Email field is required.", "login")
            is_valid = False
        elif not EMAIL_REGEX.match(email):
            flash("Invalid Email Address.", "login")
            is_valid = False
        query = "SELECT * FROM users WHERE email = %(email)s;"
        data = {
            'email': request.form['email'],
        }
        check = connectToMySQL('login_registration').query_db(query,data)
        if len(check) < 1:
            flash("invalid email", "login")
            is_valid = False
        elif not bcrypt.check_password_hash(check[0]['password'], password):
            flash("incorrect password, try again", "login")
            is_valid = False
        if (is_valid):
            session['id'] = check[0]['id']
            return redirect('/profile')
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)