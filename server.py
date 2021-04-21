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

@app.route('/recipes')
def login():
    query = "SELECT * FROM users JOIN recipes ON users.id = user_id WHERE users.id = %(id)s"
    query_user = "SELECT * FROM users WHERE users.id = %(id)s"
    data = {
        'id': session['id']
    }
    results = connectToMySQL('recipes').query_db(query,data)
    user = connectToMySQL('recipes').query_db(query_user,data)
    return render_template('recipes.html', recipes=results, user=user[0])

@app.route('/show/<int:recipe_id>')
def show_recipe(recipe_id):
    if 'id' not in session:
        return redirect('/')
    query = "SELECT * FROM recipes WHERE id = %(id)s;"
    data = {
        'id': recipe_id
    }
    results = connectToMySQL('recipes').query_db(query,data)
    return render_template('show.html', recipe=results[0])

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
            connectToMySQL('recipes').query_db(query,data)
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
        check = connectToMySQL('recipes').query_db(query,data)
        if len(check) < 1:
            flash("invalid email", "login")
            is_valid = False
        elif not bcrypt.check_password_hash(check[0]['password'], password):
            flash("incorrect password, try again", "login")
            is_valid = False
        if (is_valid):
            session['id'] = check[0]['id']
            return redirect('/recipes')
    return redirect('/')

@app.route('/new')
def new():
    if'id' not in session:
        return redirect('/')
    return render_template('new.html')


@app.route('/create/recipe', methods=['post'])
def create_recipe():
    if 'id' not in session:
        return redirect('/')
    if not validate_recipe(request.form):
        return redirect('/new')
    query = 'INSERT INTO recipes (name,description,instructions,under_thirty,created_at,updated_at,user_id) VALUES (%(name)s,%(description)s,%(instructions)s,%(under_thirty)s, NOW(),NOW(),%(user_id)s);'
    data = {
        "name": request.form['name'],
        "description": request.form['description'],
        "instructions": request.form['instructions'],
        "under_thirty": request.form['under_thirty'],
        "user_id": session['id']
    }
    result = connectToMySQL('recipes').query_db(query,data)
    return redirect('/recipes')

@app.route('/edit/<int:recipe_id>')
def edit_recipe(recipe_id):
    if 'id' not in session:
        return redirect('/')
    query = "SELECT * FROM recipes WHERE id = %(id)s;"
    data = {
        'id': recipe_id
    }
    results = connectToMySQL('recipes').query_db(query,data)
    return render_template('edit.html', recipe=results[0])

@app.route('/delete/<int:recipe_id>')
def delete_user(recipe_id):
    if 'id' not in session:
        return redirect('/')
    query = "DELETE FROM recipes WHERE id = %(id)s;"
    data = {
        'id': recipe_id
    }
    results = connectToMySQL('recipes').query_db(query,data)
    return redirect('/recipes')

@app.route('/edit/recipe/<int:recipe_id>', methods=['post'])
def update_recipe(recipe_id):
    if 'id' not in session:
        return redirect('/')
    if not validate_recipe(request.form):
        return redirect(f"/edit/{recipe_id}")
    query = "UPDATE recipes SET name=%(name)s, description=%(description)s, instructions=%(instructions)s,under_thirty=%(under_thirty)s,user_id=%(user_id)s, updated_at=NOW() WHERE recipes.id = %(id)s;"
    data ={
        'id': recipe_id,
        'name': request.form['name'],
        'description': request.form['description'],
        'instructions': request.form['instructions'],
        'under_thirty': request.form['under_thirty'],
        'user_id': request.form['user_id']
    }

    results = connectToMySQL('recipes').query_db(query,data)
    return redirect(f"/show/{recipe_id}")

def validate_recipe(recipe):
    is_valid = True
    if len(recipe['name']) < 3:
        is_valid = False
        flash('Recipe name must be at least 3 characters', "recipe")
    if len(recipe['description']) < 3:
        is_valid = False
        flash('Recipe description must be at least 3 characters', "recipe")
    if len(recipe['instructions']) < 3:
        is_valid = False
        flash('Recipe instructions must be at least 3 characters', "recipe")
    return is_valid

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)