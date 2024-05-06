from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_bcrypt import Bcrypt
import re
from mongita import MongitaClientDisk
from datetime import datetime
from random import sample
from bson import ObjectId

app = Flask(__name__)
app.secret_key = 'Secret123'
bcrypt = Bcrypt(app)

# Initialize Mongita database
client = MongitaClientDisk("database")
db = client["my_database"]
users_collection = db["users"]
quotes_collection = db["quotes"]
comments_collection = db["comments"]

# Function to display flash messages
def show_flash(message, category):
    flash(message, category)

# Function to validate password complexity
def is_valid_password(password):
    return re.match(r'^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.*[0-9])(?=.*[a-z]).{8,}$', password)

@app.route('/')
def home():
    return render_template('index.html')

# Route for signing up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        # Check if the email already exists
        if users_collection.find_one({'email': email}):
            show_flash("Email already exists! Please use a different email.", "error")
            return redirect(url_for('signup'))

        # Check if the username already exists
        if users_collection.find_one({'username': username}):
            show_flash("Username already exists! Please choose a different one.", "error")
            return redirect(url_for('signup'))

        # Validate password complexity
        if not is_valid_password(password):
            show_flash("Password must be at least 8 characters long and contain at least one uppercase letter, one special character, and one digit.", "error")
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert new user into the database with hashed password
        user_data = {'email': email, 'username': username, 'password': hashed_password}
        users_collection.insert_one(user_data)
        
        show_flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# Route for logging in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Retrieve user data from the database
        user = users_collection.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['email'] = email
            return redirect(url_for('dashboard'))
        else:
            show_flash("Invalid email or password. Please try again.", "error")

    return render_template('login.html')

# Route for dashboard
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        email = session['email']
        user = users_collection.find_one({'email': email})
        if user:
            return render_template('dashboard.html', user=user)
        else:
            show_flash("User not found.", "error")
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

# Route for adding a quote
@app.route('/add_quote', methods=['GET', 'POST'])
def add_quote():
    if request.method == 'POST':
        quote_text = request.form['quote_text']
        author = request.form['author']
        
        if 'logged_in' in session:
            email = session['email']
            user = users_collection.find_one({'email': email})
            if user:
                username = user['username']
                quote_data = {'quote_text': quote_text, 'author': author, 'added_by': username, 'timestamp': datetime.now()}
                quotes_collection.insert_one(quote_data)
                return redirect(url_for('dashboard'))
        return "User not found."

    return render_template('addQuote.html')    

# Route for viewing user's quotes
@app.route('/my_quotes')
def my_quotes():
    if 'logged_in' in session:
        email = session['email']
        user = users_collection.find_one({'email': email})
        if user:
            username = user['username']
            user_quotes = list(quotes_collection.find({'added_by': username}))
            return render_template('myQuotes.html', user_quotes=user_quotes)
        else:
            show_flash("User not found.", "error")
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

# Route for trying the app
@app.route('/try_our_app')
def try_our_app():
    all_quotes = list(quotes_collection.find({}))
    random_quotes = sample(all_quotes, 10) if len(all_quotes) >= 10 else all_quotes
    return render_template('tryOurApp.html', random_quotes=random_quotes)

# Route for deleting a quote
@app.route('/delete_quote', methods=['POST'])
def delete_quote():
    if 'logged_in' in session:
        quote_id = request.form.get('quote_id')

        if quote_id:
            result = quotes_collection.delete_one({'_id': ObjectId(quote_id)})

            if result.deleted_count > 0:
                return redirect(url_for('my_quotes'))
            else:
                show_flash("Quote not found or deletion failed.", "error")
        else:
            show_flash("Invalid quote ID.", "error")
    else:
        return redirect(url_for('login'))

# Route for editing a quote
@app.route('/editQuote', methods=['GET', 'POST'])
def edit_quote():
    if request.method == 'GET':
        quote_id = request.args.get('quote_id')
        if quote_id:
            quote = quotes_collection.find_one({'_id': ObjectId(quote_id)})
            if quote:
                return render_template('edit_quote.html', quote=quote)
            else:
                show_flash("Quote not found.", "error")
        else:
            show_flash("Invalid quote ID.", "error")
    
    elif request.method == 'POST':
        quote_id = request.form['quote_id']
        quote_text = request.form['quote_text']
        author = request.form['author']

        result = quotes_collection.update_one({'_id': ObjectId(quote_id)}, {'$set': {'quote_text': quote_text, 'author': author}})
        if result.modified_count > 0:
            return redirect(url_for('my_quotes'))
        else:
            show_flash("Failed to update quote.", "error")

# Route for logging out
@app.route('/logout')
def logout():
    if 'logged_in' in session:
        session.pop('logged_in', None)
        session.pop('email', None)
    return redirect(url_for('login'))

# Route for commenting on a quote
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'GET':
        quote_id = request.args.get('quote_id')
        if quote_id:
            quote = quotes_collection.find_one({'_id': ObjectId(quote_id)})
            if quote:
                return render_template('comment.html', quote=quote)
            else:
                show_flash("Quote not found.", "error")
        else:
            show_flash("Invalid quote ID.", "error")
    
    elif request.method == 'POST':
        quote_id = request.form['quote_id']
        comment_text = request.form['comment_text']

        if 'email' in session:
            user_email = session['email']
        else:
            return redirect(url_for('login'))

        comment_data = {
            'quote_id': quote_id,
            'comment_text': comment_text,
            'user_email': user_email,
            'timestamp': datetime.now()
        }
        comments_collection.insert_one(comment_data)
        return redirect(url_for('try_our_app'))

# Route for viewing comments on a quote
@app.route('/comments')
def view_comments():
    quote_id = request.args.get('quote_id')
    if quote_id:
        quote_comments = list(comments_collection.find({'quote_id': quote_id}))
        return render_template('viewComments.html', quote_comments=quote_comments)
    else:
        show_flash("Invalid quote ID.", "error")

# Route for viewing comments added by the logged-in user
@app.route('/view_user_comments')
def view_user_comments():
    if 'email' in session:
        user_email = session['email']
        user_comments = list(comments_collection.find({'user_email': user_email}))
        
        for comment in user_comments:
            quote_id = comment['quote_id']
            quote_data = quotes_collection.find_one({'_id': ObjectId(quote_id)})
            comment['quote_data'] = quote_data
        
        return render_template('view_user_comments.html', user_comments=user_comments)
    else:
        return redirect(url_for('login'))

# Route for deleting a comment
@app.route('/delete_comment/<comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'email' in session:
        user_email = session['email']
        comment = comments_collection.find_one({'_id': ObjectId(comment_id), 'user_email': user_email})
        if comment:
            comments_collection.delete_one({'_id': ObjectId(comment_id)})
            return jsonify({'success': True, 'message': 'Comment deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Unauthorized or Comment not found'}), 403
    else:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

if __name__ == '__main__':
    app.run(debug=True)
