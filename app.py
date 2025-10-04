from flask import Flask, render_template, url_for, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)

app.secret_key = "YourSecretKey"  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password= db.Column(db.String(128), nullable=False)

def set_password(self, password):
    self_password_hash = generate_password_hash(password)

def check_password(self, password):
    return check_password_hash(self.password_hash, password)



@app.route('/', methods=['POST','GET'])
def home():
    if "email" in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if "email" in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = email
            flash('Logged in successfully!', 'success') 
            return redirect(url_for('dashboard')) 
        else:
            flash('Invalid email or password. Please try again.', 'danger') 
            return render_template('login.html')
    return render_template('login.html')


@app.route('/sign-up', methods=['POST','GET'])
def sign_up():
    return render_template('sign-up.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('home'))

@app.route('/dashboard.html', methods=['POST','GET'])
def dashboard():
    if "email" not in session:
        flash("Please log in to view the dashboard.", 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'])

@app.route('/courses')
def courses():
    return render_template('courses.html')

@app.route('/scholarship')
def scholarship():
    return render_template('scholarship.html')

@app.route('/certifications')
def certifications():
    return render_template('certifications.html')

@app.route('/supports')
def supports():
    return render_template('supports.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/admin_login123')
def admin_login():
    return render_template('admin_login.html')

if __name__ == '__main__':
    app.run(debug=True)