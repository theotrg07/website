from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    coins = db.Column(db.Integer)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    link = db.Column(db.String(1000))
    reward = db.Column(db.Integer)
    des = db.Column(db.Text)


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('home'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, coins=500, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created! <a href="/login">Login</a></h1>'
            #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/h')
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.route('/issues')
@login_required
def issues():
    issues = Issue.query.all()
    return render_template("issues.html", issues=issues)

@app.route("/issue/<int:id>")
@login_required
def issue(id):
    issue = Issue.query.get_or_404(id)
    return render_template("issue.html", issue=issue)

@app.route('/add_issue', methods=["POST", "GET"])
def add_issue():
    if request.method == "POST":
        title = request.form["title"]
        link = request.form["link"]
        reward = request.form["coins"]
        des = request.form["description"]
        issue = Issue(title=title, link=link, reward=reward, des=des)
        db.session.add(issue)
        db.session.commit()
        return redirect(url_for("issues"))
    else:
        return render_template("add_issue.html")

#sending coins
@app.route('/send_coins', methods=["POST", "GET"])
def send_coins():
    if request.method == "POST":
        aid = request.form["aid"]
        amt = request.form["amt"]
        aid = int(aid)
        amt = int(amt)
        if current_user.coins < amt:
            return "You don't have enough coins to send"
        current_user.coins = current_user.coins - amt
        db.session.commit()
        account = User.query.get_or_404(aid)
        account.coins = account.coins + amt
        db.session.commit()
        return redirect(url_for("home"))
    else:
        return render_template("send_coins.html")

@app.route('/u')
def users():
    users = User.query.all()
    return render_template("users.html", users=users)

@app.route('/coins/<int:id>')
def coins(id):
    user = User.query.get_or_404(id)
    return f"you have {user.coins} coins"

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)