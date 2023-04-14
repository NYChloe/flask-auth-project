from flask import Flask, render_template, request, url_for, redirect, send_from_directory, flash
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "USER"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # Line below only required once, when creating DB.


# db.create_all()


##CREATE WTFORM

# class LoginForm(FlaskForm):
#    name = StringField("Name", validators=[DataRequired()])
#    email = EmailField("Email", validators=[DataRequired()])
#    password = StringField("Password", validators=[DataRequired()])
#    submit = SubmitField("Log in")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!", "error")
            return redirect(url_for('login'))

        safe_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8)
        # new_user = User()
        # new_user.email = request.form['email']
        # new_user.password = safe_password
        # new_user.name = request.form['name']
        new_user = User(
           email=request.form.get('email'),
           name=request.form.get('name'),
           password=request.form.get('password')
        )

        db.session.add(new_user)
        db.session.commit()
        # log in and authenticate user after adding details to database:
        login_user(new_user)
        return redirect(url_for('secrets'))

    return render_template("register.html",logged_in=current_user.is_authenticated)


# @app.route('/delete/<user_id>')
# def delete_user(user_id):
#    user_to_delete = User.query.get(user_id)
#    db.session.delete(user_to_delete)
#    db.session.commit()
#    return redirect("login.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        # entered info
        email = request.form.get('email')
        password = request.form.get('password')
        # check user by email:
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist, please try again.", 'error')
            redirect(url_for('login'))
        # check stored password against entered password hashed:
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.', 'error')
            redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for("secrets"))

    # form = LoginForm()
    # if form.validate_on_submit():
    #    login_user(user)
    #    flask.flash('Logged in successfully.')
    #    next = flask.request.args.get('next')
    #
    #    if not is_safe_url(next):
    #        return flask.abort(400)
    #
    #    return flask.redirect(next or flask.url_for('index'))
    # return flask.render_template('login.html', form=form)

    return render_template("login.html",logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    # name = request.args.get('name')
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name,logged_in=True)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
        directory='static', path="files/cheat_sheet.pdf",  # as_attachment=True
    )


# @app.route("/download")
# def download(name):
#    app.config['UPLOAD_FOLDER']='static/files'
#    name= 'cheat_sheet.pdf'
#    return send_from_directory(
#        app.config['UPLOAD_FOLDER'], name, as_attachment=False
#    )


if __name__ == "__main__":
    app.run(debug=True)
