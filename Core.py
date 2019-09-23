from flask import Flask, flash, request, redirect, url_for, send_file, abort, send_from_directory, session
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import Form, BooleanField, StringField, PasswordField, validators, SubmitField, TextField
import json
import flask_login
import os
import pathlib
from flask_autoindex import AutoIndex
from twilio.rest import Client
import random
from flask_sqlalchemy import SQLAlchemy
from flask import make_response
import flask as flask
login_manager = LoginManager()


app = Flask(__name__) 
CORS(app)
bcrypt = Bcrypt(app)
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy()
db.init_app(app)

with app.app_context():
    db.create_all()

app.secret_key = "super secret key"
    
@app.errorhandler(404) 
def not_found(e): 
    return render_template("404.html")


UPLOAD_FOLDER = 'static/uploadedfiles/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app.config['UPLOADED_FILES'] = UPLOAD_FOLDER

class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password = db.Column(db.String(80))



def send_confirmation_code(to_number):
    verification_code = generate_code()
    send_sms(to_number, verification_code)
    session['verification_code'] = verification_code
    return verification_code


def generate_code():
    return str(random.randrange(100000, 999999))


def send_sms(to_number, body):
    account_sid = 'ENTER SID HERE'
    auth_token = 'ENTER TOKEN HERE'
    twilio_number = 'ENTER NUMBER HERE'
    client = Client(account_sid, auth_token)
    client.api.messages.create(to_number,
                           from_=twilio_number,
                           body=body)


@app.route('/')
@app.route('/index')
def index():
    if 'username' in session:
        return redirect(url_for('userpage', uname= session['username']))
    return render_template('index.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload/', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files.getlist("file")
        directory = app.config['UPLOADED_FILES'] + session['username']
        if not os.path.exists(directory):
            os.makedirs(directory,mode=0o777, exist_ok=False)
    
        task_name=session['username']
        pathlib.Path(app.config['UPLOADED_FILES'], task_name).mkdir(exist_ok=True)
        for item in file:
            if item.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if item and allowed_file(item.filename):
                filename = secure_filename(item.filename)
                item.save(os.path.join(app.config['UPLOADED_FILES'], task_name, filename))

    return render_template('upload.html')


def writeToJSONFile(path, fileName, data):
    filePathNameWExt = './' + path + '/' + fileName + '.json'
    with open(filePathNameWExt, 'a') as fp:
        json.dump(data, fp)



def logOut():
    flash("Successfully logged out")
    return render_template('login.html', error=error)

class UserLoginForm(Form):
    username = TextField('Username', [validators.Required(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.Required(), validators.Length(min=6, max=200)])


@app.route("/login/",methods=["GET", "POST"])
def login():
    if 'username' in session:
        return redirect(url_for('userpage', uname=session['username']))
    if request.method == "POST":
        uname = request.form["uname"]
        passw = request.form["passw"]
        
        found = user.query.filter_by(username=uname).first()
        if found == None:
            return render_template("login.html")
        if (bcrypt.check_password_hash(found.password, passw)):
            login = True
        if (bcrypt.check_password_hash(found.password, passw)) == False:
            login = False
        if login is not False:
            session['username'] = found.username
            return redirect(url_for('userpage', uname= session['username']))
    return render_template("login.html")

@app.route("/user/", methods=["GET", "POST"])
def userpage():
    if 'username' in session:
        if request.method == "POST":
            if 'settings' in request.form:
                return redirect(url_for ("settings"))
            if 'back' in request.form:
                return redirect(request.referrer)
            if 'upload' in request.form:
                return redirect(url_for("upload_file"))
            if 'MyFiles' in request.form:
                return redirect(url_for("files"))
            elif 'logOut' in request.form:
                    return redirect(url_for("logout"))
        return render_template("user.html", uname= session['username'])
    else:
        return redirect(url_for("login"))

@app.route("/files/", methods=["GET", "POST"])
def files():
    if 'username' in session:

        main_path = '/Users/syvash/Documents/Projects/static/uploadedfiles/' + session['username']
        if os.path.exists(main_path):
            file_list=sorted([f for f in os.listdir(main_path) if not f.startswith('.')], key=lambda f: f.lower())
            if request.method == "POST":
                if 'remove' in request.form:
                    path = '/Users/syvash/Documents/Projects/static/uploadedfiles/' + session['username'] + '/' + request.form["filename"]
                    if os.path.exists(path):
                        os.remove(path)
                        file_list=sorted([f for f in os.listdir(main_path) if not f.startswith('.')], key=lambda f: f.lower())

                        return render_template('files.html', files = file_list, uname= session['username'])
                    else:
                        return render_template('files.html', files = file_list, uname= session['username'])
                if 'rename' in request.form:
                    if request.form["filenameRename"] and request.form["newName"]:
                        targetFile = request.form["filenameRename"]
                        path = '/Users/syvash/Documents/Projects/static/uploadedfiles/' + session['username'] + '/' + targetFile
                        if os.path.exists(path):
                            extension = os.path.splitext(targetFile)[1]
                            newPath = '/Users/syvash/Documents/Projects/static/uploadedfiles/' + session['username'] + '/' + request.form['newName'] + extension
                            os.rename(path, newPath)
                            file_list=sorted([f for f in os.listdir(main_path) if not f.startswith('.')], key=lambda f: f.lower())

                            return render_template ('files.html', files = file_list, uname= session['username'])

                    else:
                        return render_template("files.html", files = file_list, uname= session['username'])

                if 'upload' in request.form:
                    return (redirect(url_for('upload_file')))
            return render_template('files.html', files = file_list, uname= session['username'])
        else:
            return redirect(url_for("upload_file"))
    else:
        return redirect(url_for("login"))




@app.route("/register/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = request.form['uname']
        mail = bcrypt.generate_password_hash(request.form['mail']).decode('utf-8')
        passw = bcrypt.generate_password_hash(request.form['passw']).decode('utf-8')
        found = user.query.filter_by(username=uname).first()
        if found != None: 
            if uname == user.query.filter_by(username=uname).first().username:
                render_template("register.html")

        register = user(username = uname, email = mail, password = passw)

        session['username'] = uname
        session['password'] = passw
        session['email'] = mail
        global registerDict
        registerDict = register

        session['phone'] = request.form['phone']

        send_confirmation_code(session['phone'])



        return redirect(url_for("confirmation"))
    return render_template("register.html")


@app.route('/confirmation/', methods=['GET', 'POST'])
def confirmation():
    if request.method == 'POST':
        if request.form['verification_code'] == session['verification_code']:
            register = registerDict
            db.session.add(register)
            db.session.commit()
            return redirect(url_for('login'))
        flash('Wrong code. Please try again.', 'erfror')

    return render_template('confirmation.html')

@app.route('/settings/', methods = ["POST", "GET"])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    else:
        if request.method == "POST":
            if 'changepw' in request.form:
                return redirect(url_for ("changepass"))
            if 'back' in request.form:
                return redirect(request.referrer)
            elif 'logOut' in request.form:
                return redirect(url_for("logout"))
            if 'delete' in request.form:
                print (session['username'])
                found = user.query.filter_by(username='testinguser').first()
                print (found)
                db.session.commit()


        return render_template('settings.html', uname = session['username'])




@app.route('/changepass/', methods=['GET', 'POST'])
def changepass():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == "POST" and 'username' in session:
        uname = request.form['uname']
        oldpassw = request.form['oldpassw']
        newpassw = request.form['newpassw']
        found = user.query.filter_by(username=uname).first()
        if (bcrypt.check_password_hash(found.password, oldpassw)):
            found.password = bcrypt.generate_password_hash(newpassw).decode('utf-8')
            db.session.commit()
            return redirect(url_for("login"))
    return render_template("changepass.html", uname= session['username'])


@app.route('/logout/', methods=['GET'])
def logout():
    session.pop('username', None)
    logout_user()
    return redirect(url_for('login'))



@app.route('/secret')
def secret():
    return '''
     <div className="App">
      <title>LOGGED IN</title>
      </div> '''
def create_app(config_filename):
    app = Flask(__name__)
    app.register_error_handler(404, page_not_found)
    return app

if __name__ == "__main__":
    app.run(debug=True)