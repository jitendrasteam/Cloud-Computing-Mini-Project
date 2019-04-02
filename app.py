import os
from flask import Flask, flash, request, redirect, url_for, render_template, session
from werkzeug.utils import secure_filename
import bcrypt
from flask import send_from_directory
from util import ALLOWED_EXTENSIONS, allowed_file
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt
import json

UPLOAD_FOLDER = 'storage'


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
engine = create_engine("mysql+pymysql://root:root@localhost/register")
db = scoped_session(sessionmaker(bind=engine))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/home")
def home():
    if 'log' in session:
        path = os.path.join(app.config['UPLOAD_FOLDER'], session["username"])
        files = os.listdir(path)
        folder = path
        folder_size = 0
        for (path, dirs, files) in os.walk(folder):
            for file in files:
                filename = os.path.join(path, file)
                folder_size += os.path.getsize(filename)
        storage_space = folder_size/(1024*1024.0)
        return render_template("home.html", files=files, storage_space=storage_space)
    abort(404)


@app.route("/register", methods=["GET", "POST"])
def register():
    if 'log' in session:
        flash("Your already logged in your account, logout if you want to create new account", "danger")
        return redirect(url_for("home"))
    else:
        if request.method == "POST":
            name = request.form.get("name")
            username = request.form.get("username")
            password = request.form.get("password")
            confirm = request.form.get("confirm")
            secure_password = sha256_crypt.encrypt(str(password))

            if password == confirm:
                db.execute("INSERT INTO users(name,username,password) VALUES (:name,:username,:password)", {
                           "name": name, "username": username, "password": secure_password})
                db.commit()
                flash("Registeration successfull , Please Login ", "success")
                os.mkdir(os.path.join(app.config['UPLOAD_FOLDER'], username))
                return redirect(url_for('login'))
            else:
                flash("Password does not match", "danger")
                return render_template('register.html')
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if 'log' in session:
        flash("Already Logged in , To login with another account logout first", "danger")
        return render_template('home.html')
    if request.method == "POST":
        uname = request.form.get("username")
        password = request.form.get("password")
        userdata = db.execute("SELECT username FROM users where username=:uname", {
                              "uname": uname}).fetchone()
        passdata = db.execute("SELECT password FROM users where username=:uname", {
                              "uname": uname}).fetchone()

        if userdata is None:
            flash("No user found please check your username", "danger")
            return render_template("login.html")
        else:
            for pd in passdata:
                if sha256_crypt.verify(password, pd):
                    session["log"] = True
                    session["username"] = userdata[0]
                    flash("Welcome back {} ".format(userdata[0]), "success")
                    return redirect(url_for("home"))
                else:
                    flash("Wrong password", "danger")
                    return render_template("login.html")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if 'log' in session:
        session["log"] = False
        session.clear()
        flash("Logged out ,Thank you for using our service", "success")
        return redirect(url_for("index"))
    else:
        flash("For logging out you need to login first", "danger")
        return redirect(url_for("index"))

# error handlers


@app.errorhandler(404)
def error404(error):
    return render_template("notallowed.html"), 404


@app.errorhandler(405)
def error405(error):
    return render_template("noaccess.html"), 405


############     FILES   #######################
@app.route('/uploads', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST' or request.method == 'GET':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', "danger")
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', "danger")
            return redirect("home")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            afile = session["username"]+"/"+filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], afile))
            flash('File Uploaded Successfully', "success")
            return redirect("home")
    return render_template("home.html")


@app.route('/uploaded_file/<filename>', methods=["GET", "POST"])
def uploaded_file(filename):
    afile = session["username"]+"/"+filename
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], session["username"]),
                               filename)


if __name__ == "__main__":
    app.secret_key = "interviewbot"
    app.run(debug=True, port=4219, threaded=True)
