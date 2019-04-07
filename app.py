import os
from flask import Flask, flash, request, redirect, url_for, render_template, session,Response,abort
from werkzeug.utils import secure_filename
import bcrypt
from flask import send_from_directory
from util import ALLOWED_EXTENSIONS, allowed_file
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt
import json

import boto3
from config import S3_BUCKET,S3_KEY,S3_SECKET_ACCESS_KEY

#s3
s3=boto3.client('s3',aws_access_key_id=S3_KEY,aws_secret_access_key=S3_SECKET_ACCESS_KEY)

#local server
UPLOAD_FOLDER = 'storage'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
engine = create_engine("mysql+pymysql://root:root@localhost/register",pool_size=50, max_overflow=0)
db = scoped_session(sessionmaker(bind=engine))

@app.route("/")
def index():
	return render_template("index.html")

@app.route("/home")
def home():
	if 'log' in session:
		s3_resource=boto3.resource('s3')
		my_bucket=s3_resource.Bucket(S3_BUCKET)
		summaries = my_bucket.objects.filter(Prefix='{}/'.format(session["username"]))

		path = os.path.join(app.config['UPLOAD_FOLDER'], session["username"])
		files = os.listdir(path)
		folder = path
		folder_size = 0
		for (path, dirs, files) in os.walk(folder):
			for file in files:
				filename = os.path.join(path, file)
				folder_size += os.path.getsize(filename)
		storage_space = folder_size/(1024*1024.0)

		return render_template("home.html", files=files, storage_space=storage_space,cloud_files=summaries,my_bucket=my_bucket)
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
				db.execute("INSERT INTO cloud_mini(name,username,password) VALUES (:name,:username,:password)", {
						"name": name, "username": username, "password": secure_password})
				db.commit()
				flash("Registeration successfull , Please Login ", "success")
				s3.put_object(Bucket=S3_BUCKET,Key='{}/.'.format(username))
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
		userdata = db.execute("SELECT username,admin FROM cloud_mini where username=:uname", {
							"uname": uname}).fetchone()
		passdata = db.execute("SELECT password FROM cloud_mini where username=:uname", {
							"uname": uname}).fetchone()

		if userdata is None:
			flash("No user found please check your username", "danger")
			return render_template("login.html")
		else:
			for pd in passdata:
				if sha256_crypt.verify(password, pd):
					session["log"] = True
					if userdata[1]==1:
							session["admin"]=True
					session["username"] = userdata[0]
					flash("Welcome back {} ".format(userdata[0]), "success")
					if "admin" in session:
						return redirect(url_for("admin"))
					else:
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

############## Delete ######################
@app.route('/delete', methods=['POST'])
def delete():
	key = request.form['key']
	print(key)
	s3_resource = boto3.resource('s3')
	my_bucket = s3_resource.Bucket(S3_BUCKET)
	my_bucket.Object(key).delete()

	flash('File deleted successfully')
	return redirect(url_for('home'))

############# DOWNLOAD #######################
@app.route('/download', methods=['POST'])
def download():
	key = request.form['key']

	s3_resource = boto3.resource('s3')
	my_bucket = s3_resource.Bucket(S3_BUCKET)

	file_obj = my_bucket.Object(key).get()

	return Response(
		file_obj['Body'].read(),
		mimetype='text/plain',
		headers={"Content-Disposition": "attachment;filename={}".format(key)}
	)

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
			s3 = boto3.resource('s3')
			s3.Bucket(S3_BUCKET).put_object(Key="{}/{}".format(session['username'],filename),Body=file)

			return redirect("home")
	return render_template("home.html")


@app.route('/uploaded_file/<filename>', methods=["GET", "POST"])
def uploaded_file(filename):
	afile = session["username"]+"/"+filename
	return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], session["username"]),
							filename)



####################################ADMIN####################################################

def toggle_permission(username,current_role):
	toggle_role=1
	if current_role==1:
		toggle_role=0
	db.execute("Update cloud_mini set admin = :toggle_role where username=:username", {
			"toggle_role": toggle_role, "username": username})
	db.commit()
	
@app.route("/admin")
def admin():
	if 'admin' in session:
			return render_template("admin_panel/admin.html")
	abort(404)

@app.route("/admin_user_role")
def admin_user_role():
	if 'admin' in session:
		userdata = db.execute("SELECT username,admin FROM cloud_mini").fetchall()
		print(userdata)
		return render_template("admin_panel/user_role.html",users=userdata)
	abort(404)


@app.route("/remove_admin/<username>")
def remove_admin(username):
		if "admin" in session:
	
			toggle_permission(username,1)
			flash("{} has been removed from Admin privileage".format(username),"danger")
			return redirect("admin_user_role")
		abort(404)

@app.route("/provide_admin/<username>")
def provide_admin(username):
		if "admin" in session:
			toggle_permission(username,0)
			flash("{} has been granted Admin privileage".format(username),"success")
			return redirect("admin_user_role")
		abort(404)

@app.route("/admin_view_users",methods=["GET","POST"])
def admin_view_users():
	if 'admin' in session:
		userdata = db.execute("SELECT username FROM cloud_mini").fetchall()

		if request.method == "POST":
			s3_resource=boto3.resource('s3')
			my_bucket=s3_resource.Bucket(S3_BUCKET)
			summaries = my_bucket.objects.filter(Prefix='{}/'.format(request.form.get("username")))
			return render_template("admin_panel/user_info.html",users=userdata,files=summaries)

		print(userdata)
		return render_template("admin_panel/user_info.html",users=userdata)
	abort(404)
if __name__ == "__main__":
	app.secret_key = "interviewbot"
	app.run(debug=True, port=4221, threaded=True)
