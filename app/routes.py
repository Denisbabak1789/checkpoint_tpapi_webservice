# -*- coding: utf-8 -*- 
import os
import json
import requests
import base64

from flask import Flask, render_template, flash, redirect, url_for, request, send_from_directory, send_file
from app import app, db
from app.forms import LoginForm, RegistrationForm
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Files_te


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
@app.route('/index')
@login_required
def index():
    current_username = User.query.filter_by(username=current_user.username).first()
    check_files(current_username.id)
    files = Files_te.query.filter_by(user_id=current_username.id).all()
    return render_template('index.html', title='Home', files=files)

def check_files(user_id):
    #Get all files that have status NOT FOUND
    for f in Files_te.query.filter(Files_te.user_id==user_id).filter(Files_te.te_status!='FOUND').all():
        if f is not None:
            #Send query to get new status of files
            #Create request for based on md5
            data = {"request":[{"protocol_version": "1.1", "request_name": "QueryFile", "md5": f.md5, "features": ["te"],"te": {} }]}
            #Encode in json
            request_json = json.dumps(data)
            print(request_json)
            #Send request and get response
            res = requests.post(url=app.config['URL'], data=request_json, headers={'Content-Type': 'application/json'}, verify=False)
            #Parce response
            resp = res.json()
            print(resp)
            json_data = json.dumps(resp)
            parsed_json = json.loads(json_data)
            #Get current te status
            te_status = parsed_json["response"][0]["te"]['status']['label']
            if te_status == "FOUND":
                te_verdict = parsed_json["response"][0]["te"]["te"]["combined_verdict"]
            else:
                te_verdict = "Unknown"
            #Change status and verdict in db
            fn = Files_te.query.filter_by(md5=f.md5).first()
            fn.te_status = te_status
            fn.te_verdict = te_verdict
            db.session.commit()


@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            print(filename)
            current_username = User.query.filter_by(username=current_user.username).first()
            f = Files_te.query.filter(Files_te.filename==filename,Files_te.user_id==current_username.id).first()
            if f is None:
                if not os.path.exists(os.getcwd()+'/uploads'):
                    os.mkdir(os.getcwd()+'/uploads')
                file.save(os.getcwd()+'/uploads/'+filename)
 #           md5_hash = hashlib.md5()
 #           with open(os.getcwd()+'/uploads/'+filename,"rb") as fmd:
 #               # Read and update hash in chunks of 4K
 #               for byte_block in iter(lambda: fmd.read(4096),b""):
 #                   md5_hash.update(byte_block)
 #               print(md5_hash.hexdigest())
 #               f = Files_te.query.filter_by(md5=md5_hash.hexdigest()).all()
 #           print("md5 in db:")
 #           print(f) 
 #           if f is None:
 #               print("file not found in db")
 #               return redirect(url_for('return_cleaned_file',filename=filename))
 #           else:
 #               print("file is laready exist in db")
 #               return redirect(url_for('index'))
                print("file was saved")
                return redirect(url_for('return_cleaned_file',filename=filename)) 
            else:
                return redirect(url_for('index'))
    return render_template('upload_file.html')

@app.route('/return-files/<filename>')
def return_cleaned_file(filename):
#    abs_file_path = os.path.join(os.getcwd()+'/uploads/', filename)
    with open(os.getcwd()+'/uploads/'+filename, 'rb') as file_to_send:
        encoded_file = base64.b64encode(file_to_send.read()).decode('ascii')
    data = {"request":[{
            "protocol_version": "1.1",
            "request_name": "UploadFile",
            "file_enc_data": encoded_file,
            "file_orig_name": filename,
            "scrub_options": {"scrub_method": 2},
            "te_options": {
                "file_name": filename,
                "features": ["te"],
                "te": {"rule_id": 1}
                }
           }]
           }
    request_json = json.dumps(data)
    res = requests.post(url=app.config['URL'],data=request_json,headers={'Content-Type':'application/octet-stream'},verify=False) 
    resp = res.json()
    json_data = json.dumps(resp)
    parsed_json = json.loads(json_data)
    cleaned_file_enc = parsed_json["response"][0]["scrub"]["file_enc_data"]
    cleaned_file_dec = base64.b64decode(cleaned_file_enc)
    if not os.path.exists(os.getcwd()+'/cleaned_files/'):
        os.mkdir(os.getcwd()+'/cleaned_files/')
    output = open(os.getcwd()+'/cleaned_files/'+filename+".cleaned.pdf", "wb")
    output.write(cleaned_file_dec)
    output.close()
    te_md5 = parsed_json["response"][0]["te"]['md5']
    te_status = parsed_json["response"][0]["te"]['status']['label']
    if te_status == "FOUND":
        te_verdict = parsed_json["response"][0]["te"]["te"]["combined_verdict"]
    else:
        te_verdict = "Unknown"
    current_username = User.query.filter_by(username=current_user.username).first()
    files_te_info = Files_te(filename=filename, md5=te_md5, te_status=te_status, te_verdict=te_verdict, user_id=current_username.id)
    #Write to db
    db.session.add(files_te_info)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/download_file/<filename>')
def download_file(filename):
    return send_file(os.getcwd()+'/cleaned_files/'+filename+".cleaned.pdf", mimetype='application/pdf', as_attachment=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
