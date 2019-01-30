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
    files = Files_te.query.filter_by(user_id=current_username.id).all()
    check_files()
    return render_template('index.html', title='Home', files=files)

@app.route('/check_files')
def check_files():
    files_status = ("UPLOAD_SUCCESS", "PENDING")
    for k in files_status:
        #get all files with status UPLOAD_SUCCESS
        f = Files_te.query.filter_by(te_status=k).all()
        #Send query to check if status was changed
        for p in f:
            data = {"request":[{"protocol_version": "1.1", "request_name": "QueryFile", "md5": p.md5, "features": ["te"],"te": {} }]}
            with open("request_te_check.json", "w", encoding='utf8') as write_file:
                json.dump(data, write_file, ensure_ascii=False)
            data_request = open('./request_te_check.json', 'rb').read()
            res = requests.post(url=app.config['URL'],
                                data=data_request,
                                headers={'Content-Type': 'application/octet-stream'},
                                verify=False)
            resp = res.json()
            json_data = json.dumps(resp)
            parsed_json = json.loads(json_data)
            #Get current status
            te_status = parsed_json["response"][0]["te"]['status']['label']
            if te_status == "FOUND":
                te_verdict = parsed_json["response"][0]["te"]["te"]["combined_verdict"]
            else:
                te_verdict = "Unknown"
            #Change status and verdict in db
            fn = Files_te.query.filter_by(md5=p.md5).first()
            fn.te_status = te_status
            fn.te_verdict = te_verdict
            db.session.commit()
    return redirect(url_for('index'))


@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(app.config['UPLOAD_FOLDER'] + filename)
            return redirect(url_for('return_cleaned_file',filename=filename))
    return render_template('upload_file.html')

@app.route('/return-files/<filename>')
def return_cleaned_file(filename):
    abs_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(abs_file_path, 'rb') as file_to_send:
        encoded_file = base64.b64encode(file_to_send.read()).decode('ascii')
    data = {"request":[{
            "protocol_version": "1.1", 
            "request_name": "UploadFile",
            "file_enc_data":encoded_file, 
            "file_orig_name": filename, 
            "scrub_options": {"scrub_method": 2},
            "te_options": {
                "file_name": filename,
                "file_type": "pdf",
                "features": ["te"],
                "te": {"rule_id": 1}
            }   
        }]
       }
    with open("request_1.json", "w", encoding='utf8') as write_file:
        json.dump(data, write_file, ensure_ascii=False)
    data_request = open('./request_1.json', 'rb').read()
    res = requests.post(url=app.config['URL'], data=data_request,headers={'Content-Type': 'application/octet-stream'},verify=False)
    resp = res.json()
    json_data = json.dumps(resp)
    parsed_json = json.loads(json_data)
    cleaned_file_enc = parsed_json["response"][0]["scrub"]["file_enc_data"]
    cleaned_file_dec = base64.b64decode(cleaned_file_enc)
    output = open(app.config['CLEANED_FOLDER']+filename+".cleaned.pdf", "wb")
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
    return send_file(app.config['CLEANED_FOLDER']+filename+".cleaned.pdf", mimetype='application/pdf', as_attachment=True)

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
