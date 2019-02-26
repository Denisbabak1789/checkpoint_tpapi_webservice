# -*- coding: utf-8 -*- 
import os, json, requests, base64, hashlib

from flask import Flask, render_template, flash, redirect, url_for, request, send_from_directory, send_file
from app import app, db
from app.forms import LoginForm, RegistrationForm
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Files_te, tpapi


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
            #Request to check files
            parsed_json = tpapi.query_file(md5=f.md5)
            te_status = parsed_json["response"][0]["te"]['status']['label']
            if te_status == "FOUND":
                te_verdict = parsed_json["response"][0]["te"]["te"]["combined_verdict"]
            else:
                te_verdict = "Unknown"
                
            #Write changed status and verdict in db
            fn = Files_te.query.filter(Files_te.md5==f.md5,Files_te.user_id==user_id).first()
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
            current_username = User.query.filter_by(username=current_user.username).first()
            f = Files_te.query.filter(Files_te.filename==filename,Files_te.user_id==current_username.id).first()
            if f is None:
                if not os.path.exists(os.getcwd()+'/uploads'):
                    os.mkdir(os.getcwd()+'/uploads')
                file.save(os.getcwd()+'/uploads/'+filename)
                return redirect(url_for('return_cleaned_file',filename=filename)) 
            else:
                return redirect(url_for('index'))
        else:
            flash("File type isn't supported")
    return render_template('upload_file.html')

@app.route('/return-files/<filename>')
def return_cleaned_file(filename):
    with open(os.getcwd()+'/uploads/'+filename, 'rb') as file_to_send:
        encoded_file = base64.b64encode(file_to_send.read()).decode('ascii')
    #Check if file isn't empty
    if encoded_file == "":
        flash('File is empty! Please, try again!')
        return redirect(url_for('upload_file'))
    #Request to upload file
    parsed_json = tpapi.upload_file(encoded_file=encoded_file, filename=filename)

    try:
        resp_scrub = parsed_json["response"][0]["scrub"]
        resp_te = parsed_json["response"][0]["te"]
    except KeyError as err:
        print("Response is empty. Error: ",err)
        flash("Couldn't get response, please, try again!")
        return redirect(url_for('upload_file'))
    
    #Check scrub response
    resp_scrub_result = parsed_json["response"][0]["scrub"]["scrub_result"]
    if resp_scrub_result != 0:
        print("Scrub failed")
        flash("Couldn't clean the file, please try again")
        return redirect(url_for('upload_file'))
    
    #Get cleaned file data
    cleaned_file_enc = parsed_json["response"][0]["scrub"]["file_enc_data"]
    #Decode from base64
    cleaned_file_dec = base64.b64decode(cleaned_file_enc)
    #Is there “cleaned file” dir?
    if not os.path.exists(os.getcwd()+'/cleaned_files/'):
        os.mkdir(os.getcwd()+'/cleaned_files/')
    #Save cleaned file into dir
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
