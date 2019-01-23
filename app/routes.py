# -*- coding: utf-8 -*- 
import os
import json
import requests
import base64

from flask import Flask, render_template, flash, redirect, url_for, request, send_from_directory, send_file
from app import app
from app.forms import LoginForm
from werkzeug.utils import secure_filename


#Check if extensions is allowed 
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

#Home page
@app.route('/')
@app.route('/index')
def index():
    user = {'username': 'Denys'}
    return render_template('index.html', title='Home', user=user)

@app.route('/upload_file', methods=['GET', 'POST'])
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
	#Encode uploaded file 
    with open(abs_file_path, 'rb') as file_to_send:
        encoded_file = base64.b64encode(file_to_send.read()).decode('ascii')
    #Create reuest
	data = {"request":[{"protocol_version": "1.1","request_name": "UploadFile","file_enc_data":encoded_file,"file_orig_name": filename,"scrub_options": {"scrub_method": 2}}]}
    with open("request_1.json", "w", encoding='utf8') as write_file:
        json.dump(data, write_file, ensure_ascii=False)
    data_request = open('./request_1.json', 'rb').read()
    #Send reuest
	res = requests.post(url=app.config['URL'], data=data_request,headers={'Content-Type': 'application/octet-stream'},verify=False)
    #Parse responce
	resp = res.json()
    json_data = json.dumps(resp)
    parsed_json = json.loads(json_data)
    #Get encoded file from json
	cleaned_file_enc = parsed_json["response"][0]["scrub"]["file_enc_data"]
    #Decode cleaned file
	cleaned_file_dec = base64.b64decode(cleaned_file_enc)
    #Save cleanded file
	output = open(app.config['CLEANED_FOLDER']+filename+".cleaned.pdf", "wb")
    output.write(cleaned_file_dec)
    output.close()
	#Send cleaned file to user
    return send_file(app.config['CLEANED_FOLDER']+filename+".cleaned.pdf", mimetype='application/pdf', as_attachment=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        flash('Login requested for user {}, remember_me={}'.format(
            form.username.data, form.remember_me.data))
        return redirect(url_for('upload_file'))
    return render_template('login.html', title='Sign In', form=form)
