import os, json, requests
from datetime import datetime
from app import app, db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    files_te = db.relationship('Files_te', backref='user', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Files_te(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), index=True)
    md5 = db.Column(db.String(40), index=True)
    te_verdict = db.Column(db.String(50))
    te_status = db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Files_te {}>'.format(self.filename)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

def request(data, content_type):
    request_json = json.dumps(data)
    res = requests.post(url=app.config['URL'],data=request_json,headers={'Content-Type':content_type }, verify=False)
    resp = res.json()
    json_data = json.dumps(resp)
    parsed_json = json.loads(json_data)
    return parsed_json

class tpapi:
    
    def query_file(md5):
        data = {"request":[{
            "protocol_version": "1.1", 
            "request_name": "QueryFile", 
            "md5": md5, 
            "features": ["te"],
            "te": {} 
        }] }
        content_type = "application/json"
        return request(data, content_type)
    
    def upload_file(encoded_file, filename):
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
           }] }
        content_type = "application/octet-stream"
        return request(data, content_type)
    
    


        