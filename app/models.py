from datetime import datetime
from app import db, login
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
