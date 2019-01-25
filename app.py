import os
import json
import requests
import base64
from flask import Flask, request, send_from_directory, redirect, url_for, send_file
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/app/uploads/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'doc'}
SCRUB_URL = "https://192.168.1.60/UserCheck/TPAPI"

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

#Check allowed extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

#Main page		   
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
		    #Get filename 
            filename = secure_filename(file.filename)
			#Save file
            file.save(app.config['UPLOAD_FOLDER'] + filename)
			#Redirect to scrubing
            return redirect(url_for('return_cleaned_file',filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload file to clean</h1>
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''


#Send to scrubing
@app.route('/return-files/<filename>')
def return_cleaned_file(filename):
    path = '/app/uploads/'
    abs_file_path = os.path.join(path, filename)
	#encode file 
    with open(abs_file_path, 'rb') as file_to_send:
        encoded_file = base64.b64encode(file_to_send.read()).decode('ascii')
	#json for API request
    data = {"request":[{"protocol_version": "1.1","request_name": "UploadFile","file_enc_data":encoded_file,"file_orig_name": filename,"scrub_options": {"scrub_method": 2}}]}
    with open("request_1.json", "w", encoding='utf8') as write_file:
        json.dump(data, write_file, ensure_ascii=False)
    data_request = open('./request_1.json', 'rb').read()
	#Send request 
    res = requests.post(url=SCRUB_URL, data=data_request,headers={'Content-Type': 'application/octet-stream'},verify=False)
	#Parse responce
    resp = res.json()
    json_data = json.dumps(resp)
    parsed_json = json.loads(json_data)
    cleaned_file_enc = parsed_json["response"][0]["scrub"]["file_enc_data"]
	#Decode base64 responce
    cleaned_file_dec = base64.b64decode(cleaned_file_enc)
	#Write to file
    output = open(filename+".cleaned.pdf", "wb")
    output.write(cleaned_file_dec)
    output.close()
	#Download cleaned file
    return send_file('/app/'+filename+".cleaned.pdf", mimetype='application/pdf', as_attachment=True)

	
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')