from flask import Flask, flash, request, Response, redirect, url_for, render_template, jsonify, send_file, send_from_directory, make_response
import urllib3.request
from flask_mail import Mail,Message
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import argparse
from PIL import Image
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta, date
import jwt as jwt
import sys
import requests
from pdf2image import convert_from_path
from flask_cors import CORS
import os
import cv2
from random2 import randint
import json
import easyocr
import urllib.request
from functools import wraps
import re
from datetime import datetime

global reader
reader = easyocr.Reader(lang_list=['en'], gpu = True)
global counter 
counter =0
outs = []
global out, filepath, filename, filelimit, filena, limit
app = Flask(__name__)
mail=Mail(app)
CORS(app)
db = SQLAlchemy(app)
UPLOAD_FOLDER = 'static/uploads/'
app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['JSON_AS_ASCII'] = False
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///ocr_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=465
app.config["MAIL_USERNAME"]='thethreesaadman@gmail.com'
app.config['MAIL_PASSWORD']='shurjodoetmi'                    #you have to give your password of gmail account
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
mail=Mail(app)

global email, f_name, l_name, hashed_password,otp, free_api
free_api = "free-kj77n-kjnkjnj8-9iu8u"
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif', 'pdf'])
limit = 6

class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(80))
    email = db.Column(db.String(80))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    api_key = db.Column(db.String(80))
    counter = db.Column(db.Integer)

    def json(self):
        return {'id': self.id, 'public_id':self.public_id, 'email': self.email, 'first_name':self.first_name, 'last_name':self.last_name, 'password':self.password, 'admin':self.admin, 'api_key':self.api_key,'counter':self.counter}
        
    def get_all_users():
        '''function to get all attendance in our database'''
        return [Users.json(us) for us in Users.query.all()]

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        headers = request.headers
        key = request.args.get('api_key')
        
        token = None
        bearer = headers.get('Authorization')    # Bearer YourTokenHere
        token = bearer.split()[1] 
        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            print('TOKEN', token)
            # data = jwt.decode(token, app.config['SECRET_KEY'])
            data = jwt.decode(token, options={"verify_signature": False})
            print(data)
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator
 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS    
 
def comma_separated_params_to_list(param):
    result = []
    for val in param.split(','):
        if val:
            result.append(val)
    return result

def extractor(te):
    
    import re
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    elst = re.findall(regex, te)
    ph =[]
    nn = []
    nlst =[]
    res ={}
    nlst = re.findall('[0-9]+', te)
    dates = re.findall(r'\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}|\d{4}/\d{2}/\d{2}|\d{2}/\d{2}/\d{4}', te)
    # urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|http?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', te)
    urls = re.findall("(?P<url>https?://[^\s]+)", te)
#     urls = re.findall(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|(([^\s()<>]+|(([^\s()<>]+)))))+(?:(([^\s()<>]+|(([^\s()<>]+))))|[^\s`!()[]{};:'\".,<>?«»“”‘’]))", te)
    if nlst:
        for i in range(len(nlst)):
            if (nlst[i][0:2] == '01' and len(nlst[i])== 11 ) or (nlst[i][0:4] == '8801' and len(nlst[i])== 13):
                ph.append(nlst[i])
                nn.append(nlst[i])
            elif len(nlst[i])>9:
                nn.append(nlst[i])
        for n in nn:
           nlst.remove(n)
        if nlst:
            # digits = n
            res['digit']=nlst
    if elst:
        em = elst[0]
        res['email']=em
    if ph:
        phone = ph[0]
        res['phone']=phone
    if dates:
        res['dates']=dates
    if urls:
        res['urls']=urls
    
    return res
 
@app.route('/', methods=['GET'])
def show():
    return "OCR for 80 languages"

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
    global email, f_name, l_name, hashed_password,otp
    data = request.get_json()
    print("Checking")
    otp=randint(000000,999999)
    email=data['email']
    f_name=data['first_name']
    l_name=data['last_name']
    hashed_password = generate_password_hash(data['password'], method='sha256')
    msg=Message(subject='OTP',sender='thethreesaadman@gmail.com',recipients=[email])
    msg.body=str(otp)
    mail.send(msg)
    # return render_template('verify.html')
    return jsonify({'message': 'Please verify your email by the provided OTP'})

@app.route('/validate',methods=['POST'])
def validate():
    global email, f_name, l_name, hashed_password
    user_otp=request.get_json()['otp']
    if otp==int(user_otp):
        new_user = Users(public_id=str(uuid.uuid4()), email=email,first_name=f_name,last_name=l_name, password=hashed_password, admin=False, api_key=free_api,counter=str(0)) 
        db.session.add(new_user)  
        db.session.commit()
        return jsonify({"message": "Email varification succesfull and added to our Database"})
    return jsonify({"message": "Please Try Again"})

@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
    auth = request.form
    if not auth:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
    username = auth['username']
    password = auth['password']

    user = Users.query.filter_by(email=username).first()   
     
    if check_password_hash(user.password, password):

        token = jwt.encode({'public_id': user.public_id, 'email':username, 'exp' : datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])  
        return jsonify({'token' : token})

    return make_response('could not verify 2',  401, {'WWW.Authentication': 'Basic realm: "login required"'})

@app.route('/api', methods=['POST'])
@token_required
def get_limit(current_user):
    if 'api' not in request.get_json():
        return jsonify({'message' : "Please provide the api limit"})
    data = request.get_json()['api']
    public_id = current_user.public_id
    api_key = jwt.encode({'limit': data, 'public_id':public_id}, app.config['SECRET_KEY'])
    current_user.api_key = api_key
    current_user.counter = 0
    db.session.commit()
    return jsonify({'message' : "Your API service is upgraded", "api_key":api_key, "Request Limit":data})

@app.route('/get_result', methods=['POST'])
@token_required
def upload_image(current_user):
    global counter, out, outs, filepath, filename, filelimit, reader, filena, limit
    outs = []
    headers = request.headers
    ## issue need to be resolved
    if "api_key" not in headers:
        return jsonify({'message': 'You don\'t have any API_key to continue.'})
    api_key = headers.get('api_key')
    if current_user.api_key != api_key:
        return jsonify({'message': 'Please provide the correct API, which was assigned.'})
    if request.method == 'POST':
        current_user.counter = str(int(current_user.counter)+1)
        if api_key == free_api:
            # limit = 6
            if int(current_user.counter) > 6:
                return jsonify({'message': 'API limit has reached. Please switch to advanced options to continue.'})
        else:
            ex_api = jwt.decode(api_key, options={"verify_signature": False})
            limit = ex_api['limit']
            if int(current_user.counter) > int(limit):
                return jsonify({'message': 'API limit has reached. Please switch to advanced options to continue.'})
        db.session.commit()
        remained = int(limit) - current_user.counter 
        if 'language' in request.args:
            params = request.args.getlist('language') or request.form.getlist('language')
            if len(params) == 1 and ',' in params[0]:
                lang = comma_separated_params_to_list(params[0])
            else:
                lang = params
            reader = easyocr.Reader(lang_list=lang, gpu = True)
        if 'file' not in request.files:
            if 'url' in request.args:
                filename = 'uimage.jpg'
                filepath = 'static/uploads/'+filename
                url = str(request.args.get('url'))
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
                print(url)
                urllib.request.urlretrieve(url, os.path.join(app.config['UPLOAD_FOLDER'], filename))
                img = cv2.imread('static/uploads/'+filename)
                img = cv2.fastNlMeansDenoisingColored(img,None,10,10,7,21)
                cv2.imwrite('static/uploads/'+filename, img)
                img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                out = reader.readtext('static/uploads/'+filename,detail =0)
                overlay()
                text=""
                for n in out:
                    text = text+" "+n
                res = extractor(text)
                dict = {"text":out, "elements_extracted":res, "imageURL":f'http://103.85.159.70:8004/images/{filename}', "request_exists": remained}
                # os.remove('static/uploads/'+filename)
                return jsonify(dict)
        elif request.files['file']:
            file = request.files['file']
            if file.filename == '':
                flash('No image selected for uploading')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                counter = counter + 1
                filename = secure_filename(file.filename)
                if os.path.isfile('static/uploads/'+filename):
                    os.remove('static/uploads/'+filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filepath = 'static/uploads/'+filename
                #print('upload_image filename: ' + filename)
                flash('Image successfully uploaded')
                
                if filename.split('.')[-1] != 'pdf':
                    img = cv2.imread('static/uploads/'+filename)
        #             width = int(img.shape[1] * 1.25)
        #             height = int(img.shape[0] * 1.25)
        #             dim = (width, height)
        #             img = cv2.resize(img, dim, interpolation = cv2.INTER_AREA)
        #             ret,img = cv2.threshold(img,170,255,cv2.THRESH_BINARY)
        #             ret3,img = cv2.threshold(img,0,255,cv2.THRESH_BINARY+cv2.THRESH_OTSU)
                    img = cv2.fastNlMeansDenoisingColored(img,None,10,10,7,21)
                    cv2.imwrite('static/uploads/'+filename, img)
                    img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    out = reader.readtext(img, detail =0)
                    file1 = open("static/saved/myfile.txt","w+")
                    file1.writelines(out)
                    overlay()
                    text=""
                    for n in out:
                        text = text+" "+n
                    res = extractor(text)
                    dict = {"text":out, "elements_extracted":res, "imageURL":f'http://103.85.159.70:8004/images/{filename}', "request_exists": remained}
                    # os.remove('static/uploads/'+filename)
                    return jsonify(dict)
                else:
                    pages = convert_from_path('static/uploads/'+filename, 500)
                    image_counter = 1
                    for page in pages:
                        filena = "page_"+str(image_counter)+".jpg"
                        # Save the image of the page in system
                        if os.path.isfile('static/uploads/'+filena):
                            os.remove('static/uploads/'+filena)
                        page.save('static/uploads/'+filena, 'JPEG')
                        # Increment the counter to update filename
                        image_counter = image_counter + 1
                        # Variable to get count of total number of pages
                        filelimit = image_counter-1
                    for i in range(1, filelimit + 1):
                        filena = "static/uploads/"+"page_"+str(i)+".jpg"
                        img = cv2.imread(filena)
                        img = cv2.fastNlMeansDenoisingColored(img,None,10,10,7,21)

        #                 #-----Converting image to LAB Color model----------------------------------- 
        #                 lab= cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        #                 #-----Splitting the LAB image to different channels-------------------------
        #                 l, a, b = cv2.split(lab)

        #                 #-----Applying CLAHE to L-channel-------------------------------------------
        #                 clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8,8))
        #                 cl = clahe.apply(l)

        #                 #-----Merge the CLAHE enhanced L-channel with the a and b channel-----------
        #                 limg = cv2.merge((cl,a,b))

        #                 #-----Converting image from LAB Color model to RGB model--------------------
        #                 img = cv2.cvtColor(limg, cv2.COLOR_LAB2BGR)
                        cv2.imwrite(filena, img)
                        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                        out = reader.readtext(img,detail =0)
                        outs.append(out)
                        # os.remove('static/uploads/'+filename)
                    cnt = str(counter)
                    # outs.append(cnt)
                    file1 = open("static/saved/myfile.txt","w+")
                    for i in range(len(outs)):
                        file1.writelines(outs[i]) 
                    overlay()
                    text=""
                    for n in out:
                        text = text+" "+n
                    res = extractor(text)
                    dict = {"text":out, "elements_extracted":res, "imageURL":f'http://103.85.159.70:8004/images/{filename}', "request_exists": remained}
                    # dict = {"text":out, "imageURL":f'http://103.85.159.70:8004/images/{filena}', "request_exists": remained}
                    return jsonify(dict)
        #         return render_template('index1.html', filename=filename)
            else:
                flash('Allowed types are - png, jpg, jpeg, gif, pdf')
                # return redirect(request.url)
                return "Please provide correct file format"
    return "OCR for 80 languages"
                            
@app.route("/images/<path:path>")
def static_dir(path):
    return send_from_directory("static/uploads/", path)

@app.route('/language', methods=['POST'])
def select_language():
    global reader
    request_data = request.get_json()
    lang = request_data['lang']
    reader = easyocr.Reader(lang_list=lang, gpu = True)
    response = Response("language is selected", status=200, mimetype='application/json')
    return response  

@app.route('/file-downloads/')
def file_downloads():
    try:
        return render_template('download.html')
    except Exception as e:
        return str(e)   

@app.route('/return-files/')
def return_files_tut():
    try:
        return send_from_directory('static/saved/', 'myfile.txt', as_attachment=True)
    except Exception as e:
        return str(e) 

# @app.route('/overlay/')
def overlay():
    global filename, reader, filepath, filena
    img_list = []
    if filename.split('.')[-1] != 'pdf':
        image = cv2.imread(filepath)
        imagegr = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        res = reader.readtext(imagegr)
        for (bbox, text, prob) in res:
            print("[INFO] {:.4f}: {}".format(prob, text))
            # unpack the bounding box
            (tl, tr, br, bl) = bbox
            tl = (int(tl[0]), int(tl[1]))
            tr = (int(tr[0]), int(tr[1]))
            br = (int(br[0]), int(br[1]))
            bl = (int(bl[0]), int(bl[1]))
            # cleanup the text and draw the box surrounding the text along
            # text = cleanup_text(text)
            cv2.rectangle(image, tl, br, (0, 255, 0), 2) 
            # cv2.putText(image, text, (tl[0], tl[1] - 10),
            # cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)
            # image = cv2.cvtColor(image,cv2.COLOR_GRAY2RGB)
            cv2.imwrite(filepath, image)
#         return send_file(filepath, attachment_filename=filename)
    else:
        for i in range(1, filelimit + 1):
            base = "static/uploads/"
            filena = "page_"+str(i)+".jpg"
            filen = base+filena
            img = cv2.imread(filen)
            imgr = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            res = reader.readtext(imgr)
            for (bbox, text, prob) in res:
                print("[INFO] {:.4f}: {}".format(prob, text))
                # unpack the bounding box
                (tl, tr, br, bl) = bbox
                tl = (int(tl[0]), int(tl[1]))
                tr = (int(tr[0]), int(tr[1]))
                br = (int(br[0]), int(br[1]))
                bl = (int(bl[0]), int(bl[1]))
                # cleanup the text and draw the box surrounding the text along
                # text = cleanup_text(text)
                cv2.rectangle(img, tl, br, (0, 255, 0), 2) 
                # cv2.putText(image, text, (tl[0], tl[1] - 10),
                # cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)
            img_list.append(img)
        w_min = min(img.shape[1] 
                for img in img_list)
        # resizing images
        im_list_resize = [cv2.resize(img,
                      (w_min, int(img.shape[0] * w_min / img.shape[1])),
                                 interpolation = cv2.INTER_NEAREST)
                      for img in img_list]
        con_img = cv2.vconcat(im_list_resize)
        # con_img = cv2.cvtColor(con_img,cv2.COLOR_GRAY2RGB)
#         filename = filena
        cv2.imwrite(filen, con_img)
#         return send_file(filena, attachment_filename=filena)

@app.route('/display/<filename>')
def display_image(filename):
    #print('display_image filename: ' + filename)
    return redirect(url_for('static', filename='uploads/' + filename), code=301)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--ip", type=str, required=True,
        help="ip address of the device")
    ap.add_argument("-o", "--port", type=int, required=True,
        help="ephemeral port number of the server (1024 to 65535)")
    args = vars(ap.parse_args())
    app.run(host=args["ip"], port=args["port"], debug=True)

 