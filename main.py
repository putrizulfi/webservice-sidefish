import csv
from flask import Flask, request, jsonify
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from ultralytics import YOLO
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import base64
from base64 import b64encode
# Importing Python functools module which contains the reduce() function
import functools
from flask_mail import Mail, Message

import numpy as np
import cv2
 
# Importing Python operator module which contains the add() function
import operator

app = Flask(__name__) # Instantiation of Flask object.
app.config.SWAGGER_UI_OAUTH_APP_NAME = 'FISH DETECTION WEB SERVICE'
api = Api(app,title=app.config.SWAGGER_UI_OAUTH_APP_NAME)        # Instantiation of Flask-RESTX object.

############################
##### BEGIN: Database #####
##########################
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/webservice"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

app.config['MAIL_SERVER']= 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'putrizulfi17@gmail.com'
app.config['MAIL_PASSWORD'] = 'gijswgrqvripzhhi'
app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

db = SQLAlchemy(app) # Instantiation of Flask-SQLAlchemy object.

class User(db.Model):
    id       = db.Column(db.Integer(), primary_key=True, nullable=False)
    email    = db.Column(db.String(32), unique=True, nullable=False)
    name     = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(256), nullable=False)
##########################
##### END: Database #####
########################

# # Load the TFLite model
# interpreter = tf.lite.Interpreter(model_path='E:\Capstone Web Service\Flask\model\yolov8m_custom_float32.tflite')
# interpreter.allocate_tensors()

# # Get the input and output details of the model
# input_details = interpreter.get_input_details()
# output_details = interpreter.get_output_details()
# input_shape = input_details[0]['shape']

# # Define the labels for object classes
# labels = ['kanan', 'kiri', 'normal']

# # Define API endpoint for object detection
# @app.route('/detect_objects', methods=['POST'])
# def detect_objects():
#     image_file = request.files['image']
#     image = cv2.imdecode(np.fromstring(image_file.read(), np.uint8), cv2.IMREAD_COLOR)
#     image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
#     image = cv2.resize(image, (input_shape[2], input_shape[1]))
#     image = np.expand_dims(image, axis=0)

#     # Run object detection using the TFLite model
#     interpreter.set_tensor(input_details[0]['index'], image)
#     interpreter.invoke()

#     # Get the output tensor and process the results
#     output_data = interpreter.get_tensor(output_details[0]['index'])
#     detections = process_output(output_data)

#     return jsonify(detections)

# def process_output(output_data):
#     detections = []
#     for detection in output_data[0]:
#         confidence = detection[2]
#         if confidence > 0.5:
#             class_index = int(detection[1])
#             class_label = labels[class_index]
#             bbox = detection[0]
#             x, y, w, h = bbox[1], bbox[0], bbox[3] - bbox[1], bbox[2] - bbox[0]
#             bounding_box = {
#                 'label': class_label,
#                 'confidence': float(confidence),
#                 'x': float(x),
#                 'y': float(y),
#                 'width': float(w),
#                 'height': float(h)
#             }
#             detections.append(bounding_box)
#     return detections

###########################
##### BEGIN: Sign Up #####
#########################
parser4Reg = reqparse.RequestParser()
parser4Reg.add_argument('email', type=str, help='Email', location='json', required=True)
parser4Reg.add_argument('name', type=str, help='Name', location='json', required=True)
parser4Reg.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/register')
class Registration(Resource):
    @api.expect(parser4Reg)
    def post(self):
        # BEGIN: Get request parameters.
        args        = parser4Reg.parse_args()
        email       = args['email']
        name        = args['name']
        password    = args['password']

        # BEGIN: Check email existance.
        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        if user:
            return "This email address has been used!"
        # END: Check email existance.

        # BEGIN: Insert new user.
        user          = User() # Instantiate User object.
        user.email    = email
        user.name     = name
        user.password = generate_password_hash(password)

        db.session.add(user)
        db.session.commit()
        # END: Insert new user.

        return {'messege': 'Successful!'}, 201

#########################
##### END: Sign Up #####
#######################

###########################
##### BEGIN: Sign In #####
#########################
SECRET_KEY      = "WhatEverYouWant"
ISSUER          = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

parser4LogIn = reqparse.RequestParser()
parser4LogIn.add_argument('email', type=str, help='Email', location='json', required=True)
parser4LogIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/login')
class LogIn(Resource):
    @api.expect(parser4LogIn)
    def post(self):
        # BEGIN: Get request parameters.
        args        = parser4LogIn.parse_args()
        email       = args['email']
        password    = args['password']
        # END: Get request parameters.

        if not email or not password:
            return {
                'message': 'Please fill your email and password!'
            }, 400

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return {
                'message': 'The email or password is wrong!'
            }, 400
        else:
            user = user[0] # Unpack the array.
        # END: Check email existance.

        # BEGIN: Check password hash.
        if check_password_hash(user.password, password):
            payload = {
                'user_id': user.id,
                'email': user.email,
                'aud': AUDIENCE_MOBILE, # AUDIENCE_WEB
                'iss': ISSUER,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours = 2)
            }
            tup = email,":",password
            #toString
            data = functools.reduce(operator.add, tup)
            byte_msg = data.encode('ascii')
            base64_val = base64.b64encode(byte_msg)
            code = base64_val.decode('ascii')
            token = jwt.encode(payload, SECRET_KEY)
            msg_title = "TOKEN MASUK APLIKASI KAMU!"
            msg = Message(msg_title, sender = 'cheatdetec@gmail.com', recipients = [email])
            msg.body = token
            mail.send(msg)
            return {
                'title': 'Code Terkirim ke Email',
                'token': token,
                'code' : code
            }, 200
        else:
            return {
                'message': 'Wrong email or password!'
            }, 400
        # END: Check password hash.

#########################
##### END: Sign In #####
#######################

#############################
##### BEGIN: Basic Auth ####
###########################
import base64
parser4Basic = reqparse.RequestParser()
parser4Basic.add_argument('Authorization', type=str,
    location='headers', required=True, 
    help='Please, read https://swagger.io/docs/specification/authentication/basic-authentication/')

@api.route('/basic-auth')
class BasicAuth(Resource):
    @api.expect(parser4Basic)
    def post(self):
        args        = parser4Basic.parse_args()
        basicAuth   = args['Authorization']
        # basicAuth is "Basic bWlyemEuYWxpbS5tQGdtYWlsLmNvbTp0aGlzSXNNeVBhc3N3b3Jk"
        base64Str   = basicAuth[6:] # Remove first-6 digits (remove "Basic ")
        # base64Str is "bWlyemEuYWxpbS5tQGdtYWlsLmNvbTp0aGlzSXNNeVBhc3N3b3Jk"
        base64Bytes = base64Str.encode('ascii')
        msgBytes    = base64.b64decode(base64Bytes)
        pair        = msgBytes.decode('ascii')
        # pair is mirza.alim.m@gmail.com:thisIsMyPassword
        email, password = pair.split(':')
        # email is mirza.alim.m@gmail.com, password is thisIsMyPassword
        return {'email': email, 'password': password}
###########################
##### END: Basic Auth ####
#########################

####################################
##### BEGIN: Bearer/Token Auth ####
##################################
parser4Bearer = reqparse.RequestParser()
parser4Bearer.add_argument('Authorization', type=str, 
    location='headers', required=True, 
    help='Please, read https://swagger.io/docs/specification/authentication/bearer-authentication/')

@api.route('/bearer-auth')
class BearerAuth(Resource):
    @api.expect(parser4Bearer)
    def post(self):
        args        = parser4Bearer.parse_args()
        bearerAuth  = args['Authorization']
        # basicAuth is "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Im1pcnphLmFsaW0ubUBnbWFpbC5jb20iLCJhdWQiOiJteU1vYmlsZUFwcCIsImlzcyI6Im15Rmxhc2tXZWJzZXJ2aWNlIiwiaWF0IjoxNjc5NjQwOTcxLCJleHAiOjE2Nzk2NDgxNzF9.1ZxTlAT7bmkLQDgIvx0X3aWJaeUn8r6LjGDyhfrt3S8"
        jwtToken    = bearerAuth[7:] # Remove first-7 digits (remove "Bearer ")
        # jwtToken is "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Im1pcnphLmFsaW0ubUBnbWFpbC5jb20iLCJhdWQiOiJteU1vYmlsZUFwcCIsImlzcyI6Im15Rmxhc2tXZWJzZXJ2aWNlIiwiaWF0IjoxNjc5NjQwOTcxLCJleHAiOjE2Nzk2NDgxNzF9.1ZxTlAT7bmkLQDgIvx0X3aWJaeUn8r6LjGDyhfrt3S8"
        try:
            payload = jwt.decode(
                jwtToken, 
                SECRET_KEY, 
                audience = [AUDIENCE_MOBILE], 
                issuer = ISSUER, 
                algorithms = ['HS256'], 
                options = {"require": ["aud", "iss", "iat", "exp"]}
            )
        except:
            return {
                'message' : 'Unauthorized! Token is invalid! Please, Sign in!'
            }, 401
        
        return payload, 200
    
def decodetoken(jwtToken):
    decode_result = jwt.decode(jwtToken,
				SECRET_KEY,
				audience = [AUDIENCE_MOBILE],
				issuer = ISSUER,
				algorithms = ['HS256'],
				options = {"require": ["aud", "iss", "iat", "exp"]})	
    return decode_result

parser4get = reqparse.RequestParser()
parser4get.add_argument(
    'email', type=str, help="Masukan Email Anda", location='json', required=True)
parser4get.add_argument(
    'password', type=str, help="Ubah Password Anda", location='json', required=True)

editPasswordParser =  reqparse.RequestParser()
editPasswordParser.add_argument('current_password', type=str, help='current_password',location='json', required=True)
editPasswordParser.add_argument('new_password', type=str, help='new_password',location='json', required=True)
@api.route('/edit-password')
class Password(Resource):
    @api.expect(parser4Bearer,editPasswordParser)
    def put(self):
        args = editPasswordParser.parse_args()
        argss = parser4Bearer.parse_args()
        bearerAuth  = argss['Authorization']
        cu_password = args['current_password']
        newpassword = args['new_password']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = User.query.filter_by(id=token.get('user_id')).first()
            if check_password_hash(user.password, cu_password):
                user.password = generate_password_hash(newpassword)
                db.session.commit()
            else:
                return {'message' : 'Password Lama Salah'},400
        except:
            return {
                'message' : 'Token Tidak valid! Silahkan, Sign in!'
            }, 401
        return {'message' : 'Password Berhasil Diubah'}, 200


editParser = reqparse.RequestParser()
editParser.add_argument('email', type=str, help='email', location='json', required=True)
editParser.add_argument('name', type=str, help='name', location='json', required=True)
editParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)
@api.route('/edit-user')
class EditUser(Resource):
       @api.expect(editParser)
       def put(self):
        args = editParser.parse_args()
        bearerAuth  = args['Authorization']
        email = args['email']
        name = args['name']
        datenow =  datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            # print(token.get)
            user = User.query.filter_by(email=token.get('email')).first()
            user.email = email
            user.name = name
            user.updatedAt = datenow
            db.session.commit()
        except:
            return {
                'message' : 'Token Tidak valid,Silahkan Login Terlebih Dahulu!'
            }, 401
        return {'message' : 'Update User Sukses'}, 200
##################################
##### END: Bearer/Token Auth ####
################################

##################################
##### BEGIN: REALTIME ####
################################

# Load the YOLO model
model = YOLO("C:/Users/Admin/anaconda3/capstone_uas/model/best.pt")

threshold = 0.5
class_name_dict = {0: 'Segar', 1: 'Tidak Segar'}

# Record prediction results to a text file
def record_prediction(class_label):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("prediction_results.csv", "a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, class_label])

@app.route('/realtime')
def video_realtime():
    cap = cv2.VideoCapture(0)  # use default camera
    if not cap.isOpened():
        raise IOError("Cannot open webcam")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        H, W, _ = frame.shape

        results = model(frame)[0]

        for result in results.boxes.data.tolist():
            x1, y1, x2, y2, score, class_id = result

            if score > threshold:
                if class_id == 0:
                    class_label = 'Segar'
                    cv2.rectangle(frame, (int(x1), int(y1)), (int(x2), int(y2)), (0, 0, 255), 4)
                    cv2.putText (frame, class_label.upper(), (int(x1), int(y1 - 10)),
                                cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0, 0, 255), 3, cv2.LINE_AA)
                else:
                        class_label = 'Tidak Segar'
                        cv2.rectangle(frame, (int(x1), int(y1)), (int(x2), int(y2)), (0, 255, 0), 4)
                        cv2.putText(frame, class_label.upper(), (int(x1), int(y1 - 10)),
                                    cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0, 255, 0), 3, cv2.LINE_AA)
                    
                record_prediction(class_label)

        # Add timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cv2.putText(frame, timestamp, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

        cv2.imshow('Real-time Detection', frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

def record_prediction(class_label):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("prediction_results.csv", "a") as file:
        file.write(f"{timestamp} - Prediction: {class_label}\n")

##################################
##### END: REALTIME ####
################################


if __name__ == '__main__':
    # app.run(ssl_context='adhoc', debug=True)
    app.run(debug=True, host='192.168.43.110')