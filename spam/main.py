from flask import Flask, Response, jsonify, request
from flask_restx import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from ultralytics import YOLO
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from flask_mail import Mail, Message

import cv2



### ----------- FLASK --------- ###
app = Flask(__name__)
api = Api(app)

### ----------- Database Mysql ----------- ###

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/webservice"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

app.config['MAIL_SERVER']= 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'irfants1710@gmail.com'
app.config['MAIL_PASSWORD'] = 'waxssrqahsocafmc'
app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# app.config['JWT_IDENTITY_CLAIM'] = 'jti'
# app.secret_key = 'asdsdfsdfs13sdf_df%&'

db = SQLAlchemy(app)


### ----------- Database (Tabel Users) ----------- ###
class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(256), nullable=False)


################################ Register #####################################

parser4Register = reqparse.RequestParser()
parser4Register.add_argument(
    'email', type=str, help="Email Anda", location='json', required=True)
parser4Register.add_argument(
    'name', type=str, help="Nama Anda", location='json', required=True)
parser4Register.add_argument(
    'password', type=str, help="Password", location='json', required=True)

@app.route('/register', methods=["GET", "POST"])
def flutter_register():
    if request.method == "POST":
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]

        loguser = db.session.execute(db.select(User).filter_by(email=email)).first()

        # BEGIN: Insert new user.
        user          = User() # Instantiate User object.
        user.email    = email
        user.name     = name
        user.password = generate_password_hash(password)

        if loguser is None:
            register = User(email=email, name=name, password=generate_password_hash(password))
            db.session.add(register)
            db.session.commit()
            return jsonify(["Register success, Silahkan Login!"])
        else:
            return jsonify(["Email Telah digunakan!"])
        
################################ Login #####################################

SECRET_KEY      = "WhatEverYouWant"
ISSUER          = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"
        
parser4LogIn = reqparse.RequestParser()
parser4LogIn.add_argument('email', type=str, help='Email', location='json', required=True)
parser4LogIn.add_argument('password', type=str, help='Password', location='json', required=True)

@app.route('/login', methods=["GET", "POST"])
def flutter_login():
    if request.method == "POST":
        email       = request.form['email']
        password    = request.form['password']
        # END: Get request parameters.

        if not email or not password:
            return jsonify(["masukan email"])

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return jsonify(["email salah"])
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
            token = jwt.encode(payload, SECRET_KEY)
            msg_title = "TOKEN MASUK APLIKASI KAMU!"
            msg = Message(msg_title, sender = 'jupi@gmail.com', recipients = [email])
            msg.body = token
            mail.send(msg)
            return jsonify ({
                'message': f"berhasil",
                'token': token
            }), 200
        else:
            return jsonify (['gagal']), 400
        # END: Check password hash.

#########################
##### END: Sign In #####
#######################

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
    
model = YOLO("C:/Users/Admin/anaconda3/capstone_uas/model/best.pt")
    
@app.route('/video_feed')
def video_feed():
    return Response(object_detection(), mimetype='multipart/x-mixed-replace; boundary=frame')

def object_detection():
    video_capture = cv2.VideoCapture(0)

    results = []

    while True:
        ret, frame = video_capture.read()
        prediction = model.predict(source=frame, show=True, save=True, conf=0.5) #WebCamera
        print("Bounding Box :", prediction[0].boxes.xyxy)
        print("Classes :", prediction[0].boxes.cls)

        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    video_capture.release()
    cv2.destroyAllWindows()
    results.append(prediction)

    # return 'Prediction completed'
    for predict in prediction:
        class_id = predict[0].boxes.cls
        if class_id == 0:
            note = "Segar"
            res = {"respon": note}
            return jsonify(res)
        else:
            note = "Tidak Segar"
            res = {"respon": note}
            return jsonify(res)
    
    return results


threshold = 0.5
class_name_dict = {0: 'Segar', 1: 'Tidak Segar'}

@app.route('/realtime')
def video_realtime():
    cap = cv2.VideoCapture(0)  # use default camera
    if not cap.isOpened():
        raise IOError("Cannot open webcam")

    cv2.namedWindow('Fish Detection', cv2.WINDOW_NORMAL)


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
                    cv2.putText(frame, class_label.upper(), (int(x1), int(y1 - 10)),
                                cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0, 0, 255), 3, cv2.LINE_AA)
                else:
                    class_label = 'Tidak Segar'
                    cv2.rectangle(frame, (int(x1), int(y1)), (int(x2), int(y2)), (0, 255, 0), 4)
                    cv2.putText(frame, class_label.upper(), (int(x1), int(y1 - 10)),
                                cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0, 255, 0), 3, cv2.LINE_AA)

        # Add timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cv2.putText(frame, timestamp, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

        
        cv2.imshow('Real-time Detection', frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

if __name__ == '__main__':
     app.run(debug=True, host='192.168.43.110')