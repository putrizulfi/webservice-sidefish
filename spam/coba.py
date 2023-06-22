import os
import csv
from flask import Flask, Response, jsonify, request
from flask_restx import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from ultralytics import YOLO
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from flask_mail import Mail, Message

import cv2

app = Flask(__name__)

# Load the YOLO model
model = YOLO("C:/Users/Admin/anaconda3/capstone_uas/model/best.pt")

# Threshold for object detection
threshold = 0.5

# Dictionary mapping class IDs to class names
class_name_dict = {0: 'Segar', 1: 'Tidak Segar'}

# Record prediction results to a text file
def record_prediction(class_label):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("prediction_results.csv", "a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, class_label])

# @app.route('/video_feed')
# def video_feed():
#     return Response(object_detection(), mimetype='multipart/x-mixed-replace; boundary=frame')

# def object_detection():
#     video_capture = cv2.VideoCapture(0)

#     results = []
#     prediction_results = []

#     while True:
#         ret, frame = video_capture.read()
#         prediction = model.predict(source=frame, show=True, save=True, conf=0.5) #WebCamera
#         print("Bounding Box :", prediction[0].boxes.xyxy)
#         print("Classes :", prediction[0].boxes.cls)

#         ret, buffer = cv2.imencode('.jpg', frame)
#         frame = buffer.tobytes()

#         yield (b'--frame\r\n'
#                b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

#         if cv2.waitKey(1) & 0xFF == ord('q'):
#             break

#         results.extend(prediction)
#         prediction_results.extend([class_name_dict[class_id] for class_id in prediction[0].boxes.cls])

#     video_capture.release()
#     cv2.destroyAllWindows()

#     timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
#     file_name = f"prediction_results_{timestamp}.txt"
#     file_path = os.path.join("C:/Users/Admin/anaconda3/capstone_uas/model/", file_name)

#     with open(file_path, "w") as file:
#         for result in prediction_results:
#             timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#             line = f"{timestamp} - Prediction: {result}\n"
#             file.write(line)

#     count_tidak_segar = prediction_results.count('Tidak Segar')
#     return count_tidak_segar

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


if __name__ == '__main__':
     app.run(debug=True, host='192.168.43.110')

