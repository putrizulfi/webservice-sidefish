import cv2
from datetime import datetime
from ultralytics import YOLO

model_path = 'D:/Downloads/realtime capstone/realtime capstone/yolov8n.pt'

# Load a model
model = YOLO(model_path)  # load a custom model

threshold = 0.5

class_name_dict = {0: 'abnormal', 1: 'normal'}

cap = cv2.VideoCapture(0)  # use default camera
if not cap.isOpened():
    raise IOError("Cannot open webcam")

cv2.namedWindow('Real-time Detection', cv2.WINDOW_NORMAL)


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
                class_label = 'abnormal'
                cv2.rectangle(frame, (int(x1), int(y1)), (int(x2), int(y2)), (0, 0, 255), 4)
                cv2.putText(frame, class_label.upper(), (int(x1), int(y1 - 10)),
                            cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0, 0, 255), 3, cv2.LINE_AA)
            else:
                class_label = 'normal'
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
