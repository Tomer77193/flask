import os
import uuid
from flask import Flask, render_template, request, send_from_directory, jsonify
import cv2
import numpy as np

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['RESULT_FOLDER'] = os.path.join(app.root_path, 'static', 'results')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

def detect_access_points(image_path):
    """Detect door-like shapes and return bounding boxes."""
    img = cv2.imread(image_path)
    if img is None:
        return []
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blur, 50, 150)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    boxes = []
    for cnt in contours:
        x, y, w, h = cv2.boundingRect(cnt)
        aspect = w / float(h) if h != 0 else 0
        if 0.1 < aspect < 10 and 10 < w < 200 and 10 < h < 200:
            boxes.append((x, y, w, h))
    return boxes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return 'No file uploaded', 400
    filename = f"{uuid.uuid4().hex}_{file.filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    boxes = detect_access_points(path)
    img = cv2.imread(path)
    for (x, y, w, h) in boxes:
        cv2.rectangle(img, (x, y), (x + w, y + h), (0, 255, 0), 2)
    result_name = f"result_{filename}"
    result_path = os.path.join(app.config['RESULT_FOLDER'], result_name)
    cv2.imwrite(result_path, img)
    return render_template('result.html', image=result_name, boxes=boxes)

@app.route('/results/<path:filename>')
def results(filename):
    return send_from_directory(app.config['RESULT_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
