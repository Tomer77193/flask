# Floorplan AI Example

This example demonstrates a simple Flask app that accepts a floorplan
image, runs a very basic computer vision algorithm to locate door-like
shapes, and returns the coordinates and annotated image.

The detection uses OpenCV to find contours after edge detection. It is
only meant as a starting point. For real projects, consider training a
proper model or integrating an existing object detection API.

## Usage

Install dependencies and run the app:

```bash
pip install Flask Pillow numpy opencv-python-headless
python app.py
```

Open `http://localhost:5000` and upload a floorplan image to see
detected access points.
