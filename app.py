from flask import Flask, request, jsonify
import threading
import queue
import json
from alert_consumer import alert_processor

app = Flask(__name__)
alert_queue = queue.Queue()

@app.route('/upload-alert', methods=['POST'])

def upload_alert():
    try:
        alert_data = request.get_json(force=True)
        result = alert_processor(alert_data)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

