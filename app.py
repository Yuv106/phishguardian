from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "")

    return jsonify({
        "url": url,
        "message": "Analyzer endpoint working",
        "malicious": 0,
        "suspicious": 0
    })

if __name__ == "__main__":
    app.run()
