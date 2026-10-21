from flask import Flask, jsonify
from .config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.route("/")
    def home():
        return jsonify({
            "message": "Secure API Key Manager",
            "status": "running"
        })

    return app