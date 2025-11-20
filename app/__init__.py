from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'supersecretkey123'  # we will replace this later

    @app.route('/')
    def index():
        return "Secure Web Project - Home Page"

    return app
