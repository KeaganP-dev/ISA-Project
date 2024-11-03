from flask import Flask
from flask_cors import CORS
from routes import model_routes


app = Flask(__name__)
CORS(app)


# Register blueprints here
app.register_blueprint(model_routes.model_bp)

if __name__ == '__main__':
    app.run()
