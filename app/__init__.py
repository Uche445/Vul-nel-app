from flask import Flask
from redis import Redis

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('config.development')  # Change to production as needed
    
    # Initialize Redis
    app.redis = Redis(host='localhost', port=6379, db=0)
    
    # Register routes
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    return app