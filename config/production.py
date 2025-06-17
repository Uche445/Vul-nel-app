class ProductionConfig:
    SECRET_KEY = 'your_secret_key'
    REDIS_URL = 'redis://localhost:6379/0'
    DEBUG = False
    TESTING = False
    DATABASE_URI = 'your_production_database_uri'