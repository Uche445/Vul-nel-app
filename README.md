# Flask App

This is a simple Flask application that serves a basic homepage. The project is structured to support different environments and includes a placeholder for asynchronous job handling with Redis.

## Project Structure

```
flask-app
├── app
│   ├── __init__.py
│   ├── routes.py
│   ├── templates
│   │   └── home.html
│   └── static
├── config
│   ├── __init__.py
│   ├── development.py
│   └── production.py
├── requirements.txt
└── README.md
```

## Setup Instructions

1. **Clone the repository:**

   ```
   git clone <repository-url>
   cd flask-app
   ```

2. **Create a virtual environment:**

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**

   ```
   pip install -r requirements.txt
   ```

4. **Run the application:**

   ```
   flask run
   ```

5. **Access the homepage:**
   Open your web browser and go to `http://127.0.0.1:5000/`.

## Configuration

- The application supports different configurations for development and production environments.
- Modify the settings in `config/development.py` and `config/production.py` as needed.

## Dependencies

- Flask
- Redis

## License

This project is licensed under the Uche License.
