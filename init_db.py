from app import app, init_db

# Initialize the database
with app.app_context():
    print("Initializing database...")
    init_db()
    print("Database initialized successfully.") 