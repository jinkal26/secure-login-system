# init_db.py
from sun import db, app

with app.app_context():
    db.drop_all()   # remove any existing tables
    db.create_all() # create fresh tables with all columns
    print("Database initialized successfully.")
