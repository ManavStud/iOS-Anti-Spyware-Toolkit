# db.py
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["login_db"]
users_collection = db["users"]
scan_history_collection = db["scan_history"]  # ✅ New collection
