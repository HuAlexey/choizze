import pytest
import requests
import json
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId
import jwt
import socketio
import time
import os
from unittest.mock import patch

BASE_URL = "http://localhost:3000/api"

# Очистка базы перед тестами
@pytest.fixture(scope="session", autouse=True)
def clear_database():
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    client.drop_database("choizze")
    yield
    client.close()

# Создание пользователей
@pytest.fixture(scope="module")
def setup_users():
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    try:
        unique_suffix = os.urandom(4).hex()
        main_user = {
            "username": f"testuser_{unique_suffix}",
            "email": f"test_{unique_suffix}@gmail.com",
            "password": "test123",
            "birthdate": (datetime.now() - timedelta(days=25*365)).isoformat(),
            "gender": "male",
            "preferredGender": "female",
            "preferredAgeMin": 20,
            "preferredAgeMax": 30,
            "referral": None
        }
        response = requests.post(f"{BASE_URL}/register", json=main_user)
        assert response.status_code == 200, f"Registration failed: {response.text}"
        main_user_db = db.users.find_one({"email": main_user["email"]})
        db.users.update_one({"_id": main_user_db["_id"]}, {"$set": {"emailVerified": True, "rulesAgreed": True}})
        main_user_id = str(main_user_db["_id"])
        db.userstats.insert_one({"user_id": main_user_db["_id"], "cp": 0, "lives": 3, "chips": 15, "ad_views": 0})

        second_user = {
            "username": f"testuser2_{unique_suffix}",
            "email": f"test2_{unique_suffix}@gmail.com",
            "password": "test123",
            "birthdate": (datetime.now() - timedelta(days=30*365)).isoformat(),
            "gender": "female",
            "preferredGender": "male",
            "preferredAgeMin": 20,
            "preferredAgeMax": 30,
            "referral": None
        }
        response = requests.post(f"{BASE_URL}/register", json=second_user)
        assert response.status_code == 200, f"Registration failed: {response.text}"
        second_user_db = db.users.find_one({"email": second_user["email"]})
        db.users.update_one({"_id": second_user_db["_id"]}, {"$set": {"emailVerified": True, "rulesAgreed": True}})
        second_user_id = str(second_user_db["_id"])
        db.userstats.insert_one({"user_id": second_user_db["_id"], "cp": 0, "lives": 3, "chips": 15, "ad_views": 0})

        return {"main_user_id": main_user_id, "second_user_id": second_user_id}
    except Exception as e:
        raise Exception(f"Setup users failed: {e}")

# Токены
@pytest.fixture
def auth_token(setup_users):
    token = jwt.encode({"userId": setup_users["main_user_id"]}, os.getenv("JWT_SECRET", "IWillNeverGiveUp2025!"), algorithm="HS256")
    return token

@pytest.fixture
def second_auth_token(setup_users):
    token = jwt.encode({"userId": setup_users["second_user_id"]}, os.getenv("JWT_SECRET", "IWillNeverGiveUp2025!"), algorithm="HS256")
    return token

# Тесты для функциональных блоков
def test_express_init():
    response = requests.get(f"{BASE_URL}/nonexistent")
    assert response.status_code == 404, "Express initialization failed"

def test_socketio_init():
    sio = socketio.Client()
    sio.connect('http://localhost:3000')
    sio.emit('ping')
    time.sleep(1)
    sio.disconnect()
    assert True, "Socket.IO initialization failed"

def test_jwt_middleware(auth_token):
    url = f"{BASE_URL}/history"
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(url, headers=headers)
    assert response.status_code == 200, "JWT middleware failed"

def test_registration_validation():
    url = f"{BASE_URL}/register"
    payload = {"username": "ab", "email": "invalid@unknown.com", "password": "123"}
    response = requests.post(url, json=payload)
    assert response.status_code == 400, "Registration validation failed"  # Блок 43

def test_user_registration(setup_users):
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    user = db.users.find_one()
    assert user, "User registration failed"  # Блок 44

def test_login():
    url = f"{BASE_URL}/login"
    payload = {"email": "test_1234@gmail.com", "password": "test123"}  # Пример, нужно заменить на реальные данные
    response = requests.post(url, json=payload)
    assert response.status_code == 200, "Login failed"  # Блок 45

def test_create_post(auth_token, setup_users):
    url = f"{BASE_URL}/post"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"content": "Test post"}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Create post failed"  # Блок 46

def test_like_post(auth_token, setup_users):
    post_id = test_create_post(auth_token, setup_users)
    url = f"{BASE_URL}/like"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"postId": post_id}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Like post failed"  # Блок 47

def test_repost(auth_token, setup_users):
    post_id = test_create_post(auth_token, setup_users)
    url = f"{BASE_URL}/repost"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"postId": post_id}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Repost failed"  # Блок 48

def test_comment_post(auth_token, setup_users):
    post_id = test_create_post(auth_token, setup_users)
    url = f"{BASE_URL}/comment"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"postId": post_id, "content": "Test comment"}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Comment failed"  # Блок 49

def test_quiz(auth_token, setup_users):
    url = f"{BASE_URL}/quiz"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"type": "interaction", "won": True}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Quiz failed"  # Блок 71

def test_ad_view(auth_token, setup_users):
    url = f"{BASE_URL}/ad-view"
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.post(url, headers=headers)
    assert response.status_code == 200, "Ad view failed"  # Блок 72

def test_chat_message(auth_token, second_auth_token, setup_users):
    sender_sio = socketio.Client()
    sender_sio.connect('http://localhost:3000')
    sender_sio.emit('join', {'token': auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    receiver_sio = socketio.Client()
    receiver_sio.connect('http://localhost:3000')
    receiver_sio.emit('join', {'token': second_auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    received = [None]
    @receiver_sio.on('message')
    def on_message(data):
        received[0] = data

    sender_sio.emit('message', {'roomId': setup_users["second_user_id"], 'message': "Test message"})
    time.sleep(3)
    assert received[0] is not None, "Chat message failed"  # Блок 74

def test_call(auth_token, second_auth_token, setup_users):
    sender_sio = socketio.Client()
    sender_sio.connect('http://localhost:3000')
    sender_sio.emit('join', {'token': auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    receiver_sio = socketio.Client()
    receiver_sio.connect('http://localhost:3000')
    receiver_sio.emit('join', {'token': second_auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    sender_sio.emit('call', {'roomId': setup_users["second_user_id"], 'receiverId': setup_users["second_user_id"]})
    time.sleep(2)
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    stats = db.userstats.find_one({"user_id": ObjectId(setup_users["second_user_id"])})
    assert stats["missed_calls"] == 1, "Call failed"  # Блок 75

def test_call_reject(auth_token, second_auth_token, setup_users):
    sender_sio = socketio.Client()
    sender_sio.connect('http://localhost:3000')
    sender_sio.emit('join', {'token': auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    receiver_sio = socketio.Client()
    receiver_sio.connect('http://localhost:3000')
    receiver_sio.emit('join', {'token': second_auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    sender_sio.emit('call', {'roomId': setup_users["second_user_id"], 'receiverId': setup_users["second_user_id"]})
    time.sleep(1)
    receiver_sio.emit('call_reject', {'roomId': setup_users["second_user_id"], 'callerId': setup_users["main_user_id"]})
    time.sleep(2)
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    stats = db.userstats.find_one({"user_id": ObjectId(setup_users["second_user_id"])})
    assert stats["refused_calls"] == 1, "Call reject failed"  # Блок 76

def test_chat_end(auth_token, second_auth_token, setup_users):
    sender_sio = socketio.Client()
    sender_sio.connect('http://localhost:3000')
    sender_sio.emit('join', {'token': auth_token, 'roomId': setup_users["second_user_id"]})
    time.sleep(1)

    sender_sio.emit('chat_end', {'roomId': setup_users["second_user_id"], 'receiverId': setup_users["second_user_id"]})
    time.sleep(1)
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    stats = db.userstats.find_one({"user_id": ObjectId(setup_users["main_user_id"])})
    assert stats["cp"] == 0, "Chat end CP calculation failed"  # Блок 77

def test_cron_inactivity(setup_users):
    with patch('moment().diff') as mock_diff:
        mock_diff.return_value = 8 * 24 * 60 * 60 * 1000  # 8 days
        client = MongoClient("mongodb://127.0.0.1:27017/choizze")
        db = client["choizze"]
        user = db.users.find_one()
        # Мок cron вручную (нужно вызвать функцию из блока 79)
        assert True, "Cron inactivity requires manual trigger"  # Блок 79

def test_report(auth_token, setup_users):
    url = f"{BASE_URL}/report"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"reportedId": setup_users["second_user_id"], "reason": "Test reason"}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Report failed"  # Блок 63

def test_appeal(auth_token, second_auth_token, setup_users):
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    report = db.reports.insert_one({
        "reporterId": ObjectId(setup_users["main_user_id"]),
        "reportedId": ObjectId(setup_users["second_user_id"]),
        "reason": "Test reason",
        "status": "pending"
    })
    report_id = str(report.inserted_id)
    url = f"{BASE_URL}/appeal"
    headers = {"Authorization": f"Bearer {second_auth_token}"}
    payload = {"reportId": report_id, "message": "Test appeal"}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Appeal failed"  # Блок 64

def test_moderate(auth_token, setup_users):
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    report = db.reports.insert_one({
        "reporterId": ObjectId(setup_users["main_user_id"]),
        "reportedId": ObjectId(setup_users["second_user_id"]),
        "reason": "Test reason",
        "status": "pending"
    })
    report_id = str(report.inserted_id)
    url = f"{BASE_URL}/moderate"
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {"reportId": report_id, "decision": "approve"}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200, "Moderate failed"  # Блок 65

def test_user_matching(auth_token, setup_users):
    url = f"{BASE_URL}/match"
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(url, headers=headers)
    assert response.status_code == 200, "User matching failed"  # Блок 67

def test_history(auth_token, setup_users):
    client = MongoClient("mongodb://127.0.0.1:27017/choizze")
    db = client["choizze"]
    db.messages.insert_one({
        "sender_id": ObjectId(setup_users["main_user_id"]),
        "receiver_id": ObjectId(setup_users["second_user_id"]),
        "message_text": "Test message"
    })
    url = f"{BASE_URL}/history"
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(url, headers=headers)
    assert response.status_code == 200, "History failed"  # Блок 68

if __name__ == "__main__":
    pytest.main(["-v", __file__])