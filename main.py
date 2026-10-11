import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from database import create_tables, get_db

app = FastAPI(title="Сервер реестра заявок")
security = HTTPBearer()
SECRET_KEY = "my-secret-key"


class Register(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=3)
    department: str = Field(min_length=1)


class Login(BaseModel):
    username: str
    password: str


class TicketCreate(BaseModel):
    applicant: str = Field(min_length=1)
    type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    priority: str = "средний"


class TicketUpdate(BaseModel):
    applicant: str = Field(min_length=1)
    type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    priority: str
    status: str


@app.on_event("startup")
def startup():
    create_tables()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_token(user):
    data = {
        "user_id": user["id"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }
    return jwt.encode(data, SECRET_KEY, algorithm="HS256")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        data = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Недействительный JWT-токен")

    db = get_db()
    user = db.execute(
        "SELECT id, username, department FROM users WHERE id = ?",
        (data.get("user_id"),)
    ).fetchone()
    db.close()

    if user is None:
        raise HTTPException(status_code=401, detail="Пользователь не найден")

    return dict(user)


@app.get("/")
def home():
    return {"message": "Сервер реестра заявок работает"}


@app.post("/register")
def register(data: Register):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, department) VALUES (?, ?, ?)",
            (data.username, hash_password(data.password), data.department)
        )
        db.commit()
    except Exception:
        db.close()
        raise HTTPException(status_code=400, detail="Пользователь уже существует")

    user = db.execute(
        "SELECT id, username, department FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()
    db.close()
    return dict(user)


@app.post("/login")
def login(data: Login):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()
    db.close()

    if user is None or hash_password(data.password) != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    return {
        "access_token": create_token(user),
        "token_type": "bearer"
    }


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user


@app.get("/tickets")
def get_tickets(
    status: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    user=Depends(get_current_user)
):
    db = get_db()
    query = "SELECT * FROM tickets WHERE applicant = ?"
    params = [user["department"]]

    if status is not None:
        query += " AND status = ?"
        params.append(status)

    if priority is not None:
        query += " AND priority = ?"
        params.append(priority)

    query += " ORDER BY id"
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(row) for row in rows]


@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int, user=Depends(get_current_user)):
    db = get_db()
    ticket = db.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (ticket_id,)
    ).fetchone()
    db.close()

    if ticket is None or ticket["applicant"] != user["department"]:
        raise HTTPException(status_code=404, detail="Заявка не найдена")

    return dict(ticket)


@app.post("/tickets")
def create_ticket(data: TicketCreate, user=Depends(get_current_user)):
    if data.priority not in ["низкий", "средний", "высокий"]:
        raise HTTPException(status_code=422, detail="Недопустимый приоритет")

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO tickets (applicant, type, description, priority, status)
        VALUES (?, ?, ?, ?, 'новая')
        """,
        (user["department"], data.type, data.description, data.priority)
    )
    db.commit()

    ticket = db.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (cursor.lastrowid,)
    ).fetchone()
    db.close()
    return dict(ticket)


@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, data: TicketUpdate, user=Depends(get_current_user)):
    if data.priority not in ["низкий", "средний", "высокий"]:
        raise HTTPException(status_code=422, detail="Недопустимый приоритет")

    if data.status not in ["новая", "в работе", "выполнена", "отклонена"]:
        raise HTTPException(status_code=422, detail="Недопустимый статус")

    db = get_db()
    ticket = db.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (ticket_id,)
    ).fetchone()

    if ticket is None:
        db.close()
        raise HTTPException(status_code=404, detail="Заявка не найдена")

    if ticket["applicant"] != user["department"]:
        db.close()
        raise HTTPException(status_code=403, detail="Нет доступа к заявке")

    db.execute(
        """
        UPDATE tickets
        SET applicant = ?, type = ?, description = ?, priority = ?, status = ?
        WHERE id = ?
        """,
        (
            data.applicant,
            data.type,
            data.description,
            data.priority,
            data.status,
            ticket_id
        )
    )
    db.commit()

    ticket = db.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (ticket_id,)
    ).fetchone()
    db.close()
    return dict(ticket)


@app.delete("/tickets/{ticket_id}")
def delete_ticket(ticket_id: int, user=Depends(get_current_user)):
    db = get_db()
    ticket = db.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (ticket_id,)
    ).fetchone()

    if ticket is None:
        db.close()
        raise HTTPException(status_code=404, detail="Заявка не найдена")

    if ticket["applicant"] != user["department"]:
        db.close()
        raise HTTPException(status_code=403, detail="Нет доступа к заявке")

    db.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    db.commit()
    db.close()
    return {"message": "Заявка удалена"}
