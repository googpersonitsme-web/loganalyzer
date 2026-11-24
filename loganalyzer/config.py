import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://loguser:logpass@127.0.0.1:3306/loganalyzer?charset=utf8mb4",
)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-please-0123456789abcdef")
TOKEN_MINUTES = 60