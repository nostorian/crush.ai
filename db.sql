CREATE DATABASE crushai_db;

CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(50) PRIMARY KEY,
    password VARCHAR(100),
    chat_id VARCHAR(50)
);
