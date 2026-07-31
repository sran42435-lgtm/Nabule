-- Buat database
CREATE DATABASE IF NOT EXISTS testing_db;
USE testing_db;

-- Buat tabel users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert data contoh
INSERT INTO users (username, password, role) VALUES 
('admin', 'admin123', 'superadmin'),
('user1', 'pass123', 'user'),
('user2', 'qwerty', 'user'),
('test', 'test123', 'user');

-- Tampilkan data
SELECT * FROM users;
