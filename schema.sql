-- Secure Chat Database Schema
-- Drop existing table if exists
DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample data for testing (password: "TestPass123")
-- Salt: randomly generated 16 bytes (example)
-- This is just for reference - real salts should be random per user
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('test@example.com', 'testuser', 
 UNHEX('0123456789ABCDEF0123456789ABCDEF'),
 'example_hash_will_be_generated_by_server');
