-- Production Database Dump
CREATE TABLE users (id INT, email VARCHAR(255), pass_hash VARCHAR(255));
INSERT INTO users VALUES (1, 'admin@university.edu', '$2y$10$demoHash');
