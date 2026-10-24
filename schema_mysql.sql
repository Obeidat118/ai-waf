-- Production MySQL schema equivalent to database.py's SQLite schema
-- (Section 6.5 / Figure 5.2). The app itself runs on SQLite out of the
-- box with zero setup; point it at MySQL by swapping database.py's
-- sqlite3 connection for a mysql-connector/PyMySQL connection using
-- this same table layout.

CREATE DATABASE IF NOT EXISTS aiwaf CHARACTER SET utf8mb4;
USE aiwaf;

CREATE TABLE companies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    website_url VARCHAR(512) NOT NULL,
    created_at DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_id INT NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(255) NOT NULL,
    is_verified TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
) ENGINE=InnoDB;

CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_id INT NOT NULL,
    source_ip VARCHAR(64),
    method VARCHAR(16),
    url VARCHAR(2048),
    layer1_result VARCHAR(32),
    layer2_result VARCHAR(32),
    status VARCHAR(32),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
) ENGINE=InnoDB;

CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_id INT NOT NULL,
    log_id INT,
    attack_type VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    message VARCHAR(512) NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id),
    FOREIGN KEY (log_id) REFERENCES logs(id)
) ENGINE=InnoDB;
