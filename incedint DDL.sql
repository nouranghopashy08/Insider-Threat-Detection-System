CREATE DATABASE IF NOT EXISTS InsiderThreatDB;
USE InsiderThreatDB;


CREATE TABLE Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(50),
    department VARCHAR(50),
    email VARCHAR(100),
    status ENUM('Active','Disabled') DEFAULT 'Active',
    last_login DATETIME,
    privilege_level INT CHECK (privilege_level BETWEEN 1 AND 5),
    p_hash VARCHAR(255) NOT NULL
);


CREATE TABLE Devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    hostname VARCHAR(100),
    ip_address VARCHAR(50),
    os VARCHAR(50),
    status ENUM('Active','Flagged','Removed') DEFAULT 'Active',
    registered_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

CREATE TABLE LoginHistory (
    login_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_id INT NOT NULL,
    login_time DATETIME NOT NULL,
    logout_time DATETIME,
    login_status ENUM('Success','Failed','Locked') DEFAULT 'Success',
    location VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (device_id) REFERENCES Devices(device_id)
);

CREATE TABLE FileAccessLogs (
    access_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_id INT NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    action ENUM('Read','Write','Delete','Download','Copy','USB_Insert','USB_Remove') NOT NULL,
    timestamp DATETIME NOT NULL,
    sensitivity_level ENUM('Low','Medium','High','Critical') DEFAULT 'Low',
    status ENUM('Allowed','Blocked') DEFAULT 'Allowed',
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (device_id) REFERENCES Devices(device_id)
);

CREATE TABLE DeviceEvents (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_id INT NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- e.g., USB_Insert, AntivirusDisabled
    event_description VARCHAR(255),
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (device_id) REFERENCES Devices(device_id)
);

CREATE TABLE BehaviorScores (
    score_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    login_anomaly_score INT DEFAULT 0,
    file_access_score INT DEFAULT 0,
    device_score INT DEFAULT 0,
    total_score INT DEFAULT 0,
    calculated_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

CREATE TABLE RiskLevels (
    level_id INT AUTO_INCREMENT PRIMARY KEY,
    level_name ENUM('Low','Medium','High','Critical') NOT NULL,
    min_score INT NOT NULL,
    max_score INT NOT NULL,
    description VARCHAR(255)
);

CREATE TABLE SuspiciousActions (
    action_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL, -- e.g., USB_Insert, Login_At_03AM
    raw_source VARCHAR(50) NOT NULL, -- e.g., LoginHistory, FileAccessLogs, DeviceEvents
    action_description VARCHAR(255),
    timestamp DATETIME NOT NULL,
    severity ENUM('Low','Medium','High','Critical') DEFAULT 'Medium',
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (device_id) REFERENCES Devices(device_id)
);

CREATE TABLE Alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    level_id INT NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    alert_message VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Open','Investigating','Closed') DEFAULT 'Open',
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (level_id) REFERENCES RiskLevels(level_id)
);

CREATE TABLE Investigations (
    investigation_id INT AUTO_INCREMENT PRIMARY KEY,
    alert_id INT NOT NULL,
    investigator_name VARCHAR(100),
    investigation_status ENUM('Open','In Progress','Closed') DEFAULT 'Open',
    findings TEXT,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME,
    FOREIGN KEY (alert_id) REFERENCES Alerts(alert_id)
);





