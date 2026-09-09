USE InsiderThreatDB;

INSERT INTO Users (username, full_name, role, department, email, status, last_login, privilege_level,p_hash)
VALUES
('m.ahmed', 'Mohamed Ahmed', 'System Administrator', 'IT Security', 'm.ahmed@gmail.com', 'Active', '2025-01-23 08:41:00', 5, '$2y$12$nGDfdxEpVeI27RSNdB/AoOq0OrXmvwZc513uD3Sop2P0WPE0zBeJe'),
('s.ali', 'Sara Ali', 'Developer', 'IT Development', 's.ali@gmail.com', 'Active', '2025-01-23 09:10:00', 4, '$2y$12$f8Na9fwqzHR79RUlD.hhOeyQswENjwgmWpFL1TT1wiALq/m/Yx72S'),
('h.farid', 'Hassan Farid', 'HR Manager', 'HR', 'h.farid@gmail.com', 'Active', '2025-01-23 09:30:00', 3, '$2y$12$lawzCWeEydbpPTXxoRWgUe.0w/fodlLq/Nd0FAfAB2Pu4cJvfSghq');

INSERT INTO Devices (device_id, user_id, hostname, ip_address, os, status, registered_at)
VALUES
(101, 1, 'PC-MOHAMED', '192.168.1.23', 'Windows 10 Pro', 'Active', '2024-12-10 10:23:00'),
(102, 2, 'LAPTOP-SARA', '192.168.1.25', 'Windows 11', 'Active', '2024-12-12 11:00:00'),
(103, 3, 'PC-HASSAN', '192.168.1.30', 'Windows 10 Pro', 'Active', '2024-12-15 09:45:00');
INSERT INTO LoginHistory (user_id, device_id, login_time, logout_time, login_status, location)
VALUES
(1, 101, '2025-01-23 08:41:00', '2025-01-23 16:55:00', 'Success', 'Cairo-HQ'),
(1, 101, '2025-01-24 03:12:00', '2025-01-24 03:20:00', 'Success', 'Cairo-HQ'),  -- abnormal login
(2, 102, '2025-01-23 09:15:00', '2025-01-23 18:10:00', 'Success', 'Cairo-HQ'),
(3, 103, '2025-01-23 09:40:00', '2025-01-23 17:30:00', 'Success', 'Cairo-HQ');

INSERT INTO FileAccessLogs (user_id, device_id, file_path, action, timestamp, sensitivity_level, status)
VALUES
(1, 101, '/secure/hr/salaries.xlsx', 'Read', '2025-01-23 11:02:33', 'High', 'Allowed'),
(1, 101, '/secure/finance/finance_report_2025.pdf', 'Read', '2025-01-24 10:45:00', 'Critical', 'Allowed'),
(1, 101, '/docs/file1.pdf', 'Download', '2025-01-24 10:01:00', 'Medium', 'Allowed'),
(1, 101, '/docs/file50.pdf', 'Download', '2025-01-24 10:09:00', 'Medium', 'Allowed'),
(1, 101, 'USB:/KINGSTON', 'USB_Insert', '2025-01-24 09:15:00', 'Medium', 'Allowed'),
(2, 102, '/projects/code.py', 'Read', '2025-01-23 10:00:00', 'Low', 'Allowed'),
(3, 103, '/hr/policies.docx', 'Read', '2025-01-23 11:30:00', 'Medium', 'Allowed');

INSERT INTO DeviceEvents (user_id, device_id, event_type, event_description, timestamp)
VALUES
(1, 101, 'USB_Insert', 'USB Kingston inserted into workstation PC-MOHAMED', '2025-01-24 09:15:00'),
(2, 102, 'Antivirus_Disabled', 'User temporarily disabled antivirus', '2025-01-24 10:20:00');

INSERT INTO BehaviorScores (user_id, login_anomaly_score, file_access_score, device_score, total_score, calculated_at)
VALUES
(1, 70, 95, 15, 180, '2025-01-24 12:30:00'), -- high risk for Mohamed
(2, 10, 15, 5, 30, '2025-01-24 12:30:00'),  -- normal
(3, 5, 10, 0, 15, '2025-01-24 12:30:00');   -- low risk

INSERT INTO RiskLevels (level_name, min_score, max_score, description)
VALUES
('Low', 0, 49, 'Low risk; normal activity'),
('Medium', 50, 99, 'Medium risk; slight unusual behavior'),
('High', 100, 199, 'High risk; unusual activity detected'),
('Critical', 200, 999, 'Critical threat; immediate investigation required');

INSERT INTO SuspiciousActions (user_id, device_id, action_type, raw_source, action_description, timestamp, severity)
VALUES
(1, 101, 'USB_Insert', 'DeviceEvents', 'USB Kingston inserted into workstation PC-MOHAMED', '2025-01-24 09:15:00', 'Medium'),
(1, 101, 'Access_Confidential_File', 'FileAccessLogs', 'User read confidential finance_report_2025.pdf', '2025-01-24 10:45:00', 'High'),
(1, 101, 'Mass_Download', 'FileAccessLogs', 'User downloaded 50 files between 10:01 and 10:09', '2025-01-24 10:09:00', 'Critical'),
(1, 101, 'Login_At_Abnormal_Hour', 'LoginHistory', 'User logged in at 03:12 AM outside normal working hours', '2025-01-24 03:12:00', 'High');

INSERT INTO Alerts (user_id, level_id, alert_type, alert_message, created_at, status)
VALUES
(1, 3, 'Suspicious File Access', 'User read confidential finance_report_2025.pdf', '2025-01-24 10:50:00', 'Open'),
(1, 4, 'Mass File Download', 'User downloaded 50 files in under 10 minutes', '2025-01-24 10:15:00', 'Open'),
(1, 3, 'Abnormal Login', 'User logged in at 03:12 AM outside normal hours', '2025-01-24 03:20:00', 'Investigating'),
(1, 2, 'USB Inserted', 'USB Kingston inserted into PC-MOHAMED', '2025-01-24 09:20:00', 'Open');

INSERT INTO Investigations (alert_id, investigator_name, investigation_status, findings, started_at, closed_at)
VALUES
(1, 'Ahmed Salah', 'Closed', 'User accessed confidential file accidentally. No data exfiltration.', '2025-01-24 10:55:00', '2025-01-24 12:00:00'),
(2, 'Sara Nabil', 'In Progress', 'Downloading 50+ files detected. Investigation ongoing.', '2025-01-24 10:20:00', NULL),
(3, 'Mohamed Khaled', 'Open', '', '2025-01-24 03:25:00', NULL);