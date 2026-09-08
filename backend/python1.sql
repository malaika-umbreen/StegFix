CREATE DATABASE IF NOT EXISTS stego_detection;

USE stego_detection;


CREATE TABLE IF NOT EXISTS flows (

id INT AUTO_INCREMENT PRIMARY KEY,

src_ip VARCHAR(50),
dst_ip VARCHAR(50),

src_port INT,
dst_port INT,

protocol VARCHAR(10),

features JSON,

binary_label INT,
technique_label INT,

timestamp DATETIME DEFAULT CURRENT_TIMESTAMP

);


CREATE INDEX idx_protocol ON flows(protocol);
CREATE INDEX idx_timestamp ON flows(timestamp);

-- ============================================================
-- TABLE 1: detection_logs
-- ============================================================

CREATE TABLE IF NOT EXISTS detection_logs (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    flow_id       INT            NULL,               -- links to flows.id (soft link, no FK so existing table untouched)
    timestamp     DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source        VARCHAR(50)    NOT NULL,            -- src_ip copy from flows
    dest          VARCHAR(50)    NOT NULL,            -- dst_ip copy from flows
    protocol      VARCHAR(10)    NOT NULL,
    technique     VARCHAR(100)   NOT NULL DEFAULT 'Unknown',  -- LSB, DCT, etc.
    risk          VARCHAR(20)    NOT NULL DEFAULT 'low',      -- low / medium / high
    confidence    FLOAT          NOT NULL DEFAULT 0.0,        -- e.g. 94.7
    status        VARCHAR(20)    NOT NULL DEFAULT 'normal',   -- normal / suspicious / covert

    INDEX idx_detection_status    (status),
    INDEX idx_detection_risk      (risk),
    INDEX idx_detection_timestamp (timestamp),
    INDEX idx_detection_flow_id   (flow_id)
);


-- ============================================================
-- TABLE 2: alerts
-- Provides data for /dashboard endpoint → Dashboard.tsx alerts section
-- Stores: message, time, severity
-- ============================================================

CREATE TABLE IF NOT EXISTS alerts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    flow_id       INT            NULL,               -- links to flows.id (soft link, no FK)
    message       TEXT           NOT NULL,
    time          DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity      VARCHAR(20)    NOT NULL DEFAULT 'low',   -- low / medium / high / critical

    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_time     (time)
);


-- ============================================================
-- TABLE 3: users
-- ============================================================


CREATE TABLE IF NOT EXISTS users (
    id            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    full_name     VARCHAR(120)     NOT NULL,
    email         VARCHAR(255)     NOT NULL,
    password_hash VARCHAR(255)     NOT NULL,
    is_active     TINYINT          NOT NULL DEFAULT 1,
    created_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 4: login_logs
-- ============================================================

CREATE TABLE IF NOT EXISTS login_logs (
    id           BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    user_id      INT UNSIGNED     NULL,
    email        VARCHAR(255)     NOT NULL,
    ip_address   VARCHAR(45)      NOT NULL,
    user_agent   VARCHAR(512)     NULL,
    success      TINYINT          NOT NULL DEFAULT 0,
    attempted_at DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_login_logs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;




-- View stored flows
SELECT * FROM flows;
SELECT * FROM users;
SELECT * FROM login_logs;
SELECT * FROM alerts;
SELECT * FROM detection_logs;