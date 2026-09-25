-- Migration 001: Schéma initial de la base de données
-- LabAccess

-- Activer les extensions si nécessaire (PostgreSQL)
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table: users
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'agent')),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: faculties
CREATE TABLE faculties (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: promotions
CREATE TABLE promotions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    faculty_id INTEGER NOT NULL,
    year INTEGER NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (faculty_id) REFERENCES faculties(id) ON DELETE RESTRICT
);

-- Table: students
CREATE TABLE students (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE,
    matricule VARCHAR(50) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(50),
    photo_url VARCHAR(500),
    faculty_id INTEGER,
    promotion_id INTEGER,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (faculty_id) REFERENCES faculties(id) ON DELETE SET NULL,
    FOREIGN KEY (promotion_id) REFERENCES promotions(id) ON DELETE SET NULL
);

-- Table: professors
CREATE TABLE professors (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE,
    matricule VARCHAR(50) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(50),
    photo_url VARCHAR(500),
    department VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Table: agents
CREATE TABLE agents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE,
    agent_id VARCHAR(50) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(50),
    photo_url VARCHAR(500),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Table: cards
CREATE TABLE cards (
    id SERIAL PRIMARY KEY,
    qr_identifier VARCHAR(50) UNIQUE NOT NULL,
    card_type VARCHAR(50) NOT NULL CHECK (card_type IN ('student', 'professor')),
    person_id INTEGER NOT NULL,
    person_type VARCHAR(50) NOT NULL CHECK (person_type IN ('student', 'professor')),
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'blocked', 'lost')),
    issue_date DATE NOT NULL,
    expiry_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (person_id) REFERENCES students(id) ON DELETE RESTRICT
);

-- Table: rooms
CREATE TABLE rooms (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    room_type VARCHAR(50) NOT NULL CHECK (room_type IN ('laboratory', 'auditorium')),
    capacity INTEGER,
    location VARCHAR(255),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: computers
CREATE TABLE computers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    room_id INTEGER NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'occupied', 'maintenance', 'out_of_service')),
    ip_address VARCHAR(50),
    mac_address VARCHAR(50),
    specifications TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE RESTRICT
);

-- Table: sessions
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    person_id INTEGER NOT NULL,
    person_type VARCHAR(50) NOT NULL CHECK (person_type IN ('student', 'professor')),
    room_id INTEGER NOT NULL,
    agent_id INTEGER NOT NULL,
    entry_time TIMESTAMP NOT NULL,
    exit_time TIMESTAMP,
    duration_minutes INTEGER,
    computer_type VARCHAR(50) CHECK (computer_type IN ('lab', 'private')),
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT completed_session_has_exit CHECK (
        (status = 'active' AND exit_time IS NULL AND duration_minutes IS NULL)
        OR (status = 'completed' AND exit_time IS NOT NULL AND duration_minutes IS NOT NULL AND duration_minutes >= 0)
    ),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE RESTRICT,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX uq_active_session_per_person
    ON sessions(person_id, person_type)
    WHERE status = 'active';

-- Table: computer_assignments
CREATE TABLE computer_assignments (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL,
    computer_id INTEGER NOT NULL,
    assigned_at TIMESTAMP NOT NULL,
    released_at TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE RESTRICT
);

-- Table: reservations
CREATE TABLE reservations (
    id SERIAL PRIMARY KEY,
    room_id INTEGER NOT NULL,
    professor_id INTEGER NOT NULL,
    reservation_date DATE NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    purpose TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'cancelled', 'completed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE RESTRICT,
    FOREIGN KEY (professor_id) REFERENCES professors(id) ON DELETE RESTRICT,
    CONSTRAINT end_time_after_start_time CHECK (end_time > start_time)
);

-- Table: access_logs
CREATE TABLE access_logs (
    id SERIAL PRIMARY KEY,
    session_id INTEGER,
    person_id INTEGER,
    person_type VARCHAR(50),
    qr_identifier VARCHAR(50),
    action VARCHAR(50) NOT NULL CHECK (action IN ('entry', 'exit', 'refused', 'error')),
    room_id INTEGER,
    agent_id INTEGER,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE SET NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
);

-- Index pour optimiser les performances
CREATE INDEX idx_sessions_person ON sessions(person_id, person_type);
CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_entry_time ON sessions(entry_time);
CREATE INDEX idx_computers_status ON computers(status);
CREATE INDEX idx_computers_room ON computers(room_id);
CREATE INDEX idx_cards_qr ON cards(qr_identifier);
CREATE INDEX idx_cards_status ON cards(status);
CREATE INDEX idx_reservations_date ON reservations(reservation_date);
CREATE INDEX idx_reservations_status ON reservations(status);
CREATE INDEX idx_access_logs_created ON access_logs(created_at);
CREATE INDEX idx_access_logs_action ON access_logs(action);
CREATE INDEX idx_access_logs_session ON access_logs(session_id);
