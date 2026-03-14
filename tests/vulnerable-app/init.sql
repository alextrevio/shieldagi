-- ShieldAGI Vulnerable Test Database
-- Contains test data for security scanning

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- VULN: Plain text passwords
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    user_id INTEGER REFERENCES users(id),
    is_private BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,  -- VULN: Stores raw HTML
    post_id INTEGER NOT NULL,
    user_id INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- VULN: No RLS policies on any table
-- VULN: Weak/predictable passwords
INSERT INTO users (name, email, password, role) VALUES
    ('Admin User', 'admin@test.com', 'admin123', 'admin'),
    ('Test User A', 'usera@test.com', 'password123', 'user'),
    ('Test User B', 'userb@test.com', 'password456', 'user'),
    ('Demo User', 'demo@test.com', 'demo', 'user');

INSERT INTO documents (title, content, user_id, is_private) VALUES
    ('Secret Strategy', 'Confidential business strategy document', 1, true),
    ('User A Private Doc', 'This belongs to User A only', 2, true),
    ('User B Private Doc', 'This belongs to User B only', 3, true),
    ('Public Document', 'This is a public document', 1, false);

INSERT INTO comments (content, post_id, user_id) VALUES
    ('Great article!', 1, 2),
    ('Thanks for sharing', 1, 3);
