CREATE TABLE IF NOT EXISTS users
(
    id              serial    NOT NULL PRIMARY KEY,
    username        text      NOT NULL UNIQUE,
    hashed_password bytea     NOT NULL,
    email           varchar   NOT NULL,
    name            varchar   NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at      timestamp NOT NULL DEFAULT now(),
    updated_at      timestamp NOT NULL DEFAULT now(),
    CHECK (role IN ('admin', 'user'))
);

INSERT INTO users(username, hashed_password, name, email, role)
VALUES ('slava', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Slava', 'slava@vk.com', 'admin'),
       ('kirill', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Kirill', 'kirill@vk.com', 'user'),
       ('petya', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Petya', 'petya@vk.com', 'user'),
       ('evgenii', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Evgenii', 'evgenii@vk.com', 'user');
