CREATE TABLE IF NOT EXISTS users
(
    id              serial    NOT NULL PRIMARY KEY,
    username        text      NOT NULL UNIQUE,
    hashed_password bytea     NOT NULL,
    email           varchar   NOT NULL,
    name            varchar   NOT NULL,
    created_at      timestamp NOT NULL DEFAULT now(),
    updated_at      timestamp NOT NULL DEFAULT now()
);

INSERT INTO users(username, hashed_password, name, email)
VALUES ('slava', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Slava', 'slava@vk.com'),
       ('kirill', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Kirill', 'kirill@vk.com'),
       ('petya', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Petya', 'petya@vk.com'),
       ('evgenii', '$2a$10$A4Ab/cuy/oLNvm4VxGoO/ezKL.fiew5e.eKTkUOWIVxoBh8XFO4lS', 'Evgenii', 'evgenii@vk.com');
