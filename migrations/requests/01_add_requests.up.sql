CREATE TABLE IF NOT EXISTS requests
(
    method  varchar NOT NULL,
    url     varchar NOT NULL,
    body    varchar NOT NULL,
    headers varchar NOT NULL
);
