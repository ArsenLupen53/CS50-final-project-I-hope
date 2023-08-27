--CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , username TEXT NOT NULL, hash TEXT NOT NULL);
--CREATE TABLE tracks(
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--   user_id INTEGER NOT NULL,
--    body TEXT NOT NULL,
--    exercise TEXT NOT NULL,
--    sett INTEGER NOT NULL,
--    rep INTEGER NOT NULL,
--    kg INTEGER NOT NULL,
--    loadd INTEGER NOT NULL,
--    datee INTEGER NOT NULL,
--   month INTEGER NOT NULL,
--  year INTEGER NOT NULL
--);



--INSERT INTO users(username, hash) VALUES ("ahmet" ,"123");
SELECT * FROM users;