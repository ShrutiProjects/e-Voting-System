DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS blocks;

CREATE TABLE user(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  is_candidate INTEGER,
  publickey TEXT NOT NULL,
  voteCoins INTEGER,
  voteCollection INTEGER
);

CREATE TABLE blocks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proof INTEGER NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  prev_hash TEXT NOT NULL,
  transactions TEXT NOT NULL
);
