import pytest                                  # test framework
from sqlcipher3 import dbapi2 as sqlcipher     # SQLite module with SQLCipher support

KEY_A = "11" * 32   # "11" repeated 32 times = 64 hex characters = a 32-byte key
KEY_B = "22" * 32   # a different 32-byte key, used as the wrong key

def make(path, key_hex):
    con = sqlcipher.connect(str(path))                    # create or open the database file
    con.execute(f"PRAGMA key = \"x'{key_hex}'\";")        # x'..' tells SQLCipher the key is raw bytes in hex, not a password
    con.execute("CREATE TABLE t(x)")                      # make one table so the file has content
    con.execute("INSERT INTO t VALUES (1)")               # add one row
    con.commit()                                          # write changes to disk
    con.close()                                           # release the file

def read(path, key_hex):
    con = sqlcipher.connect(str(path))                    # open the file
    try:
        con.execute(f"PRAGMA key = \"x'{key_hex}'\";")    # supply a key; this never fails even if the key is wrong
        return con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]  # first real read; fails if the key is wrong
    finally:
        con.close()                                       # always close, even after an error

def test_right_key(tmp_path):                             # tmp_path = a fresh temporary folder given by pytest
    p = tmp_path / "a.db"
    make(p, KEY_A)
    assert read(p, KEY_A) == 1                            # one table exists, so the count is 1

def test_wrong_key_raises(tmp_path):
    p = tmp_path / "a.db"
    make(p, KEY_A)
    with pytest.raises(sqlcipher.DatabaseError):          # a wrong key must raise an error on the first read
        read(p, KEY_B)
