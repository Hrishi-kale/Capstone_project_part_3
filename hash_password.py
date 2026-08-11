"""
Password hashing utilities using bcrypt.

Replaces the original implementation, which stored passwords as unsalted
MD5 hashes. bcrypt generates a unique random salt for every call, so two
hashes of the same plaintext password are never identical.
"""

import bcrypt


def hash_password(plain_text: str) -> str:
    """Generate a unique salt and return the salted bcrypt hash as a string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_text: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a previously stored bcrypt hash."""
    return bcrypt.checkpw(plain_text.encode("utf-8"), stored_hash.encode("utf-8"))


if __name__ == "__main__":
    # Demonstration: hashing the same password twice produces two different
    # hashes, because each call generates its own random salt.
    pw = "CorrectHorseBatteryStaple"
    h1 = hash_password(pw)
    h2 = hash_password(pw)
    print("Hash 1:", h1)
    print("Hash 2:", h2)
    print("Hashes are different:", h1 != h2)
    print("verify_password(pw, h1):", verify_password(pw, h1))
    print("verify_password(pw, h2):", verify_password(pw, h2))
    print("verify_password('wrong', h1):", verify_password("wrong", h1))
