 import hashlib

# User input
password = input("Enter the password to hash: ")
hash_type = input("Enter hash type (md5/sha1/sha256): ").lower()

# Hash the password
if hash_type == "md5":
    hashed_password = hashlib.md5(password.encode()).hexdigest()
elif hash_type == "sha1":
    hashed_password = hashlib.sha1(password.encode()).hexdigest()
elif hash_type == "sha256":
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
else:
    print("Unsupported hash type.")
    exit()

print(f"Hashed password ({hash_type}): {hashed_password}")
