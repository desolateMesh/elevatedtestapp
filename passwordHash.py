from werkzeug.security import generate_password_hash

# Replace these with your actual usernames and passwords
users = {
    "jasonr": "Welcome2024!",
}

hashed_passwords = {}

for username, password in users.items():
    hashed_password = generate_password_hash(password)
    hashed_passwords[username] = hashed_password
    # Use parameterized query to avoid SQL injection and syntax errors
    print(f"UPDATE Users SET PasswordHash = ? WHERE Username = ?;")
    print(f"-- Parameters: 1) {hashed_password}, 2) {username}")

# Print hashed passwords (for reference)
print("\nHashed passwords:")
for username, hashed_password in hashed_passwords.items():
    print(f"{username}: {hashed_password}")