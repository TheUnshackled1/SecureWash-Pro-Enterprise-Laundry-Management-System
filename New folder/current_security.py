# Current security measures in the system:

# 1. Login Authentication
def authenticate():
    username = username_entry.get()
    password = password_entry.get()
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        login_window.destroy()
        show_main_application()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

# 2. Password Recovery via Security Questions
def verify_hint():
    if hint_answer_entry.get().strip().lower() == ADMIN_HINT_ANSWER.lower():
        # Allow password reset
        pass
    else:
        messagebox.showerror("Verification Failed", "Incorrect hint answer.")

# 3. Configuration Storage
def save_config():
    config = {
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,  # VULNERABILITY: Plain text password
        "hint_question": ADMIN_HINT_QUESTION,
        "hint_answer": ADMIN_HINT_ANSWER  # VULNERABILITY: Plain text answer
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
