import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
import sqlite3
import hashlib
import secrets
import time
import logging
import os
import re
from cryptography.fernet import Fernet
import json


# --- Security Configuration ---
class SecurityConfig:
    SESSION_TIMEOUT = 3000
    MAX_LOGIN_ATTEMPTS = 10
    LOCKOUT_DURATION = 10
    PASSWORD_MIN_LENGTH = 8
    REQUIRE_UPPERCASE = False
    REQUIRE_LOWERCASE = False
    REQUIRE_NUMBERS = False
    REQUIRE_SPECIAL_CHARS = False

# --- Database Manager ---
class DatabaseManager:
    def __init__(self, db_name="laundry_system.db"):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        """Initialize the database with all required tables"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table with RBAC
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
                full_name TEXT,
                phone TEXT,
                security_question TEXT,
                security_answer_hash TEXT,
                security_answer_salt TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')
        
        # Orders table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER,
                customer_name TEXT NOT NULL,
                order_type TEXT NOT NULL CHECK (order_type IN ('Small', 'Big')),
                weight REAL NOT NULL,
                price REAL NOT NULL,
                payment_status TEXT NOT NULL CHECK (payment_status IN ('Paid', 'Unpaid')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (customer_id) REFERENCES users(id),
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')
        
        # Inventory table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT UNIQUE NOT NULL,
                current_quantity REAL NOT NULL,
                unit TEXT NOT NULL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
        ''')
        
        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                table_name TEXT,
                record_id INTEGER,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Initialize default data
        self._init_default_data(cursor)
        
        conn.commit()
        conn.close()
    
    def _init_default_data(self, cursor):
        """Initialize default admin user and inventory"""
        # Check if admin exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            # Create default admin
            security_manager = SecurityManager()
            password_hash, salt = security_manager.hash_password("chips123")
            sec_answer_hash, sec_salt = security_manager.hash_password("coke")
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, role,full_name, 
                                 security_question, security_answer_hash, security_answer_salt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', ("admin", password_hash, salt, "admin", "admin@washbar.com", "System Administrator",
                  "What is your favorite drink?", sec_answer_hash, sec_salt))
        
        # Initialize inventory
        cursor.execute("SELECT COUNT(*) FROM inventory")
        if cursor.fetchone()[0] == 0:
            inventory_items = [
                ("Detergent", 50000.0, "grams"),
                ("Fabric Softener", 30000.0, "grams"),
                ("Bleach", 20000.0, "grams")
            ]
            cursor.executemany('''
                INSERT INTO inventory (item_name, current_quantity, unit)
                VALUES (?, ?, ?)
            ''', inventory_items)

# --- Security Manager ---
class SecurityManager:
    def __init__(self):
        self.config = SecurityConfig()
        self.setup_logging()
        self.encryption_key = self._load_or_create_key()
    
    def setup_logging(self):
        """Setup security audit logging"""
        logging.basicConfig(
            filename='security_audit.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filemode='a'
        )
    
    def _load_or_create_key(self):
        """Load or create encryption key"""
        key_file = 'security.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict file permissions
            return key
    
    def hash_password(self, password, salt=None):
        """Hash password with salt using SHA-256"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for better security
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)  # 100,000 iterations
        return password_hash.hex(), salt
    
    def verify_password(self, password, stored_hash, salt):
        """Verify password against stored hash"""
        password_hash, _ = self.hash_password(password, salt)
        return password_hash == stored_hash
    
    def validate_password_strength(self, password):
        """Validate password meets security requirements"""
        errors = []
        
        if len(password) < self.config.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {self.config.PASSWORD_MIN_LENGTH} characters long")
        
        if self.config.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.config.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.config.REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if self.config.REQUIRE_SPECIAL_CHARS and not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def sanitize_input(self, input_string):
        """Sanitize user input"""
        if not isinstance(input_string, str):
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'\&\\\/\.\.]', '', input_string)
        return sanitized.strip()[:255]  # Limit length
    
    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        fernet = Fernet(self.encryption_key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    
    def generate_session_token(self):
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def log_security_event(self, event_type, user_id=None, details=""):
        """Log security events"""
        logging.info(f"SECURITY_EVENT: {event_type} - User: {user_id} - Details: {details}")

# --- Authentication Manager ---
class AuthenticationManager:
    def __init__(self, db_manager, security_manager):
        self.db = db_manager
        self.security = security_manager
        self.current_user = None
        self.current_session = None
    
    def authenticate_user(self, username, password):
        """Authenticate user with enhanced security"""
        username = self.security.sanitize_input(username)
        
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        
        try:
            # Get user data
            cursor.execute('''
                SELECT id, username, password_hash, salt, role, is_active, 
                       failed_login_attempts, locked_until
                FROM users WHERE username = ?
            ''', (username,))
            
            user_data = cursor.fetchone()
            
            if not user_data:
                self.security.log_security_event("LOGIN_FAILED", details=f"User not found: {username}")
                return False, "Invalid credentials"
            
            user_id, db_username, password_hash, salt, role, is_active, failed_attempts, locked_until = user_data
            
            # Check if account is active
            if not is_active:
                self.security.log_security_event("LOGIN_FAILED", user_id, "Account disabled")
                return False, "Account is disabled"
            
            # Check if account is locked
            if locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    self.security.log_security_event("LOGIN_FAILED", user_id, "Account locked")
                    return False, "Account is temporarily locked"
                else:
                    # Unlock account
                    cursor.execute('''
                        UPDATE users SET locked_until = NULL, failed_login_attempts = 0 
                        WHERE id = ?
                    ''', (user_id,))
            
            # Verify password
            if self.security.verify_password(password, password_hash, salt):
                # Successful login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0
                    WHERE id = ?
                ''', (user_id,))
                
                # Create session
                session_token = self.security.generate_session_token()
                expires_at = datetime.now() + timedelta(seconds=self.security.config.SESSION_TIMEOUT)
                
                cursor.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, ?)
                ''', (user_id, session_token, expires_at))
                
                self.current_user = {
                    'id': user_id,
                    'username': db_username,
                    'role': role
                }
                self.current_session = session_token
                
                self.security.log_security_event("LOGIN_SUCCESS", user_id)
                conn.commit()
                return True, "Login successful"
            
            else:
                # Failed login
                failed_attempts += 1
                
                if failed_attempts >= self.security.config.MAX_LOGIN_ATTEMPTS:
                    # Lock account
                    lock_until = datetime.now() + timedelta(seconds=self.security.config.LOCKOUT_DURATION)
                    cursor.execute('''
                        UPDATE users SET failed_login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, lock_until, user_id))
                    self.security.log_security_event("ACCOUNT_LOCKED", user_id)
                    conn.commit()
                    return False, "Account locked due to too many failed attempts"
                else:
                    cursor.execute('''
                        UPDATE users SET failed_login_attempts = ?
                        WHERE id = ?
                    ''', (failed_attempts, user_id))
                
                self.security.log_security_event("LOGIN_FAILED", user_id, "Invalid password")
                conn.commit()
                return False, "Invalid credentials"
        
        finally:
            conn.close()
    
    def register_user(self, username, password, full_name, phone, role="customer", 
                     security_question="", security_answer=""):
        """Register new user with validation"""
        username = self.security.sanitize_input(username)
        full_name = self.security.sanitize_input(full_name)
        phone = self.security.sanitize_input(phone)
        
        # Validate password strength
        is_strong, errors = self.security.validate_password_strength(password)
        if not is_strong:
            return False, "Password requirements not met: " + "; ".join(errors)
        


        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        
        try:
            # Check if username exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] > 0:
                return False, "Username already exists"
            

            
            # Hash password and security answer
            password_hash, salt = self.security.hash_password(password)
            sec_answer_hash, sec_salt = self.security.hash_password(security_answer) if security_answer else (None, None)
            
            # Insert user
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, role, full_name, phone,
                                 security_question, security_answer_hash, security_answer_salt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, salt, role, full_name, phone,
                  security_question, sec_answer_hash, sec_salt))
            
            user_id = cursor.lastrowid
            self.security.log_security_event("USER_REGISTERED", user_id)
            conn.commit()
            return True, "User registered successfully"
        
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
        finally:
            conn.close()
    
    def logout(self):
        """Logout current user"""
        if self.current_session:
            conn = sqlite3.connect(self.db.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE user_sessions SET is_active = 0 
                WHERE session_token = ?
            ''', (self.current_session,))
            
            self.security.log_security_event("LOGOUT", self.current_user['id'] if self.current_user else None)
            conn.commit()
            conn.close()
        
        self.current_user = None
        self.current_session = None
    
    def check_session_valid(self):
        """Check if current session is still valid"""
        if not self.current_session:
            return False
        
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT expires_at, is_active FROM user_sessions 
            WHERE session_token = ?
        ''', (self.current_session,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result or not result[1]:  # Not active
            return False
        
        expires_at = datetime.fromisoformat(result[0])
        if datetime.now() > expires_at:
            return False
        
        return True
    
    def update_session_activity(self):
        """Update last activity timestamp"""
        if self.current_session:
            conn = sqlite3.connect(self.db.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP 
                WHERE session_token = ?
            ''', (self.current_session,))
            
            conn.commit()
            conn.close()
    
    def has_permission(self, required_role):
        """Check if current user has required role"""
        if not self.current_user:
            return False
        
        if required_role == "admin":
            return self.current_user['role'] == "admin"
        elif required_role == "customer":
            return self.current_user['role'] in ["customer", "admin"]
        
        return False

# --- Data Access Layer ---
class DataAccessLayer:
    def __init__(self, db_manager, auth_manager):
        self.db = db_manager
        self.auth = auth_manager
    
    def log_audit(self, action, table_name, record_id=None, old_values=None, new_values=None):
        """Log audit trail"""
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        
        user_id = self.auth.current_user['id'] if self.auth.current_user else None
        
        cursor.execute('''
            INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, action, table_name, record_id, 
              json.dumps(old_values) if old_values else None,
              json.dumps(new_values) if new_values else None))
        
        conn.commit()
        conn.close()
    
    def get_orders(self, filter_type="Today", customer_id=None):
        """Get orders with filtering"""
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        
        base_query = '''
            SELECT o.id, o.customer_name, o.order_type, o.weight, o.price, 
                   o.payment_status, o.created_at, u.username as created_by
            FROM orders o
            LEFT JOIN users u ON o.created_by = u.id
            WHERE 1=1
        '''
        params = []
        
        # Role-based filtering
        if self.auth.current_user['role'] == 'customer' and customer_id:
            base_query += " AND o.customer_id = ?"
            params.append(customer_id)
        
        # Date filtering
        today = datetime.now().date()
        if filter_type == "Today":
            base_query += " AND DATE(o.created_at) = ?"
            params.append(today)
        elif filter_type == "Last 7 Days":
            week_ago = today - timedelta(days=7)
            base_query += " AND DATE(o.created_at) BETWEEN ? AND ?"
            params.extend([week_ago, today])
        elif filter_type == "This Month":
            base_query += " AND strftime('%Y-%m', o.created_at) = ?"
            params.append(today.strftime('%Y-%m'))
        
        base_query += " ORDER BY o.created_at DESC"
        
        cursor.execute(base_query, params)
        orders = cursor.fetchall()
        conn.close()
        
        return orders
    
    def add_order(self, customer_name, order_type, weight, price, payment_status, customer_id=None):
        """Add new order with inventory update"""
        if not self.auth.has_permission("customer"):
            return False, "Insufficient permissions"
        
        conn = sqlite3.connect(self.db.db_name, timeout=10)
        cursor = conn.cursor()
        
        try:
            # Calculate supply usage
            detergent_needed = weight * 20
            softener_needed = weight * 5
            bleach_needed = weight * 5
            
            # Check inventory
            cursor.execute("SELECT current_quantity FROM inventory WHERE item_name = 'Detergent'")
            detergent_stock = cursor.fetchone()[0]
            cursor.execute("SELECT current_quantity FROM inventory WHERE item_name = 'Fabric Softener'")
            softener_stock = cursor.fetchone()[0]
            cursor.execute("SELECT current_quantity FROM inventory WHERE item_name = 'Bleach'")
            bleach_stock = cursor.fetchone()[0]
            
            if (detergent_stock < detergent_needed or 
                softener_stock < softener_needed or 
                bleach_stock < bleach_needed):
                return False, "Insufficient inventory"
            
            # Add order
            cursor.execute('''
                INSERT INTO orders (customer_id, customer_name, order_type, weight, price, 
                                  payment_status, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (customer_id, customer_name, order_type, weight, price, payment_status,
                  self.auth.current_user['id']))
            
            order_id = cursor.lastrowid
            
            # Update inventory
            cursor.execute('''
                UPDATE inventory SET current_quantity = current_quantity - ?, 
                                   last_updated = CURRENT_TIMESTAMP, updated_by = ?
                WHERE item_name = 'Detergent'
            ''', (detergent_needed, self.auth.current_user['id']))
            
            cursor.execute('''
                UPDATE inventory SET current_quantity = current_quantity - ?, 
                                   last_updated = CURRENT_TIMESTAMP, updated_by = ?
                WHERE item_name = 'Fabric Softener'
            ''', (softener_needed, self.auth.current_user['id']))
            
            cursor.execute('''
                UPDATE inventory SET current_quantity = current_quantity - ?, 
                                   last_updated = CURRENT_TIMESTAMP, updated_by = ?
                WHERE item_name = 'Bleach'
            ''', (bleach_needed, self.auth.current_user['id']))
            
            # Log audit (use existing connection)
            self.log_audit("ORDER_CREATED", "orders", order_id, None, {
                'customer_name': customer_name,
                'order_type': order_type,
                'weight': weight,
                'price': price
            }, cursor=cursor, conn=conn)
            
            conn.commit()
            return True, "Order added successfully"
        
        except sqlite3.Error as e:
            conn.rollback()
            return False, f"Database error: {str(e)}"
        finally:
            conn.close()

    def log_audit(self, action, table_name, record_id, previous_data=None, new_data=None, cursor=None, conn=None):
        """Log an audit trail event"""
        needs_own_connection = cursor is None or conn is None
        try:
            if needs_own_connection:
                conn = sqlite3.connect(self.db.db_name, timeout=10)
                cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO audit_log (user_id, action, table_name, record_id, timestamp, previous_data, new_data)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
            ''', (
                self.auth.current_user['id'],
                action,
                table_name,
                record_id,
                json.dumps(previous_data) if previous_data else None,
                json.dumps(new_data) if new_data else None
            ))

            if needs_own_connection:
                conn.commit()
        except sqlite3.Error as e:
            print(f"Audit log error: {e}")
        finally:
            if needs_own_connection:
                conn.close()

    
    def update_order_payment(self, order_id, new_status):
        """Update order payment status"""
        if not self.auth.has_permission("customer"):
            return False, "Insufficient permissions"
        
        conn = sqlite3.connect(self.db.db_name, timeout=10, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        try:
            # Get old status
            cursor.execute("SELECT payment_status FROM orders WHERE id = ?", (order_id,))
            old_status = cursor.fetchone()
            if not old_status:
                return False, "Order not found"
            
            # Update status
            cursor.execute('''
                UPDATE orders SET payment_status = ? WHERE id = ?
            ''', (new_status, order_id))
            
            self.log_audit("ORDER_PAYMENT_UPDATED", "orders", order_id, 
                          {'payment_status': old_status[0]}, 
                          {'payment_status': new_status})
            
            conn.commit()
            return True, "Payment status updated"
        
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
        finally:
            conn.close()
    
    def get_inventory(self):
        """Get current inventory"""
        conn = sqlite3.connect(self.db.db_name, timeout=10)  # waits up to 10 seconds
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT item_name, current_quantity, unit, last_updated
            FROM inventory ORDER BY item_name
        ''')
        
        inventory = cursor.fetchall()
        conn.close()
        return inventory
    def update_inventory(self, item_name, new_quantity):
        """Update inventory quantity"""
        if not self.auth.has_permission("admin"):
            return False, "Admin access required"
        
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        
        try:
            # Get old quantity
            cursor.execute("SELECT current_quantity FROM inventory WHERE item_name = ?", (item_name,))
            old_quantity = cursor.fetchone()
            if not old_quantity:
                return False, "Item not found"
            
            # Update quantity
            cursor.execute('''
                UPDATE inventory SET current_quantity = ?, last_updated = CURRENT_TIMESTAMP,
                                   updated_by = ?
                WHERE item_name = ?
            ''', (new_quantity, self.auth.current_user['id'], item_name))
            
            self.log_audit("INVENTORY_UPDATED", "inventory", None,
                          {'item': item_name, 'quantity': old_quantity[0]},
                          {'item': item_name, 'quantity': new_quantity})
            
            conn.commit()
            return True, "Inventory updated"
        
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
        finally:
            conn.close()

# --- GUI Application ---
class LaundryManagementApp:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.security_manager = SecurityManager()
        self.auth_manager = AuthenticationManager(self.db_manager, self.security_manager)
        self.data_layer = DataAccessLayer(self.db_manager, self.auth_manager)
        
        self.root = tk.Tk()
        self.root.withdraw()  # Hide initially
        self.root.title("WashBar Laundry Management System")
        self.root.geometry("1200x800")
        
        # Session timeout checker
        self.session_check_job = None
        
        self.show_login_screen()
    
    def center_window(self, window, width=None, height=None):
        """Center window on screen"""
        window.update_idletasks()
        w = width or window.winfo_width()
        h = height or window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (w // 2)
        y = (window.winfo_screenheight() // 2) - (h // 2)
        window.geometry(f"{w}x{h}+{x}+{y}")
    
    def show_login_screen(self):
        """Display login/register screen"""
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login - WashBar Laundry System")
        self.login_window.state("zoomed")  # ✅ Maximized window

        
        self.login_window.geometry("400x500")
        self.center_window(self.login_window, 400, 500)
        self.login_window.resizable(False, False)
        self.login_window.grab_set()
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.login_window)
        notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Login tab
        login_frame = ttk.Frame(notebook)
        notebook.add(login_frame, text="Login")
        
        tk.Label(login_frame, text="WashBar Laundry System", 
                font=("Arial", 16, "bold")).pack(pady=20)
        
        tk.Label(login_frame, text="Username:", font=("Arial", 10)).pack(pady=5)
        self.login_username = tk.Entry(login_frame, width=30, font=("Arial", 10))
        self.login_username.pack(pady=5)
        
        tk.Label(login_frame, text="Password:", font=("Arial", 10)).pack(pady=5)
        self.login_password = tk.Entry(login_frame, show="*", width=30, font=("Arial", 10))
        self.login_password.pack(pady=5)
        
        tk.Button(login_frame, text="Login", command=self.handle_login,
                 bg="#2196F3", fg="white", font=("Arial", 12, "bold"), 
                 width=20).pack(pady=20)
        
        tk.Button(login_frame, text="Forgot Password?", command=self.show_forgot_password,
                 fg="blue", font=("Arial", 9, "underline"), relief="flat").pack()
        
        # Register tab
        register_frame = ttk.Frame(notebook)
        notebook.add(register_frame, text="Register")
        
        tk.Label(register_frame, text="Create New Account", 
                font=("Arial", 14, "bold")).pack(pady=10)
        
        # Registration fields
        fields = [
            ("Username:", "reg_username"),
            ("Password:", "reg_password"),
            ("Confirm Password:", "reg_confirm_password"),
            ("Full Name:", "reg_full_name"),
            ("Phone:", "reg_phone"),
            ("Security Question:", "reg_security_question"),
            ("Security Answer:", "reg_security_answer")
        ]
        
        self.reg_fields = {}
        for label, field_name in fields:
            tk.Label(register_frame, text=label, font=("Arial", 9)).pack(pady=2)
            if "password" in field_name.lower():
                entry = tk.Entry(register_frame, show="*", width=30, font=("Arial", 9))
            else:
                entry = tk.Entry(register_frame, width=30, font=("Arial", 9))
            entry.pack(pady=2)
            self.reg_fields[field_name] = entry
        
        tk.Button(register_frame, text="Register", command=self.handle_register,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 width=20).pack(pady=15)
        
        # Bind Enter key
        self.login_window.bind('<Return>', lambda e: self.handle_login())
        
        # Handle window close
        self.login_window.protocol("WM_DELETE_WINDOW", self.on_login_close)
    
    def handle_login(self):
        """Handle login attempt"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        success, message = self.auth_manager.authenticate_user(username, password)
        
        if success:
            self.login_window.destroy()
            self.show_main_application()
            self.start_session_monitor()
        else:
            messagebox.showerror("Login Failed", message)
            self.login_password.delete(0, tk.END)
    
    def handle_register(self):
        """Handle user registration"""
        # Get all field values
        values = {k: v.get().strip() for k, v in self.reg_fields.items()}
        
        # Validate required fields
        required = ['reg_username', 'reg_password', 'reg_full_name']
        for field in required:
            if not values[field]:
                messagebox.showerror("Error", f"Please fill in all required fields")
                return
        
        # Validate password confirmation
        if values['reg_password'] != values['reg_confirm_password']:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        # Register user
        success, message = self.auth_manager.register_user(
            username=values['reg_username'],
            password=values['reg_password'],
            full_name=values['reg_full_name'],
            phone=values['reg_phone'],
            security_question=values['reg_security_question'],
            security_answer=values['reg_security_answer']
        )
        
        if success:
            messagebox.showinfo("Success", "Account created successfully! Please login.")
            # Clear fields
            for entry in self.reg_fields.values():
                entry.delete(0, tk.END)
        else:
            messagebox.showerror("Registration Failed", message)
    
    def show_forgot_password(self):
        """Show forgot password dialog"""
        forgot_window = tk.Toplevel(self.login_window)
        forgot_window.title("Password Recovery")
        forgot_window.geometry("400x300")
        self.center_window(forgot_window, 400, 300)
        forgot_window.grab_set()
        
        tk.Label(forgot_window, text="Password Recovery", 
                font=("Arial", 14, "bold")).pack(pady=20)
        
        tk.Label(forgot_window, text="Enter your username:", 
                font=("Arial", 10)).pack(pady=5)
        username_entry = tk.Entry(forgot_window, width=30)
        username_entry.pack(pady=5)
        
        def verify_user():
            username = username_entry.get().strip()
            if not username:
                messagebox.showerror("Error", "Please enter username")
                return
            
            # Get user's security question
            conn = sqlite3.connect(self.db_manager.db_name)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, security_question, security_answer_hash, security_answer_salt
                FROM users WHERE username = ? AND is_active = 1
            ''', (username,))
            
            user_data = cursor.fetchone()
            conn.close()
            
            if not user_data:
                messagebox.showerror("Error", "User not found")
                return
            
            user_id, question, answer_hash, answer_salt = user_data
            
            if not question:
                messagebox.showerror("Error", "No security question set for this account")
                return
            
            # Show security question
            for widget in forgot_window.winfo_children():
                widget.destroy()
            
            tk.Label(forgot_window, text="Security Question", 
                    font=("Arial", 14, "bold")).pack(pady=20)
            
            tk.Label(forgot_window, text=question, 
                    font=("Arial", 10)).pack(pady=10)
            
            tk.Label(forgot_window, text="Your Answer:", 
                    font=("Arial", 10)).pack(pady=5)
            answer_entry = tk.Entry(forgot_window, width=30)
            answer_entry.pack(pady=5)
            
            def verify_answer():
                answer = answer_entry.get().strip()
                if self.security_manager.verify_password(answer, answer_hash, answer_salt):
                    # Show password reset
                    for widget in forgot_window.winfo_children():
                        widget.destroy()
                    
                    tk.Label(forgot_window, text="Reset Password", 
                            font=("Arial", 14, "bold")).pack(pady=20)
                    
                    tk.Label(forgot_window, text="New Password:", 
                            font=("Arial", 10)).pack(pady=5)
                    new_pass_entry = tk.Entry(forgot_window, show="*", width=30)
                    new_pass_entry.pack(pady=5)
                    
                    tk.Label(forgot_window, text="Confirm Password:", 
                            font=("Arial", 10)).pack(pady=5)
                    confirm_pass_entry = tk.Entry(forgot_window, show="*", width=30)
                    confirm_pass_entry.pack(pady=5)
                    
                    def reset_password():
                        new_pass = new_pass_entry.get()
                        confirm_pass = confirm_pass_entry.get()
                        
                        if new_pass != confirm_pass:
                            messagebox.showerror("Error", "Passwords do not match")
                            return
                        
                        is_strong, errors = self.security_manager.validate_password_strength(new_pass)
                        if not is_strong:
                            messagebox.showerror("Error", "Password requirements not met:\n" + "\n".join(errors))
                            return
                        
                        # Update password
                        password_hash, salt = self.security_manager.hash_password(new_pass)
                        
                        conn = sqlite3.connect(self.db_manager.db_name)
                        cursor = conn.cursor()
                        cursor.execute('''
                            UPDATE users SET password_hash = ?, salt = ?
                            WHERE id = ?
                        ''', (password_hash, salt, user_id))
                        conn.commit()
                        conn.close()
                        
                        self.security_manager.log_security_event("PASSWORD_RESET", user_id)
                        messagebox.showinfo("Success", "Password reset successfully!")
                        forgot_window.destroy()
                    
                    tk.Button(forgot_window, text="Reset Password", command=reset_password,
                             bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(pady=20)
                else:
                    messagebox.showerror("Error", "Incorrect answer")
            
            tk.Button(forgot_window, text="Verify Answer", command=verify_answer,
                     bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(pady=20)
        
        tk.Button(forgot_window, text="Continue", command=verify_user,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(pady=20)
    
    def show_main_application(self):
        """Show main application interface"""
        self.root.deiconify()
        
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Admin menu (only for admins)
        if self.auth_manager.has_permission("admin"):
            admin_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Admin", menu=admin_menu)
            admin_menu.add_command(label="User Management", command=self.show_user_management)
            admin_menu.add_command(label="Audit Log", command=self.show_audit_log)
        
        # Header
        header_frame = tk.Frame(self.root, bg="#2196F3", height=60)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="WashBar Laundry Management System", 
                font=("Arial", 18, "bold"), bg="#2196F3", fg="white").pack(side="left", padx=20, pady=15)
        
        user_info = f"Welcome, {self.auth_manager.current_user['username']} ({self.auth_manager.current_user['role'].title()})"
        tk.Label(header_frame, text=user_info, 
                font=("Arial", 10), bg="#2196F3", fg="white").pack(side="right", padx=20, pady=15)
        
        # Main content area
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Orders section
        orders_frame = tk.LabelFrame(main_frame, text="Orders", font=("Arial", 12, "bold"))
        orders_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        self.setup_orders_section(orders_frame)
        
        # Inventory section (admin only)
        if self.auth_manager.has_permission("admin"):
            inventory_frame = tk.LabelFrame(main_frame, text="Inventory", font=("Arial", 12, "bold"))
            inventory_frame.pack(fill="both", expand=True)
            
            self.setup_inventory_section(inventory_frame)
        
        # Action buttons
        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill="x", pady=10)
        
        tk.Button(buttons_frame, text="Add Order", command=self.show_add_order,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 width=15).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="View Reports", command=self.show_reports,
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold"), 
                 width=15).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="Logout", command=self.logout,
                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), 
                 width=15).pack(side="right", padx=5)
        
        # Load initial data
        self.refresh_orders()
        if self.auth_manager.has_permission("admin"):
            self.refresh_inventory()
    
    def setup_orders_section(self, parent):
        """Setup orders display section"""
        # Filter controls
        filter_frame = tk.Frame(parent)
        filter_frame.pack(fill="x", pady=5)
        
        tk.Label(filter_frame, text="Show Orders:", font=("Arial", 10)).pack(side="left", padx=5)
        
        self.order_filter = tk.StringVar(value="Today")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.order_filter,
                                   values=["Today", "Last 7 Days", "This Month", "All Orders"],
                                   state="readonly", width=15)
        filter_combo.pack(side="left", padx=5)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_orders())
        
        # Orders tree
        columns = ("ID", "Customer", "Type", "Weight", "Price", "Status", "Date")
        self.orders_tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)
        
        # Configure columns
        self.orders_tree.heading("ID", text="ID")
        self.orders_tree.heading("Customer", text="Customer")
        self.orders_tree.heading("Type", text="Type")
        self.orders_tree.heading("Weight", text="Weight (kg)")
        self.orders_tree.heading("Price", text="Price (₱)")
        self.orders_tree.heading("Status", text="Payment")
        self.orders_tree.heading("Date", text="Date")
        
        self.orders_tree.column("ID", width=50)
        self.orders_tree.column("Customer", width=150)
        self.orders_tree.column("Type", width=80)
        self.orders_tree.column("Weight", width=100)
        self.orders_tree.column("Price", width=100)
        self.orders_tree.column("Status", width=100)
        self.orders_tree.column("Date", width=150)
        
        # Scrollbar
        orders_scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.orders_tree.yview)
        self.orders_tree.configure(yscrollcommand=orders_scrollbar.set)
        
        self.orders_tree.pack(side="left", fill="both", expand=True)
        orders_scrollbar.pack(side="right", fill="y")
        
        # Order control buttons
        order_buttons_frame = tk.Frame(parent)
        order_buttons_frame.pack(fill="x", pady=5)
        
        tk.Button(order_buttons_frame, text="Mark as Paid", command=self.mark_order_paid,
                 bg="#28a745", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=5)
        
        if self.auth_manager.has_permission("admin"):
            tk.Button(order_buttons_frame, text="Delete Order", command=self.delete_order,
                     bg="#dc3545", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=5)
    
    def setup_inventory_section(self, parent):
        """Setup inventory display section"""
        columns = ("Item", "Quantity", "Unit", "Last Updated")
        self.inventory_tree = ttk.Treeview(parent, columns=columns, show="headings", height=6)
        
        # Configure columns
        for col in columns:
            self.inventory_tree.heading(col, text=col)
            self.inventory_tree.column(col, width=150)
        
        # Scrollbar
        inv_scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.inventory_tree.yview)
        self.inventory_tree.configure(yscrollcommand=inv_scrollbar.set)
        
        self.inventory_tree.pack(side="left", fill="both", expand=True)
        inv_scrollbar.pack(side="right", fill="y")
        
        # Inventory buttons
        inv_buttons_frame = tk.Frame(parent)
        inv_buttons_frame.pack(fill="x", pady=5)
        
        tk.Button(inv_buttons_frame, text="Update Inventory", command=self.show_update_inventory,
                 bg="#17a2b8", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=5)
    
    def refresh_orders(self):
        """Refresh orders display"""
        # Clear existing items
        for item in self.orders_tree.get_children():
            self.orders_tree.delete(item)
        
        # Get orders
        filter_type = self.order_filter.get()
        customer_id = self.auth_manager.current_user['id'] if self.auth_manager.current_user['role'] == 'customer' else None
        orders = self.data_layer.get_orders(filter_type, customer_id)
        
        # Populate tree
        total_revenue = 0
        for order in orders:
            order_id, customer_name, order_type, weight, price, payment_status, created_at, created_by = order
            
            # Format date
            date_obj = datetime.fromisoformat(created_at)
            formatted_date = date_obj.strftime("%Y-%m-%d %H:%M")
            
            # Add to tree
            self.orders_tree.insert("", "end", values=(
                order_id, customer_name, order_type, f"{weight:.1f}", 
                f"₱{price:.2f}", payment_status, formatted_date
            ))
            
            if payment_status == "Paid":
                total_revenue += price
        
        # Update totals (you can add a label for this)
        print(f"Total Revenue: ₱{total_revenue:.2f}")  # For now, just print
    
    def refresh_inventory(self):
        """Refresh inventory display"""
        if not hasattr(self, 'inventory_tree'):
            return
        
        # Clear existing items
        for item in self.inventory_tree.get_children():
            self.inventory_tree.delete(item)
        
        # Get inventory
        inventory = self.data_layer.get_inventory()
        
        # Populate tree
        for item in inventory:
            item_name, quantity, unit, last_updated = item
            
            # Format date
            if last_updated:
                date_obj = datetime.fromisoformat(last_updated)
                formatted_date = date_obj.strftime("%Y-%m-%d %H:%M")
            else:
                formatted_date = "N/A"
            
            self.inventory_tree.insert("", "end", values=(
                item_name, f"{quantity:.0f}", unit, formatted_date
            ))
    
    def show_add_order(self):
        """Show add order dialog"""
        order_window = tk.Toplevel(self.root)
        order_window.title("Add New Order")
        order_window.geometry("400x500")
        self.center_window(order_window, 400, 500)
        order_window.grab_set()
        
        tk.Label(order_window, text="Add New Order", 
                font=("Arial", 14, "bold")).pack(pady=20)
        
        # Form fields
        fields = {}
        
        tk.Label(order_window, text="Customer Name:", font=("Arial", 10)).pack(pady=5)
        fields['customer_name'] = tk.Entry(order_window, width=30)
        fields['customer_name'].pack(pady=5)
        
        tk.Label(order_window, text="Order Type:", font=("Arial", 10)).pack(pady=5)
        fields['order_type'] = ttk.Combobox(order_window, values=["Small", "Big"], 
                                           state="readonly", width=27)
        fields['order_type'].pack(pady=5)
        
        tk.Label(order_window, text="Weight (kg):", font=("Arial", 10)).pack(pady=5)
        fields['weight'] = tk.Entry(order_window, width=30)
        fields['weight'].pack(pady=5)
        
        tk.Label(order_window, text="Price (₱):", font=("Arial", 10)).pack(pady=5)
        fields['price'] = tk.Entry(order_window, width=30, state="readonly")
        fields['price'].pack(pady=5)
        
        tk.Label(order_window, text="Payment Status:", font=("Arial", 10)).pack(pady=5)
        fields['payment_status'] = ttk.Combobox(order_window, values=["Paid", "Unpaid"], 
                                               state="readonly", width=27)
        fields['payment_status'].set("Paid")
        fields['payment_status'].pack(pady=5)
        
        def calculate_price(event=None):
            """Calculate price based on weight and type"""
            try:
                weight = float(fields['weight'].get())
                order_type = fields['order_type'].get()
                
                if order_type == "Small":
                    if weight <= 6:
                        price = 120
                    else:
                        price = 120 + (weight - 6) * 20
                elif order_type == "Big":
                    if weight <= 1.9:
                        price = 130
                    elif weight <= 2.2:
                        price = 150
                    elif weight <= 2.5:
                        price = 170
                    elif weight <= 2.9:
                        price = 200
                    elif weight <= 3.5:
                        price = 250
                    elif weight <= 3.8:
                        price = 300
                    else:
                        extra_weight = weight - 3.8
                        extra_price = (extra_weight // 0.1) * 50
                        price = 300 + extra_price
                else:
                    price = 0
                
                fields['price'].config(state="normal")
                fields['price'].delete(0, tk.END)
                fields['price'].insert(0, f"{price:.2f}")
                fields['price'].config(state="readonly")
            except ValueError:
                fields['price'].config(state="normal")
                fields['price'].delete(0, tk.END)
                fields['price'].config(state="readonly")
        
        fields['weight'].bind("<KeyRelease>", calculate_price)
        fields['order_type'].bind("<<ComboboxSelected>>", calculate_price)
        
        def save_order():
            """Save the order"""
            try:
                customer_name = fields['customer_name'].get().strip()
                order_type = fields['order_type'].get()
                weight = float(fields['weight'].get())
                price = float(fields['price'].get())
                payment_status = fields['payment_status'].get()
                
                if not all([customer_name, order_type, weight > 0, price > 0, payment_status]):
                    messagebox.showerror("Error", "Please fill in all fields correctly")
                    return
                
                # Determine customer_id if customer role
                customer_id = None
                if self.auth_manager.current_user['role'] == 'customer':
                    customer_id = self.auth_manager.current_user['id']
                
                success, message = self.data_layer.add_order(
                    customer_name, order_type, weight, price, payment_status, customer_id
                )
                
                if success:
                    messagebox.showinfo("Success", "Order added successfully!")
                    order_window.destroy()
                    self.refresh_orders()
                    if hasattr(self, 'inventory_tree'):
                        self.refresh_inventory()
                else:
                    messagebox.showerror("Error", message)
            
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numeric values")
        
        tk.Button(order_window, text="Save Order", command=save_order,
                 bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), 
                 width=20).pack(pady=30)
    
    def mark_order_paid(self):
        """Mark selected order as paid"""
        selection = self.orders_tree.selection()
        if not selection:
            messagebox.showerror("Error", "Please select an order")
            return
        
        item = self.orders_tree.item(selection[0])
        order_id = item['values'][0]
        current_status = item['values'][5]
        
        if current_status == "Paid":
            messagebox.showinfo("Info", "Order is already marked as paid")
            return
        
        if messagebox.askyesno("Confirm", "Mark this order as paid?"):
            success, message = self.data_layer.update_order_payment(order_id, "Paid")
            if success:
                messagebox.showinfo("Success", "Order marked as paid")
                self.refresh_orders()
            else:
                messagebox.showerror("Error", message)
    
    def delete_order(self):
        """Delete selected order (admin only)"""
        if not self.auth_manager.has_permission("admin"):
            messagebox.showerror("Error", "Admin access required")
            return
        
        selection = self.orders_tree.selection()
        if not selection:
            messagebox.showerror("Error", "Please select an order")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this order?"):
            # Implementation for order deletion would go here
            messagebox.showinfo("Info", "Order deletion feature to be implemented")
    
    def show_update_inventory(self):
        """Show inventory update dialog"""
        if not self.auth_manager.has_permission("admin"):
            messagebox.showerror("Error", "Admin access required")
            return
        
        inv_window = tk.Toplevel(self.root)
        inv_window.title("Update Inventory")
        inv_window.geometry("400x300")
        self.center_window(inv_window, 400, 300)
        inv_window.grab_set()
        
        tk.Label(inv_window, text="Update Inventory", 
                font=("Arial", 14, "bold")).pack(pady=20)
        
        # Get current inventory
        inventory = self.data_layer.get_inventory()
        entries = {}
        
        for item in inventory:
            item_name, quantity, unit, _ = item
            
            frame = tk.Frame(inv_window)
            frame.pack(fill="x", padx=20, pady=5)
            
            tk.Label(frame, text=f"{item_name} ({unit}):", 
                    font=("Arial", 10), width=20, anchor="w").pack(side="left")
            
            entry = tk.Entry(frame, width=15)
            entry.insert(0, str(int(quantity)))
            entry.pack(side="right")
            
            entries[item_name] = entry
        
        def save_inventory():
            """Save inventory updates"""
            try:
                for item_name, entry in entries.items():
                    new_quantity = float(entry.get())
                    if new_quantity < 0:
                        messagebox.showerror("Error", f"Quantity for {item_name} cannot be negative")
                        return
                    
                    success, message = self.data_layer.update_inventory(item_name, new_quantity)
                    if not success:
                        messagebox.showerror("Error", f"Failed to update {item_name}: {message}")
                        return
                
                messagebox.showinfo("Success", "Inventory updated successfully!")
                inv_window.destroy()
                self.refresh_inventory()
            
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numeric values")
        
        tk.Button(inv_window, text="Save Changes", command=save_inventory,
                 bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), 
                 width=20).pack(pady=30)
    
    def show_reports(self):
        """Show reports dialog"""
        # Implementation for reports would go here
        messagebox.showinfo("Info", "Reports feature to be implemented")
    
    def show_user_management(self):
        """Show user management dialog (admin only)"""
        if not self.auth_manager.has_permission("admin"):
            messagebox.showerror("Error", "Admin access required")
            return
        
        # Implementation for user management would go here
        messagebox.showinfo("Info", "User management feature to be implemented")
    
    def show_audit_log(self):
        """Show audit log (admin only)"""
        if not self.auth_manager.has_permission("admin"):
            messagebox.showerror("Error", "Admin access required")
            return
        
        # Implementation for audit log would go here
        messagebox.showinfo("Info", "Audit log feature to be implemented")
    
    def start_session_monitor(self):
        """Start session timeout monitoring"""
        def check_session():
            if not self.auth_manager.check_session_valid():
                messagebox.showwarning("Session Expired", 
                                     "Your session has expired. Please log in again.")
                self.logout()
                return
            
            self.auth_manager.update_session_activity()
            # Schedule next check in 60 seconds
            self.session_check_job = self.root.after(60000, check_session)
        
        # Start the monitoring
        self.session_check_job = self.root.after(60000, check_session)
    
    def logout(self):
        """Logout current user"""
        if self.session_check_job:
            self.root.after_cancel(self.session_check_job)
        
        self.auth_manager.logout()
        self.root.withdraw()
        self.show_login_screen()
    
    def on_login_close(self):
        """Handle login window close"""
        if messagebox.askokcancel("Quit", "Do you want to exit the application?"):
            self.root.destroy()
    
    def on_closing(self):
        """Handle main window close"""
        if messagebox.askokcancel("Quit", "Do you want to logout and exit?"):
            self.logout()
            self.root.destroy()
    
    def run(self):
        """Run the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

# --- Main Application Entry Point ---
if __name__ == "__main__":
    try:
        app = LaundryManagementApp()
        app.run()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        messagebox.showerror("Application Error", f"An error occurred: {str(e)}")
