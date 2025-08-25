from app import db, User, app
from werkzeug.security import generate_password_hash

# Admin credentials
admin_username = "admin1"
admin_email = "thotateja314@gmail.com"
admin_password = "Admin@143"

with app.app_context():  # <- Important!
    # Check if admin already exists
    existing = User.query.filter_by(username=admin_username).first()
    if existing:
        print("Admin already exists.")
    else:
        hashed = generate_password_hash(admin_password)
        admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=hashed,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin account created: {admin_username} / {admin_password}")

