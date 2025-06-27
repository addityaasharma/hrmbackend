from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
from datetime import datetime, timezone, timedelta
from models import db, Announcement
from user_route import user
from superadmin_routes import superAdminBP
from middleware import auth_middleware
from socket_instance import socketio
from masteradmin import masterBP
from dotenv import load_dotenv
import os
from pytz import timezone as pytz_timezone

load_dotenv()

app = Flask(__name__)

class Config:
    SCHEDULER_API_ENABLED = True

CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": [
        "http://localhost:5173",
        "https://wzl6mwg3-5000.inc1.devtunnels.ms",
        "https://48qphfmd-5173.inc1.devtunnels.ms",
        "https://dvlhkxbv-5173.inc1.devtunnels.ms",
        "https://wzl6mwg3-5173.inc1.devtunnels.ms",
        "https://hrms-master.vercel.app",
        "http://192.168.1.23:5173",
        "http://localhost:5173",
        "http://localhost:5173",
        "https://hrms-admin-dashboard-xi.vercel.app",
    ]}},
    expose_headers=["Content-Type", "Authorization"],
    allow_headers=["Content-Type", "Authorization"]
)

MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "*****")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_DB = os.getenv("MYSQL_DB", "test")

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_object(Config())

db.init_app(app)
migrate = Migrate(app, db)
auth_middleware(app)

app.register_blueprint(user)
app.register_blueprint(superAdminBP)
app.register_blueprint(masterBP)

scheduler = APScheduler()
scheduler.init_app(app)


def publish_scheduled_announcements():
    with app.app_context():
        ist = timezone(timedelta(hours=5, minutes=30))
        now = datetime.now(ist)
        print(f"[Scheduler] Now (IST): {now.isoformat()}")

        pending_announcements = Announcement.query.filter(
            Announcement.is_published == False
        ).all()

        publish_count = 0
        for ann in pending_announcements:
            if not ann.scheduled_time:
                continue

            # Correct: treat naive times as IST
            if ann.scheduled_time.tzinfo is None:
                scheduled_aware = ann.scheduled_time.replace(tzinfo=ist)
            else:
                scheduled_aware = ann.scheduled_time.astimezone(ist)

            if scheduled_aware <= now:
                print(f"  → Publishing: {ann.title} @ {scheduled_aware.isoformat()}")
                ann.is_published = True
                publish_count += 1

        if publish_count:
            db.session.commit()
            print(f"[Scheduler] Published {publish_count} announcement(s).")
        else:
            print("[Scheduler] No announcements to publish.")


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    scheduler.add_job(
        id='publish_announcements',
        func=publish_scheduled_announcements,
        trigger='interval',
        seconds=60
    )
    scheduler.start()

    socketio.init_app(app, cors_allowed_origins="*")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
