from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, request, jsonify, g
from models import *
from middleware import create_tokens  # Assuming you have a JWT token creation utility
from flask import Blueprint


masterBP = Blueprint('masteradmin',__name__, url_prefix='/master')


@masterBP.route('/signup', methods=['POST'])
def master_signup():
    data = request.get_json()
    required_fields = ['company_email', 'company_password']

    if not data or not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    if Master.query.filter_by(company_email=data['company_email']).first():
        return jsonify({"status": "error", "message": "Master admin already exists"}), 400

    hashed_password = generate_password_hash(data['company_password'])

    new_master = Master(
        name=data['name'],
        company_email=data['company_email'],
        company_password=hashed_password
    )

    db.session.add(new_master)
    db.session.flush()

    new_master.masteradminPanel = MasterPanel(masterid=new_master.id)

    db.session.commit()

    access_token, refresh_token = create_tokens(user_id=new_master.id, role='master_admin')

    return jsonify({
        "status": "success",
        "message": "Master admin registered successfully",
        "data": {
            "id": new_master.id,
            "name": new_master.name,
            "email": new_master.company_email,
            "panel_id": new_master.masteradminPanel.id
        },
        "token": {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    }), 201


@masterBP.route('/login', methods=['POST'])
def master_login():
    data = request.get_json()
    required_fields = ['company_email', 'company_password']

    if not data or not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    master = Master.query.filter_by(company_email=data['company_email']).first()

    if not master or not check_password_hash(master.company_password, data['company_password']):
        return jsonify({"status": "error", "message": "Invalid email or password"}), 401

    access_token, refresh_token = create_tokens(user_id=master.id, role='master_admin')

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "data": {
            "id": master.id,
            "name": master.name,
            "email": master.company_email,
            "panel_id": master.masteradminPanel.id
        },
        "token": {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    }), 200


@masterBP.route('/profile', methods=['PUT'])
def update_master_admin():

    userID = g.user.get('userID') if g.user else None
    if not userID:
        return jsonify({
            "status" : "Error",
            "status" : "Unauthorized",
        }), 400
    
    try:

        data = request.get_json()
        if not g.user or g.user.get("role") != "master_admin":
            return jsonify({"status": "error", "message": "Unauthorized"}), 403

        master = Master.query.filter_by(id=userID).first()

        if not master:
            return jsonify({"status": "error", "message": "Master admin not found"}), 404

        name = data.get("name")
        email = data.get("company_email")
        new_password = data.get("new_password")
        current_password = data.get("current_password")

        if name:
            master.name = name

        if email:
            existing_email = Master.query.filter(
                Master.company_email == email,
                Master.id != userID
            ).first()
            if existing_email:
                return jsonify({"status": "error", "message": "Email already in use"}), 400
            master.company_email = email

        if new_password:
            if not current_password or not check_password_hash(master.company_password, current_password):
                return jsonify({"status": "error", "message": "Current password is incorrect"}), 401
            master.company_password = generate_password_hash(new_password)

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Master admin profile updated",
            "data": {
                "id": master.id,
                "name": master.name,
                "email": master.company_email
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Something went wrong while updating profile",
            "error": str(e)
        }), 500


@masterBP.route('/profile', methods=['GET'])
def get_details():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 403

        master = Master.query.filter_by(id=userID).first()
        if not master:
            return jsonify({
                "status": "error",
                "message": "Master admin not found",
            }), 404

        return jsonify({
            "status": "success",
            "message": "Profile fetched successfully",
            "data": {
                "id": master.id,
                "name": master.name,
                "company_email": master.company_email,
                "panel_id": master.masteradminPanel.id if master.masteradminPanel else None
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e),
        }), 500


@masterBP.route('/admin', methods=['GET'])
def get_all_superadmins():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "Unauthorized access"
            }), 403

        master = Master.query.filter_by(id=userID).first()
        if not master:
            return jsonify({
                "status": "error",
                "message": "Master admin not found"
            }), 404

        panel_id = master.masteradminPanel.id
        superadmins = SuperAdmin.query.filter_by(master_id=panel_id).all()

        superadmin_list = []
        for admin in superadmins:
            superadmin_list.append({
                "id": admin.id,
                "superId": admin.superId,
                "companyName": admin.companyName,
                "companyEmail": admin.companyEmail,
                "company_type": admin.company_type,
                "company_website": admin.company_website,
                "company_estabilish": admin.company_estabilish.strftime("%Y-%m-%d") if admin.company_estabilish else None,
                "company_years": admin.company_years,
                "is_super_admin": admin.is_super_admin,
                "expiry": admin.expiry_date.strftime("%Y-%m-%d") if admin.expiry_date else None,
                "panel_id": admin.superadminPanel.id if admin.superadminPanel else None
            })

        return jsonify({
            "status": "success",
            "message": "SuperAdmins fetched successfully",
            "data": superadmin_list
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e),
        }), 500


@masterBP.route('/expired-admins', methods=['GET'])
def get_expired_superadmins():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "Unauthorized access"
            }), 403

        master = Master.query.filter_by(id=userID).first()
        if not master:
            return jsonify({
                "status": "error",
                "message": "Master admin not found"
            }), 404

        panel_id = master.masteradminPanel.id

        # Filter superadmins under this master whose expiry date is in the past
        now = datetime.utcnow()
        expired_admins = SuperAdmin.query.filter(
            SuperAdmin.master_id == panel_id,
            SuperAdmin.expiry_date != None,
            SuperAdmin.expiry_date < now
        ).all()

        expired_list = []
        for admin in expired_admins:
            expired_list.append({
                "id": admin.id,
                "superId": admin.superId,
                "companyName": admin.companyName,
                "companyEmail": admin.companyEmail,
                "company_type": admin.company_type,
                "company_website": admin.company_website,
                "company_estabilish": admin.company_estabilish.strftime("%Y-%m-%d") if admin.company_estabilish else None,
                "company_years": admin.company_years,
                "is_super_admin": admin.is_super_admin,
                "expiry": admin.expiry_date.strftime("%Y-%m-%d"),
                "panel_id": admin.superadminPanel.id if admin.superadminPanel else None
            })

        return jsonify({
            "status": "success",
            "message": "Expired SuperAdmins fetched successfully",
            "data": expired_list
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e),
        }), 500



@masterBP.route('/admin/<int:admin_id>', methods=['PUT'])
def edit_superadmin(admin_id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "Unauthorized access"}), 403

        master = Master.query.filter_by(id=userID).first()
        if not master:
            return jsonify({"status": "error", "message": "Master admin not found"}), 404

        superadmin = SuperAdmin.query.filter_by(id=admin_id, master_id=master.masteradminPanel.id).first()
        if not superadmin:
            return jsonify({"status": "error", "message": "SuperAdmin not found"}), 404

        data = request.get_json()
        allowed_fields = ['companyName', 'company_type', 'company_website', 'company_estabilish', 'company_years', 'is_super_admin', 'expiry_date']
        
        for field in allowed_fields:
            if field in data:
                if field == 'company_estabilish' or field == 'expiry_date':
                    setattr(superadmin, field, datetime.strptime(data[field], "%Y-%m-%d"))
                else:
                    setattr(superadmin, field, data[field])

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "SuperAdmin updated successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500



@masterBP.route('/admin/<int:admin_id>', methods=['DELETE'])
def delete_superadmin(admin_id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "Unauthorized access"}), 403

        master = Master.query.filter_by(id=userID).first()
        if not master:
            return jsonify({"status": "error", "message": "Master admin not found"}), 404

        superadmin = SuperAdmin.query.filter_by(id=admin_id, master_id=master.masteradminPanel.id).first()
        if not superadmin:
            return jsonify({"status": "error", "message": "SuperAdmin not found"}), 404

        panel = SuperAdminPanel.query.filter_by(superadmin_id=superadmin.id).first()

        if panel:
            panel_id = panel.id

            # Step 1: Delete all users
            for user in panel.allUsers:
                db.session.delete(user)

            # Step 2: Delete dependent admin data
            db.session.query(AdminAssets).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(AdminLeave).filter_by(superadminPanel=panel_id).delete(synchronize_session=False)
            db.session.query(AdminLeaveName).filter_by(adminLeaveName=panel_id).delete(synchronize_session=False)
            db.session.query(AdminDetail).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(AdminDoc).filter_by(superadminPanel=panel_id).delete(synchronize_session=False)
            db.session.query(Announcement).filter_by(adminPanelId=panel_id).delete(synchronize_session=False)
            db.session.query(Notice).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(BonusPolicy).filter_by(superPanelID=panel_id).delete(synchronize_session=False)
            db.session.query(RemotePolicy).filter_by(superPanel=panel_id).delete(synchronize_session=False)
            db.session.query(ShiftTimeManagement).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(PayrollPolicy).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(AdminDepartment).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(AdminRoles).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(TaskManagement).filter_by(superpanelId=panel_id).delete(synchronize_session=False)
            db.session.query(AdminHoliday).filter_by(superpanel=panel_id).delete(synchronize_session=False)
            db.session.query(AdminLocation).filter_by(superpanel=panel_id).delete(synchronize_session=False)  # ✅ Add this

            # Step 3: Delete panel
            db.session.delete(panel)

        # Step 4: Delete superadmin
        db.session.delete(superadmin)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "SuperAdmin, users, and panel deleted successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500
