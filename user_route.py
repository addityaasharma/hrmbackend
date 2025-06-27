from models import User,UserPanelData,db,SuperAdmin,PunchData, UserTicket, UserDocument, UserChat, UserLeave, ShiftTimeManagement, Announcement, Likes, Comments, Notice, ProductAsset, TaskUser ,TaskComments, TaskManagement, TicketAssignmentLog, UserSalary, UserPromotion, JobInfo, AdminLocation, AdminLeaveName
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, request, json, jsonify, g
from datetime import datetime,time, timedelta
from otp_utils import generate_otp, send_otp
from flask_socketio import join_room, emit
from werkzeug.utils import secure_filename
from sqlalchemy import func, extract, and_
from sqlalchemy.orm import joinedload
from socket_instance import socketio
from middleware import create_tokens
from dotenv import load_dotenv
from config import cloudinary
import cloudinary.uploader
from flask import url_for
from redis import Redis
import random,os
from dateutil import parser
import string, math
import os, calendar
from sqlalchemy import or_, and_
import pytz
from pytz import timezone


user = Blueprint('user',__name__, url_prefix='/user')
load_dotenv()
REDIS_URL = os.getenv("REDIS_URL")
redis = Redis.from_url(REDIS_URL)



#generate unique EMPID
def gen_empId():
    random_letter = random.choice(string.ascii_uppercase)
    last_user = User.query.filter(User.empId.like('%EMP%')).order_by(User.id.desc()).first()

    if last_user and last_user.empId:
        try:
            last_number = int(last_user.empId[-4:])
        except ValueError:
            last_number = 0
        new_number = last_number + 1
    else:
        new_number = 1

    return f"{random_letter}EMP{str(new_number).zfill(4)}"


#function to check access
def get_authorized_user(required_section=None, required_permissions=None):
    userID = g.user.get('userID') if g.user else None
    if not userID:
        return None, jsonify({"status": "error", "message": "No auth token"}), 401

    user = User.query.filter_by(id=userID).first()
    if not user:
        return None, jsonify({"status": "error", "message": "User not found"}), 403

    if required_section and required_permissions:
        if isinstance(required_permissions, str):
            required_permissions = [required_permissions]

        section = required_section.lower()
        allowed_perms = [perm.lower() for perm in required_permissions]

        has_permission = any(
            access.section.lower() == section and
            access.permission.lower() in allowed_perms and
            access.allowed
            for access in user.access_permissions
        )

        if not has_permission:
            return None, jsonify({
                "status": "error",
                "message": f"Access denied for section '{section}' with permission(s): {allowed_perms}"
            }), 403

    return user, None, None


#function to convert any time zone into correct Indian time
def convert_to_full_ist(input_time_str):
    try:
        dt = parser.parse(input_time_str)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC)

        ist = pytz.timezone('Asia/Kolkata')
        ist_time = dt.astimezone(ist)

        return ist_time.strftime("%B %d, %Y at %I:%M %p IST")

    except Exception as e:
        return f"Error: {str(e)}"


# ====================================
#          USER AUTH SECTION
# ====================================

@user.route('/signup', methods=['POST'])
def send_otp_route():
    data = request.json
    required_fields = ['userName', 'email', 'password', 'superadminId','userRole', 'gender']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    email = data['email']

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 409

    superadmin = SuperAdmin.query.filter_by(superId=data['superadminId']).first()
    if not superadmin:
        return jsonify({
            "status" : "error",
            "message" : "Please Enter valid id",
        }), 400
    
    if superadmin.expiry_date and datetime.utcnow() > superadmin.expiry_date:
        return jsonify({'error': 'Superadmin account expired. Cannot create user.'}), 403

    otp = generate_otp()
    otp_sent = send_otp(email, otp)
    print(f"{otp} and {otp_sent}")

    if not otp_sent:
        return jsonify({'error': 'Failed to send OTP'}), 500

    redis.setex(f"otp:{email}", 300, otp)
    redis.setex(f"signup:{email}", 300, json.dumps(data))

    return jsonify({'status': 'success', 'message': 'OTP sent successfully'}), 200


@user.route('/verify-signup', methods=['POST'])
def verify_otp_route():
    data = request.json
    email = data.get('email')
    otp_input = data.get('otp')

    stored_otp = redis.get(f"otp:{email}")
    if not stored_otp or stored_otp.decode() != otp_input:
        return jsonify({'error': 'Invalid or expired OTP'}), 400

    stored_data = redis.get(f"signup:{email}")
    if not stored_data:
        return jsonify({'error': 'Signup data expired or missing'}), 400

    user_data = json.loads(stored_data)

    superadmin = SuperAdmin.query.filter_by(superId=user_data['superadminId']).first()
    if not superadmin or not superadmin.superadminPanel:
        return jsonify({'error': 'SuperAdmin panel not found'}), 404
    
    new_user = User(
        superadminId=user_data['superadminId'],
        empId=gen_empId(),
        userName=user_data['userName'],
        email=user_data['email'],
        gender = user_data['gender'],
        password=generate_password_hash(user_data['password']),
        onBoardingStatus=user_data.get('onBoardingStatus'),
        profileImage=user_data.get('profileImage'),
        department=user_data.get('department'),
        sourceOfHire=user_data.get('sourceOfHire'),
        panNumber=user_data.get('panNumber'),
        adharNumber=user_data.get('adharNumber'),
        uanNumber=user_data.get('uanNumber'),
        userRole=user_data.get('userRole'),
        nationality=user_data.get('nationality'),
        number=user_data.get('number'),
        currentAddress=user_data.get('currentAddress'),
        permanentAddress=user_data.get('permanentAddress'),
        postal=user_data.get('postal'),
        city=user_data.get('city'),
        state=user_data.get('state'),
        country=user_data.get('country'),
        schoolName=user_data.get('schoolName'),
        degree=user_data.get('degree'),
        fieldOfStudy=user_data.get('fieldOfStudy'),
        currentSalary=user_data.get('currentSalary'),
        dateOfCompletion=user_data.get('dateOfCompletion'),
        skills=user_data.get('skills'),
        joiningDate=datetime.strptime(user_data.get('joiningDate'), '%Y-%m-%d') if user_data.get('joiningDate') else datetime.utcnow(),
        occupation=user_data.get('occupation'),
        company=user_data.get('company'),
        experience=user_data.get('experience'),
        duration=datetime.strptime(user_data.get('duration'), '%Y-%m-%d') if user_data.get('duration') else None,
        superadmin_panel_id=superadmin.superadminPanel.id,  # required for foreign key
    )

    db.session.add(new_user)
    db.session.flush() 

    new_user.panelData = UserPanelData()
    db.session.commit()

    access_token, refresh_token = create_tokens(user_id=new_user.id, role=new_user.userRole)

    redis.delete(f"otp:{email}")
    redis.delete(f"signup:{email}")

    return jsonify({
        'status': 'success',
        'message': 'User verified and created successfully',
        'user_id': new_user.id,
        'empId': new_user.empId,
        "userRole": new_user.userRole,
        'panelData_id': new_user.panelData.id,
        'access_token': access_token,
        "refresh_token": refresh_token,
    }), 201


@user.route('/login', methods=['POST'])
def user_login():
    data = request.json

    required_fields = ['email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'status': 'error', 'message': 'Email and password are required.'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    # Fetch associated superadmin
    superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
    if not superadmin:
        return jsonify({'status': 'error', 'message': 'Superadmin not found.'}), 404

    # Check superadmin expiry
    if superadmin.expiry_date and datetime.utcnow() > superadmin.expiry_date:
        return jsonify({'status': 'error', 'message': 'Superadmin account has expired.'}), 403

    # Verify password
    if not check_password_hash(user.password, data['password']):
        return jsonify({'status': 'error', 'message': 'Invalid password.'}), 401

    # Generate tokens
    access_token, refresh_token = create_tokens(user_id=user.id, role=user.userRole)

    user_data = {
        'id': user.id,
        'userName': user.userName,
        'email': user.email,
        'empId': user.empId,
        'userRole': user.userRole,
        'profileImage': user.profileImage,
        'superadminId': user.superadminId
    }

    return jsonify({
        'status': 'success',
        'message': 'Login successful.',
        'data': user_data,
        'token': {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    }), 200

# ====================================
#          USER PUNCH SECTION
# ====================================

@user.route('/punchin', methods=['POST'])
def punch_details():
    try:
        login = request.form.get('login')
        location = request.form.get('location')
        image_file = request.files.get('image')

        if not login or not location or not image_file:
            return jsonify({
                'status': 'error',
                'message': 'All fields (login, location, image) are required'
            }), 400

        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 400

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'No user found'}), 404

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin:
            return jsonify({'status': 'error', 'message': 'Unauthorized user'}), 403

        usersPanelData = user.panelData
        if not usersPanelData:
            return jsonify({'status': 'error', 'message': 'User panel data not found'}), 404

        try:
            login_time = parser.isoparse(login)
            if login_time.tzinfo:
                login_time = login_time.replace(tzinfo=None)
        except Exception:
            return jsonify({'status': 'error', 'message': 'Invalid login time format'}), 400

        today_start = datetime.combine(login_time.date(), datetime.min.time())
        today_end = datetime.combine(login_time.date(), datetime.max.time())

        existing_punch = PunchData.query.filter(
            PunchData.empId == user.empId,
            PunchData.login >= today_start,
            PunchData.login <= today_end
        ).first()

        if existing_punch:
            return jsonify({
                'status': 'error',
                'message': 'You have already punched in today.'
            }), 409

        shift = ShiftTimeManagement.query.filter_by(
            shiftType=user.shift,
            shiftStatus=True,
            superpanel=superadmin.superadminPanel.id
        ).first()

        if not shift:
            return jsonify({
                'status': 'error',
                'message': f'No active {user.shift} set by admin'
            }), 404

        try:
            upload_result = cloudinary.uploader.upload(image_file)
            image_url = upload_result.get('secure_url')
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Image upload failed',
                'error': str(e)
            }), 500
        
        today = login_time.date()
        max_early = datetime.combine(today, shift.MaxEarly.time())
        grace_time = datetime.combine(today, shift.GraceTime.time())
        max_late = datetime.combine(today, shift.MaxLateEntry.time())


        print("Login:", login_time)
        print("Max Early:", max_early)
        print("Grace:", grace_time)
        print("Max Late:", max_late)


        if login_time < max_early:
            return jsonify({
                'status': 'error',
                'message': 'Too early to punch in'
            }), 403

        if login_time <= grace_time:
            punch_status = 'ontime'
        elif login_time <= max_late:
            punch_status = 'late'
        else:
            punch_status = 'halfday'

        # Save punch-in
        punchin = PunchData(
            panelData=usersPanelData.id,
            empId=user.empId,
            name=user.userName,
            email=user.email,
            login=login_time,
            logout=None,
            location=location,
            totalhour=None,
            productivehour=None,
            shift=shift.shiftStart,
            status=punch_status,
            image=image_url
        )

        db.session.add(punchin)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': f'Punch-in successful. Status: {punch_status}',
            'punch_id': punchin.id,
            'image_url': image_url
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Error processing punch-in',
            'error': str(e)
        }), 500


@user.route('/punchin', methods=['GET'])
def get_punchDetails():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "No user found or auth token provided"
            }), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "No user found"
            }), 200

        panel_data = user.panelData
        if not panel_data:
            return jsonify({
                "status": "error",
                "message": "User panel data not found"
            }), 200

        punchdetails = panel_data.userPunchData
        if not punchdetails:
            return jsonify({
                "status": "error",
                "message": "No punch records found"
            }), 200

        punch_list = []
        for punch in punchdetails:
            punch_list.append({
                "id": punch.id,
                "image": punch.image,
                "empId": punch.empId,
                "name": punch.name,
                "email": punch.email,
                "login": punch.login.isoformat() if punch.login else None,
                "logout": punch.logout.isoformat() if punch.logout else None,
                "location": punch.location,
                "status": punch.status,
                "totalhour": punch.totalhour if isinstance(punch.totalhour, str) else punch.totalhour.strftime('%H:%M:%S') if punch.totalhour else None,
                "productivehour": punch.productivehour.isoformat() if punch.productivehour else None,
                "shift": punch.shift.isoformat() if punch.shift else None
            })

        return jsonify({
            "status": "success",
            "message": "Punch details fetched successfully",
            "data": punch_list
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/punchin', methods=['PUT'])
def punch_out_user():
    try:
        from dateutil import parser
        from datetime import datetime, time

        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        required_fields = ['logout', 'location']
        if not all(field in data for field in required_fields):
            return jsonify({"status": "error", "message": "Missing fields (logout, location)"}), 400

        # Parse logout time as offset-naive
        logout_time = parser.isoparse(data['logout'])
        if logout_time.tzinfo:
            logout_time = logout_time.replace(tzinfo=None)

        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "User not authenticated"}), 401

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin:
            return jsonify({"status": "error", "message": "Unauthorized access"}), 403

        # Find today's punch-in
        today_start = datetime.combine(logout_time.date(), datetime.min.time())
        today_end = datetime.combine(logout_time.date(), datetime.max.time())

        punchdata = PunchData.query.filter(
            PunchData.empId == user.empId,
            PunchData.login >= today_start,
            PunchData.login <= today_end
        ).first()

        if not punchdata:
            return jsonify({"status": "error", "message": "No punch-in found for today"}), 404

        if logout_time <= punchdata.login:
            return jsonify({"status": "error", "message": "Logout time must be after login time"}), 400

        # Calculate total hours
        time_diff = logout_time - punchdata.login
        total_seconds = int(time_diff.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        total_hour_time = time(hour=hours, minute=minutes, second=seconds)

        # Get shift information
        shift = ShiftTimeManagement.query.filter_by(
            shiftType=user.shift,
            shiftStatus=True,
            superpanel=superadmin.superadminPanel.id
        ).first()

        if not shift:
            return jsonify({"status": "error", "message": f"No active {user.shift} shift"}), 404

        today = logout_time.date()
        shift_start = datetime.combine(today, shift.shiftStart.time())
        grace_time = datetime.combine(today, shift.GraceTime.time())
        max_late = datetime.combine(today, shift.MaxLateEntry.time())
        half_day_threshold = datetime.combine(today, shift.HalfDayThreshhold.time())
        shift_end = datetime.combine(today, shift.shiftEnd.time())

        login_time = punchdata.login

        # Determine login status
        if login_time <= grace_time:
            login_status = "ontime"
        elif login_time <= max_late:
            login_status = "late"
        else:
            login_status = "halfday"

        # Determine logout status
        if logout_time < half_day_threshold:
            logout_status = "halfday"
        elif logout_time < shift_end:
            logout_status = "halfday"
        else:
            logout_status = "fullday"

        # Final status
        if login_status == "halfday" or logout_status == "halfday":
            final_status = "halfday"
        elif login_status == "late":
            final_status = "late"
        else:
            final_status = "fullday"

        # Update punch-out record
        punchdata.logout = logout_time
        punchdata.location = data['location']
        punchdata.totalhour = total_hour_time
        punchdata.status = final_status

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": f"Punch-out successful. Final status: {final_status}"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


# ====================================
#        USER DETAILS SECTION
# ====================================


@user.route('/profile', methods=['GET'])
def get_Profile():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({
                "status": "error",
                "message": "No user ID or auth token provided",
            }), 400

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "No user found"
            }), 400

        access_permissions = [
            {
                'section': access.section,
                'permission': access.permission,
                'allowed': access.allowed
            }
            for access in user.access_permissions
        ]

        # Core profile fields
        fields = {
            'id': user.id,
            'profileImage': user.profileImage,
            'superadminId': user.superadminId,
            'userName': user.userName,
            'empId': user.empId,
            'email': user.email,
            'gender': user.gender,
            'number': user.number,
            'currentAddress': user.currentAddress,
            'permanentAddress': user.permanentAddress,
            'postal': user.postal,
            'city': user.city,
            'state': user.state,
            'country': user.country,
            'nationality': user.nationality,
            'panNumber': user.panNumber,
            'adharNumber': user.adharNumber,
            'uanNumber': user.uanNumber,
            'department': user.department,
            'onBoardingStatus': user.onBoardingStatus,
            'sourceOfHire': user.sourceOfHire,
            'currentSalary': user.currentSalary,
            'joiningDate': user.joiningDate.strftime("%Y-%m-%d") if user.joiningDate else None,
            'schoolName': user.schoolName,
            'degree': user.degree,
            'fieldOfStudy': user.fieldOfStudy,
            'dateOfCompletion': user.dateOfCompletion.strftime("%Y-%m-%d") if user.dateOfCompletion else None,
            'skills': user.skills,
            'shift': user.shift,
            'occupation': user.occupation,
            'company': user.company,
            'experience': user.experience,
            'duration': user.duration,
            'userRole': user.userRole,
            'managerId': user.managerId,
            'superadmin_panel_id': user.superadmin_panel_id,
            'created_at': user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else None
        }

        # Determine if each field is filled
        field_status = {
            f"{key}_filled": (value is not None and value != '')
            for key, value in fields.items()
        }

        userDetails = {**fields, **field_status, 'access': access_permissions}

        return jsonify({
            "status": "success",
            "message": "Fetched successfully",
            "data": userDetails
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/profile', methods=['PUT'])
def edit_Profile():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({
                "data" : [],
                'status': 'error',
                'message': 'No auth token provided or user not found.'
            }), 400

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found.'
            }), 404

        data = request.form.to_dict()
        file = request.files.get('profileImage')

        updatable_fields = [
            'userName', 'gender', 'number', 'currentAddress', 'permanentAddress',
            'postal', 'city', 'state', 'country', 'nationality', 'panNumber',
            'adharNumber', 'uanNumber', 'department', 'onBoardingStatus',
            'sourceOfHire', 'currentSalary', 'joiningDate', 'schoolName',
            'degree', 'fieldOfStudy', 'dateOfCompletion', 'skills',
            'occupation', 'company', 'experience', 'duration', 'birthday','shift'
        ]

        if file:
            upload_result = cloudinary.uploader.upload(file, folder="user_profiles")
            user.profileImage = upload_result.get("secure_url")

        for field in updatable_fields:
            if field in data:
                if field in ['joiningDate', 'dateOfCompletion', 'birthday']:
                    try:
                        setattr(user, field, datetime.strptime(data[field], '%Y-%m-%d').date())
                    except ValueError:
                        return jsonify({
                            'status': 'error',
                            'message': f'Invalid date format for {field}. Use YYYY-MM-DD.'
                        }), 400
                else:
                    setattr(user, field, data[field])

        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'User details updated successfully.'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Internal Server Error',
            'error': str(e)
        }), 500


# ====================================
#        USER TICKET SECTION 
# ====================================


# user will raise ticket if having any problem
@user.route('/ticket', methods=['POST'])
def raise_ticket():
    data = request.form

    required_fields = ['topic', 'problem', 'priority']
    if not all(field in data for field in required_fields):
        return jsonify({
            'status': 'error',
            'message': "All fields are required"
        }), 400

    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'No auth token or userID found'
            }), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({
                'status': 'error',
                'message': 'User or user panel data not found'
            }), 404

        document_url = None
        if 'document' in request.files:
            file = request.files['document']
            if file:
                upload_result = cloudinary.uploader.upload(file)
                document_url = upload_result.get('secure_url')

        assigned_to_empId = None
        assigned_user_department = user.department  # default department

        if 'assign_to_empId' in data:
            assigned_to_empId = data['assign_to_empId']
            assigned_user = User.query.filter_by(empId=assigned_to_empId).first()
            if not assigned_user:
                return jsonify({
                    'status': 'error',
                    'message': 'Assigned user empId not found'
                }), 404
            assigned_user_department = assigned_user.department

        ticket = UserTicket(
            userName=user.userName,
            userId=user.empId,
            date=datetime.utcnow(),
            topic=data['topic'],
            problem=data['problem'],
            priority=data['priority'],
            department=assigned_user_department,  # assigned user's dept if assigned, else own dept
            document=document_url,
            status='pending',
            assigned_to_empId=assigned_to_empId,
            userticketpanel=user.panelData.id
        )

        db.session.add(ticket)
        db.session.commit()

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if superadmin:
            socketio.emit(
                'ticket_notification',
                {
                    'message': f'New ticket raised by {user.userName}',
                    'empId': user.empId,
                    'topic': ticket.topic,
                    'priority': ticket.priority,
                    'ticketId': ticket.id
                },
                room=superadmin.companyEmail
            )

        if assigned_to_empId:
            socketio.emit(
                'ticket_notification',
                {
                    'message': f"You have been assigned a new ticket #{ticket.id}",
                    'ticketId': ticket.id,
                    'assigned_by': user.empId
                },
                room=assigned_to_empId
            )

        return jsonify({
            'status': 'success',
            'message': 'Ticket raised successfully',
            'ticket': {
                'ticketId': ticket.id,
                'topic': ticket.topic,
                'priority': ticket.priority,
                'status': ticket.status,
                'document': document_url,
                'assigned_to': assigned_to_empId,
                'department': assigned_user_department
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }), 500


@user.route('/ticket', methods=['GET'])
def get_ticket():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user ID found"}), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 400

        panel_data = user.panelData
        if not panel_data or not panel_data.UserTicket:
            return jsonify({"status": "error", "message": "No tickets found"}), 404

        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit

        department_filter = request.args.get('department', '').strip().lower()
        status_filter = request.args.get('status', '').strip().lower()
        priority_filter = request.args.get('priority', '').strip().lower()

        filtered_tickets = []
        for ticket in panel_data.UserTicket:
            if department_filter and ticket.department.lower() != department_filter:
                continue
            if status_filter and ticket.status.lower() != status_filter:
                continue
            if priority_filter and ticket.priority.lower() != priority_filter:
                continue
            filtered_tickets.append(ticket)

        total_tickets = len(filtered_tickets)
        total_pages = (total_tickets + limit - 1) // limit

        paginated_tickets = filtered_tickets[offset:offset + limit]

        ticket_list = []
        for ticket in paginated_tickets:
            logs = [{
                "assigned_by": log.assigned_by_empId,
                "assigned_to": log.assigned_to_empId,
                "assigned_at": log.assigned_at.isoformat() if log.assigned_at else None
            } for log in ticket.assignment_logs]

            ticket_list.append({
                "ticket_id": ticket.id,
                "assigned_by": ticket.userName,
                "userId": ticket.userId,
                "date": ticket.date.isoformat() if ticket.date else None,
                "topic": ticket.topic,
                "problem": ticket.problem,
                "priority": ticket.priority,
                "department": ticket.department,
                "document": ticket.document,
                "status": ticket.status or 'pending',
                "assigned_to_empId": ticket.assigned_to_empId,
                "logs": logs
            })

        unique_departments = sorted(list(set([t.department for t in panel_data.UserTicket if t.department])))
        unique_statuses = sorted(list(set([t.status for t in panel_data.UserTicket if t.status])))
        unique_priorities = sorted(list(set([t.priority for t in panel_data.UserTicket if t.priority])))

        return jsonify({
            "status": "success",
            "message": "Fetched successfully",
            "pagination": {
                "current_page": page,
                "limit": limit,
                "total_tickets": total_tickets,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1,
                "next_page": page + 1 if page < total_pages else None,
                "prev_page": page - 1 if page > 1 else None
            },
            "filters": {
                "applied": {
                    "department": department_filter or None,
                    "status": status_filter or None,
                    "priority": priority_filter or None
                },
                "available": {
                    "departments": unique_departments,
                    "statuses": unique_statuses,
                    "priorities": unique_priorities
                }
            },
            "data": ticket_list
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500



# tickets assigned to user by other users and admin [route]
@user.route('/tickets/<int:ticket_id>', methods=['PUT'])
def editTicket(ticket_id):
    data = request.get_json()
    if not data:
        return jsonify({'status': "error", 'message': "No data provided"}), 400

    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({'status': 'error', 'message': 'No auth or user found'}), 400

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        ticket = UserTicket.query.filter_by(id=ticket_id).first()
        if not ticket:
            return jsonify({'status': 'error', 'message': 'Ticket not found'}), 404

        if ticket.userId != str(user.id) and ticket.assigned_to_empId != user.empId:
            return jsonify({
                'status': 'error',
                'message': 'You are not authorized to update this ticket'
            }), 403

        notify_status_change = False
        notify_assignment_change = False
        new_assignee_empId = None

        if 'status' in data and ticket.status != data['status']:
            ticket.status = data['status']
            notify_status_change = True

        if 'problem' in data:
            ticket.problem = data['problem']

        if 'assign_to_empId' in data:
            new_assignee_empId = data['assign_to_empId']
            if ticket.assigned_to_empId != new_assignee_empId:
                assigned_user = User.query.filter_by(empId=new_assignee_empId).first()
                if not assigned_user:
                    return jsonify({'status': 'error', 'message': 'Target empId not found'}), 404

                ticket.department = assigned_user.department

                log = TicketAssignmentLog(
                    ticket_id=ticket.id,
                    assigned_by_empId=user.empId,
                    assigned_to_empId=new_assignee_empId
                )
                db.session.add(log)

                ticket.assigned_to_empId = new_assignee_empId
                notify_assignment_change = True

        elif 'assign_to_department' in data:
            return jsonify({
                'status': 'error',
                'message': 'Users are not allowed to assign tickets to departments'
            }), 403

        db.session.commit()

        admin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        user_ticket_owner = User.query.filter_by(empId=ticket.userId).first()

        if notify_status_change:
            message = f"Ticket #{ticket.id} status changed to {ticket.status}"
            if admin:
                socketio.emit('ticket_notification', {'message': message, 'ticket_id': ticket.id}, room=admin.companyEmail)
            if user_ticket_owner:
                socketio.emit('ticket_notification', {'message': message, 'ticket_id': ticket.id}, room=user_ticket_owner.empId)

        if notify_assignment_change and new_assignee_empId:
            if admin:
                socketio.emit('ticket_notification', {
                    'message': f"Ticket #{ticket.id} reassigned to {new_assignee_empId}",
                    'ticket_id': ticket.id
                }, room=admin.companyEmail)

            socketio.emit('ticket_notification', {
                'message': f"You have been assigned to ticket #{ticket.id}",
                'ticket_id': ticket.id,
                'assigned_by': user.empId
            }, room=new_assignee_empId)

        return jsonify({
            'status': 'success',
            'message': 'Ticket updated successfully',
            'ticket_id': ticket.id,
            'new_status': ticket.status,
            'assigned_to': ticket.assigned_to_empId,
            'department': ticket.department
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': "error", 'message': "Internal Server Error", 'error': str(e)}), 500


@user.route('/tickets', methods=['GET'])
def get_assigned_tickets():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({
                'status': 'error',
                'message': 'No user or auth token found.'
            }), 401

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 10

        tickets = UserTicket.query.filter_by(assigned_to_empId=user.empId).order_by(UserTicket.date.desc()).all()

        total_tickets = len(tickets)
        total_pages = math.ceil(total_tickets / per_page) if total_tickets > 0 else 1

        start = (page - 1) * per_page
        end = start + per_page
        paginated = tickets[start:end]

        ticket_list = []
        for ticket in paginated:
            logs = [{
                'assigned_by': log.assigned_by_empId,
                'assigned_to': log.assigned_to_empId,
                'assigned_at': log.assigned_at.isoformat() if log.assigned_at else None
            } for log in ticket.assignment_logs]

            ticket_list.append({
                'ticket_id': ticket.id,
                'topic': ticket.topic,
                'problem': ticket.problem,
                'priority': ticket.priority,
                'department': ticket.department,
                'document': ticket.document,
                'status': ticket.status,
                'assigned_to_empId': ticket.assigned_to_empId,
                'assigned_by': ticket.assigned_by,
                'created_by': ticket.userName,
                'date': ticket.date.isoformat() if ticket.date else None,
                'logs': logs
            })

        return jsonify({
            'status': 'success',
            'assigned_to': user.empId,
            'pagination': {
                'current_page': page,
                'per_page': per_page,
                'total_tickets': total_tickets,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1,
                'next_page': page + 1 if page < total_pages else None,
                'prev_page': page - 1 if page > 1 else None
            },
            'tickets': ticket_list
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Internal Server Error',
            'error': str(e)
        }), 500


# ====================================
#        USER DOCUMENTS SECTION
# ====================================


@user.route('/documents', methods=['POST'])
def upload_documents():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 404

        user = User.query.filter_by(id=userID).first()
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel data not found"}), 400

        files = request.files.getlist('documents')  # Supports multiple files with name='documents'
        if not files or len(files) == 0:
            return jsonify({"status": "error", "message": "No documents found"}), 400

        titles = request.form.getlist('titles')  # Optional: list of titles matching file count
        uploaded_docs = []

        for i, file in enumerate(files):
            if file:
                upload_result = cloudinary.uploader.upload(file)
                doc_url = upload_result.get("secure_url")
                title = titles[i] if i < len(titles) else f"Document {i+1}"

                new_doc = UserDocument(
                    documents=doc_url,
                    panelDataID=user.panelData.id,
                    title=title
                )
                db.session.add(new_doc)
                uploaded_docs.append({"url": doc_url, "title": title})

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": f"{len(uploaded_docs)} document(s) uploaded successfully",
            "documents": uploaded_docs
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/documents', methods=['GET'])
def get_documents():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "No user or auth token found"
            }), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "No user found with this id"
            }), 409

        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))

        documents = user.panelData.UserDocuments if user.panelData else []

        if not documents:
            return jsonify({
                "status": "success",
                "field_filled": False,
                "message": "No documents found",
                "documents": []
            }), 200

        # Apply manual pagination if needed (SQLAlchemy paginate won't work on list)
        start = (page - 1) * limit
        end = start + limit
        paginated_docs = documents[start:end]

        document_list = [{
            'id': document.id,
            "documents": document.documents,
            "title": document.title,
        } for document in paginated_docs]

        return jsonify({
            "status": "success",
            "field_filled": True,
            "message": "Fetched successfully",
            "documents": document_list,
            "total": len(documents),
            "page": page,
            "limit": limit,
            "pages": (len(documents) + limit - 1) // limit
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/documents/<int:documentid>', methods=['PUT'])
def edit_documents(documentid):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 404

        user = User.query.filter_by(id=userID).first()
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel data not found"}), 400

        document = UserDocument.query.filter_by(id=documentid, panelDataID=user.panelData.id).first()
        if not document:
            return jsonify({"status": "error", "message": "No document found for this user"}), 404

        updated = False

        title = request.form.get('title')
        if title:
            document.title = title
            updated = True

        file = request.files.get('document')
        print('file',file)
        if file:
            result = cloudinary.uploader.upload(file)
            doc_url = result.get("secure_url")

            if not doc_url:
                return jsonify({"status": "error", "message": "Image upload failed"}), 500

            document.documents = doc_url
            updated = True

        if not updated:
            return jsonify({"status": "error", "message": "No changes submitted"}), 400

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Document updated successfully",
            "document": {
                "id": document.id,
                "url": document.documents,
                "title": document.title
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/documents/<int:document_id>', methods=['DELETE'])
def delete_document(document_id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 404

        user = User.query.filter_by(id=userID).first()
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel data not found"}), 400

        document = UserDocument.query.filter_by(id=document_id, panelDataID=user.panelData.id).first()
        if not document:
            return jsonify({"status": "error", "message": "Document not found or does not belong to user"}), 404

        db.session.delete(document)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Document deleted successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


# ====================================
#          USER SALARY SECTION
# ====================================

@user.route('/salaryrecords', methods=['GET'])
def salary_details():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status" : "error", "message" : "No user_id or auth token provided"}), 404
        
        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status" : "error", "message" : "No user found"}), 409
        
        salaryDetails = user.panelData.UserSalary
        if not salaryDetails:
            return jsonify({"status" : "error", "message" : "No salary details"}), 200
        
        salarylist=[]
        for salary in salaryDetails:
            salarylist.append({
                "id" : salary.id,
                "empId" : salary.empId,
                "present" : salary.present,
                "absent" : salary.absent,
                "basicSalary" : salary.basicSalary,
                "deductions" : salary.deductions,
                "finalPay" : salary.finalPay,
                "mode" : salary.mode,
                "status" : salary.status,
                "payslip" : salary.payslip,
                "approvedLeaves" : salary.approvedLeaves,
                "onHold" : salary.onhold,
                "approvedLeaves" : salary.onhold_reason,
            })

        return jsonify({"status" : "success", "message" : "fetched Successfully", "data" : salarylist}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status" : "error", "message" : "Internal Server Error", "error" : str(e)}), 500


@user.route('/salarydetails', methods=['GET'])
def get_user_salary_summary():
    try:
        user_id = g.user.get("userID") if g.user else None
        if not user_id:
            return jsonify({"status": "error", "message": "User not authenticated"}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        panel_data = user.panelData
        if not panel_data:
            return jsonify({"status": "error", "message": "User panel data not found"}), 404

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin:
            return jsonify({"status": "error", "message": "Unauthorized"}), 403

        today = datetime.utcnow().date()
        month_start = today.replace(day=1)
        month_end = today.replace(day=31) if today.month == 12 else (today.replace(month=today.month + 1, day=1) - timedelta(days=1))

        # --- Punch Info ---
        punch_count = 0
        total_halfday = 0
        total_late = 0
        punch_query = db.session.query(PunchData).filter(
            PunchData.panelData == panel_data.id,
            PunchData.login >= month_start,
            PunchData.login <= month_end
        )
        punch_count = punch_query.count()
        for status in punch_query.with_entities(PunchData.status).all():
            if status[0] == 'halfday':
                total_halfday += 1
            elif status[0] == 'late':
                total_late += 1

        # --- Leave Info ---
        paid_days = 0
        unpaid_days = 0
        leave_count = 0
        leaves = db.session.query(UserLeave).filter(
            UserLeave.panelData == panel_data.id,
            UserLeave.status == 'approved',
            UserLeave.leavefrom >= month_start,
            UserLeave.leavefrom <= month_end
        ).all()
        leave_count = len(leaves)
        for leave in leaves:
            unpaid = leave.unpaidDays or 0
            unpaid_days += unpaid
            paid_days += max((leave.days or 0) - unpaid, 0)

        # --- Job & Salary Info ---
        job_info = {
            "department": panel_data.userJobInfo[0].department if panel_data.userJobInfo else None,
        }

        # --- Shift Info ---
        admin_panel = superadmin.superadminPanel
        shift = ShiftTimeManagement.query.filter_by(
            superpanel=admin_panel.id,
            shiftStatus=True
        ).first()

        total_working_days = 0
        working_days_list = shift.workingDays if shift and shift.workingDays else []
        saturday_condition = shift.saturdayCondition if shift and shift.saturdayCondition else None

        if working_days_list:
            working_days_set = set(day.lower() for day in working_days_list)
            month_range = calendar.monthrange(today.year, today.month)[1]
            for day in range(1, month_range + 1):
                date = datetime(today.year, today.month, day).date()
                weekday = date.strftime("%A").lower()
                if weekday == 'saturday':
                    if saturday_condition:
                        week_no = (day - 1) // 7 + 1
                        if (
                            (saturday_condition == 'All Saturdays Working') or
                            (saturday_condition == 'First & Third Saturdays Working' and week_no in [1, 3]) or
                            (saturday_condition == 'Second & Fourth Saturdays Working' and week_no in [2, 4]) or
                            (saturday_condition == 'Only First Saturday Working' and week_no == 1)
                        ):
                            total_working_days += 1
                elif weekday in working_days_set:
                    total_working_days += 1

        return jsonify({
            "status": "success",
            "data": {
                "user": {
                    "empId": user.empId,
                    "name": user.userName,
                    "email": user.email,
                    "role": user.userRole,
                    "basic_salary": user.currentSalary,
                    "present": punch_count,
                    "halfday": total_halfday,
                    "late": total_late,
                    "leave_summary": {
                        "absent": leave_count,
                        "paid_days": paid_days,
                        "unpaid_days": unpaid_days
                    },
                    "jobInfo": job_info
                },
                "shift_policy": {
                    "workingDays": working_days_list,
                    "saturdayCondition": saturday_condition,
                    "totalWorkingDaysThisMonth": total_working_days
                }
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Failed to fetch user salary data",
            "error": str(e)
        }), 500


@user.route('/salary', methods=['POST'])
def post_user_salary():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({'status': 'error', 'message': 'User or panel data not found'}), 404

        data = request.get_json()
        if not data or 'baseSalary' not in data:
            return jsonify({'status': 'error', 'message': 'baseSalary is required'}), 400

        # Check if salary already exists for this user
        existing = UserSalary.query.filter_by(panelData=user.panelData.id).first()
        if existing:
            return jsonify({'status': 'error', 'message': 'Salary details already submitted'}), 409

        # Create new salary record
        salary = UserSalary(
            panelData=user.panelData.id,
            payType=data.get('payType'),
            ctc=int(data.get('ctc', 0)),
            baseSalary=int(data['baseSalary']),
            currency=data.get('currency'),
            paymentMode=data.get('paymentMode'),
            bankName=data.get('bankName'),
            accountNumber=data.get('accountNumber'),
            IFSC=data.get('IFSC')
        )

        db.session.add(salary)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Salary details submitted successfully',
            'data': {
                'payType': salary.payType,
                'ctc': salary.ctc,
                'baseSalary': salary.baseSalary,
                'currency': salary.currency,
                'paymentMode': salary.paymentMode,
                'bankName': salary.bankName,
                'accountNumber': salary.accountNumber,
                'IFSC': salary.IFSC
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }), 500


@user.route('/salary', methods=['GET'])
def get_user_salary():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({
                'status': 'success',
                'field_filled': False,
                'message': 'User or panel data not found',
                'data': None
            }), 200

        salary = UserSalary.query.filter_by(panelData=user.panelData.id).first()
        if not salary:
            return jsonify({
                'status': 'success',
                'field_filled': False,
                'message': 'Salary details not found',
                'data': None
            }), 200

        return jsonify({
            'status': 'success',
            'field_filled': True,
            'data': {
                'payType': salary.payType,
                'id': salary.id,
                'ctc': salary.ctc,
                'baseSalary': salary.baseSalary,
                'currency': salary.currency,
                'paymentMode': salary.paymentMode,
                'bankName': salary.bankName,
                'accountNumber': salary.accountNumber,
                'IFSC': salary.IFSC
            }
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }), 500


@user.route('/salary/<int:id>', methods=['PUT'])
def edit_user_salary(id):
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({'status': 'error', 'message': 'User or panel data not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        editable_fields = ['payType', 'ctc', 'baseSalary', 'currency', 'paymentMode', 'bankName', 'accountNumber', 'IFSC']

        salary = UserSalary.query.filter_by(panelData=user.panelData.id, id=id).first()

        if not salary:
            # Create new salary record
            salary = UserSalary(
                panelData=user.panelData.id
            )
            for field in editable_fields:
                if field in data:
                    setattr(salary, field, data[field])
            db.session.add(salary)
            db.session.commit()
            return jsonify({
                'status': 'success',
                'message': 'Salary details added successfully'
            }), 201

        # Update existing salary record
        for field in editable_fields:
            if field in data:
                setattr(salary, field, data[field])

        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Salary details updated successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Internal server error', 'error': str(e)}), 500


# ====================================
#        USER CHAT SECTION
# ====================================


@user.route('/colleagues/<int:id>', methods=['GET'])
def all_users(id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 400

        user = User.query.filter_by(id=userID).first()
        if not user or not user.superadminId:
            return jsonify({"status": "error", "message": "No user or Admin found"}), 409

        adminID = user.superadminId
        superadmin = SuperAdmin.query.filter_by(superId=adminID).first()

        if not superadmin or not superadmin.superadminPanel:
            return jsonify({"status": "error", "message": "No Admin panel found"}), 404

        all_users = superadmin.superadminPanel.allUsers or []

        # Admin as virtual user
        admin_user = {
            'id': superadmin.id,
            'userName': superadmin.companyName,
            'email': superadmin.companyEmail,
            'empId': superadmin.superId,
            'profile': None,  # You can replace this with actual admin profile image if exists
            'department': "Admin",
            'source_of_hire': "N/A",
            'PAN': None,
            'UAN': None,
            'joiningDate': None,
            'userType': 'admin'
        }

        if id != 0:
            if id == superadmin.id:
                return jsonify({
                    "status": "success",
                    "user": admin_user
                }), 200

            user_detail = next((u for u in all_users if u.id == id), None)
            if not user_detail:
                return jsonify({"status": "error", "message": "User not found"}), 404

            return jsonify({
                "status": "success",
                "user": {
                    'id': user_detail.id,
                    'userName': user_detail.userName,
                    'profile': user_detail.profileImage,
                    'email': user_detail.email,
                    'empId': user_detail.empId,
                    'department': user_detail.department,
                    'source_of_hire': user_detail.sourceOfHire,
                    'PAN': user_detail.panNumber,
                    'UAN': user_detail.uanNumber,
                    'joiningDate': user_detail.joiningDate,
                    'userType': 'user'
                }
            }), 200

        # Paginated list
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        start = (page - 1) * limit
        end = start + limit

        userList = [{
            'id': u.id,
            'userName': u.userName,
            'profile': u.profileImage,
            'email': u.email,
            'empId': u.empId,
            'department': u.department,
            'source_of_hire': u.sourceOfHire,
            'PAN': u.panNumber,
            'UAN': u.uanNumber,
            'joiningDate': u.joiningDate,
            'userType': 'user'
        } for u in all_users]

        userList.insert(0, admin_user)

        total_users = len(userList)
        paginated_users = userList[start:end]

        return jsonify({
            "status": "success",
            "message": "Fetched successfully",
            "page": page,
            "limit": limit,
            "total_users": total_users,
            "total_pages": (total_users + limit - 1) // limit,
            "users": paginated_users
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


#send messages to users
@user.route('/message', methods=['POST'])
def send_message():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 400

        if not user.panelData:
            return jsonify({"status": "error", "message": "Panel data not found"}), 200

        recieverId = request.form.get('recieverID')  # this should be empId or superId
        message_text = request.form.get('message')
        uploaded_file = request.files.get('file')

        if not recieverId:
            return jsonify({"status": "error", "message": "Receiver ID is required"}), 400
        if not message_text and not uploaded_file:
            return jsonify({"status": "error", "message": "Message or file is required"}), 400

        # First check if receiver is a User
        reciever = User.query.filter_by(empId=recieverId).first()
        if reciever:
            reciever_empId = reciever.empId
        else:
            admin = SuperAdmin.query.filter_by(superId=recieverId).first()
            if not admin:
                return jsonify({"status": "error", "message": "Receiver not found"}), 200
            reciever_empId = admin.superId 

        file_url = None
        message_type = 'text'

        if uploaded_file:
            filename = secure_filename(uploaded_file.filename)
            mimetype = uploaded_file.mimetype
            file_ext = os.path.splitext(filename)[-1].lower()

            folder_path = os.path.join('static', 'uploads', 'chat_files')
            os.makedirs(folder_path, exist_ok=True)
            filepath = os.path.join(folder_path, filename)
            uploaded_file.save(filepath)
            file_url = filepath

            if mimetype.startswith("image/"):
                message_type = 'image' if not message_text else 'text_image'
            else:
                message_type = 'file' if not message_text else 'text_file'

        message = UserChat(
            panelData=user.panelData.id,
            senderID=user.empId,
            recieverID=reciever_empId,
            message=message_text if message_text else None,
            image_url=file_url,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.session.add(message)
        db.session.commit()

        socketio.emit('receive_message', {
            'senderID': user.empId,
            'recieverID': reciever_empId,
            'message': message_text,
            'file_url': file_url,
            'message_type': message_type,
            'timestamp': str(message.created_at)
        }, room=str(reciever_empId))

        socketio.emit('message_sent', {'status': 'success'}, room=user.empId)

        return jsonify({"status": "success", "message": "Message sent"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500



@user.route('/message/<string:with_empId>', methods=['GET'])
def get_chat_messages(with_empId):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        if not user.panelData:
            return jsonify({"status": "error", "message": "User panel data not found"}), 404

        sender_empId = user.empId

        receiver_user = User.query.filter_by(empId=with_empId).first()
        receiver_admin = SuperAdmin.query.filter_by(superId=with_empId).first()
        if not receiver_user and not receiver_admin:
            return jsonify({"status": "error", "message": "Receiver user or admin not found"}), 404

        chats = UserChat.query.filter(
            ((UserChat.senderID == sender_empId) & (UserChat.recieverID == with_empId)) |
            ((UserChat.senderID == with_empId) & (UserChat.recieverID == sender_empId))
        ).order_by(UserChat.created_at.asc()).all()

        messages = []
        for chat in chats:
            ext = os.path.splitext(chat.image_url)[1].lower() if chat.image_url else ''
            message_type = "image" if ext in ['.jpg', '.jpeg', '.png'] else ("file" if ext else "text")
            image_url = url_for('static', filename=chat.image_url.replace('static/', ''), _external=True) if chat.image_url else None

            messages.append({
                "id": chat.id,
                "senderID": chat.senderID,
                "receiverID": chat.recieverID,
                "message": chat.message,
                "image_url": image_url,
                "message_type": message_type,
                "created_at": chat.created_at.astimezone(timezone('Asia/Kolkata')).isoformat()
            })

        return jsonify({
            "status": "success",
            "messages": messages
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal server error",
            "error": str(e)
        }), 500



#send messages to department
@user.route('/department/message', methods=['GET'])
def get_user_department_messages():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.department:
            return jsonify({'status': 'error', 'message': 'User or department not found'}), 404

        messages = (
            UserChat.query
            .filter_by(department=user.department)
            .order_by(UserChat.created_at.asc())
            .all()
        )

        result = []
        for msg in messages:
            result.append({
                'message_id': msg.id,
                'senderID': msg.senderID,
                'is_self': msg.senderID == user.empId,
                'message': msg.message,
                'image_url': msg.image_url,
                'created_at': msg.created_at.strftime("%Y-%m-%d %H:%M:%S")
            })

        return jsonify({
            'status': 'success',
            'department': user.department,
            'total_messages': len(result),
            'messages': result
        }), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@user.route('/department/message', methods=['POST'])
def user_send_message_to_department():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.department:
            return jsonify({'status': 'error', 'message': 'User or department not found'}), 404

        message_text = request.form.get('message')
        uploaded_file = request.files.get('file')

        if not message_text and not uploaded_file:
            return jsonify({'status': 'error', 'message': 'Message or file is required'}), 400

        file_url = None
        if uploaded_file:
            upload_result = cloudinary.uploader.upload(uploaded_file)
            file_url = upload_result.get('secure_url')

        message = UserChat(
            panelData=user.panelData.id,
            senderID=user.empId,
            recieverID=None,  # group chat
            department=user.department,
            message=message_text,
            image_url=file_url
        )

        db.session.add(message)
        db.session.commit()

        # Emit to department
        socketio.emit('receive_department_message', {
            'senderID': user.empId,
            'message': message_text,
            'file_url': file_url,
            'timestamp': message.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }, room=user.department)

        return jsonify({'status': 'success', 'message': 'Message sent'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500



#send message to organization
@user.route('/organization/message', methods=['POST'])
def send_message_to_organization():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({'status': 'error', 'message': 'User or panel data not found'}), 404

        message_text = request.form.get('message')
        uploaded_file = request.files.get('file')

        if not message_text and not uploaded_file:
            return jsonify({'status': 'error', 'message': 'Message or file required'}), 400

        file_url = None
        if uploaded_file:
            upload_result = cloudinary.uploader.upload(uploaded_file)
            file_url = upload_result.get('secure_url')

        # Save the message
        chat = UserChat(
            panelData=user.panelData.id,
            senderID=user.empId,
            recieverID=None,
            department=None,
            message=message_text,
            image_url=file_url
        )
        db.session.add(chat)
        db.session.commit()

        # Emit to panel room (organization)
        room_name = f"panel_{user.superadmin_panel_id}"
        socketio.emit('receive_organization_message', {
            'message': message_text,
            'file_url': file_url,
            'sender': user.userName,
            'sender_empId': user.empId,
            'timestamp': chat.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }, room=room_name)

        return jsonify({'status': 'success', 'message': 'Message sent to organization'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@user.route('/organization/message', methods=['GET'])
def get_organization_messages_for_user():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({'status': 'error', 'message': 'User or panel data not found'}), 404

        messages = (
            UserChat.query
            .filter(
                UserChat.panelData == user.panelData.id,
                UserChat.department == None,
                UserChat.recieverID == None
            )
            .order_by(UserChat.created_at.asc())
            .all()
        )

        result = []
        for msg in messages:
            result.append({
                'message_id': msg.id,
                'senderID': msg.senderID,
                'message': msg.message,
                'image_url': msg.image_url,
                'timestamp': msg.created_at.isoformat()
            })

        return jsonify({
            'status': 'success',
            'total_messages': len(result),
            'messages': result
        }), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ====================================
#        USER LEAVE SECTION
# ====================================

@user.route('/leave', methods=['POST'])
def request_leave():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No data provided", "status": "error"}), 400

    required_fields = ['empId', 'leavetype', 'leavefrom', 'leaveto', 'reason']
    if not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 409

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "Invalid user"}), 404

        # Get superadmin via superId
        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin:
            return jsonify({"status": "error", "message": "Admin not found"}), 409

        if not hasattr(superadmin.superadminPanel, 'adminLeave') or not superadmin.superadminPanel.adminLeave:
            return jsonify({'status': "error", "message": "Admin has not configured any leave policies"}), 404

        # Match policy based on leavetype
        leavetype = data['leavetype']
        adminLeaveDetails = next((
            policy for policy in superadmin.superadminPanel.adminLeave
            if policy.leaveType.lower() == leavetype.lower()
        ), None)

        if not adminLeaveDetails:
            return jsonify({"status": "error", "message": f"No policy found for leave type '{leavetype}'"}), 404

        # Parse leave dates
        leaveStart = datetime.strptime(data['leavefrom'], "%Y-%m-%d").date()
        leaveEnd = datetime.strptime(data['leaveto'], "%Y-%m-%d").date()
        totalDays = (leaveEnd - leaveStart).days + 1

        today = datetime.utcnow().date()
        currentMonth = today.month
        currentYear = today.year
        unpaidDays = 0

        # --- Probation ---
        if adminLeaveDetails.probation and user.duration:
            if (user.duration - today).days <= 30:
                return jsonify({"status": "error", "message": "You can't apply for leave within 1 month of resignation"}), 403

        # --- Lapse Policy ---
        previousYearLeaves = 0
        if not adminLeaveDetails.lapse_policy:
            previousYearLeaves = db.session.query(func.sum(UserLeave.days)).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                UserLeave.leavefrom.between(f'{currentYear - 1}-01-01', f'{currentYear - 1}-12-31')
            ).scalar() or 0

        # --- Calculation Type Range ---
        calc_type = adminLeaveDetails.calculationType
        start_range, end_range, prev_start, prev_end = None, None, None, None

        if calc_type == 'monthly':
            start_range = today.replace(day=1)
            if currentMonth == 12:
                end_range = today.replace(day=31)
            else:
                end_range = (today.replace(month=currentMonth + 1, day=1) - timedelta(days=1))

            prev_start = (start_range - timedelta(days=1)).replace(day=1)
            prev_end = start_range - timedelta(days=1)

        elif calc_type == 'quarterly':
            start_month = 1 + 3 * ((currentMonth - 1) // 3)
            end_month = start_month + 2
            start_range = datetime(currentYear, start_month, 1).date()
            end_range = datetime(currentYear, end_month + 1, 1).date() - timedelta(days=1)
            prev_start_month = start_month - 3 if start_month > 3 else 10
            prev_year = currentYear if start_month > 3 else currentYear - 1
            prev_start = datetime(prev_year, prev_start_month, 1).date()
            prev_end = datetime(prev_year, prev_start_month + 3, 1).date() - timedelta(days=1)

        elif calc_type == 'yearly':
            start_range = datetime(currentYear, 1, 1).date()
            end_range = datetime(currentYear, 12, 31).date()
            prev_start = datetime(currentYear - 1, 1, 1).date()
            prev_end = datetime(currentYear - 1, 12, 31).date()

        # --- Carryforward ---
        carried_forward = 0
        if adminLeaveDetails.carryforward:
            prev_taken = db.session.query(func.sum(UserLeave.days)).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                and_(
                    UserLeave.leavefrom >= prev_start,
                    UserLeave.leavefrom <= prev_end
                )
            ).scalar() or 0

            prev_allowance = adminLeaveDetails.max_leave_once
            if calc_type == 'yearly':
                prev_allowance = adminLeaveDetails.max_leave_year

            carried_forward = max(prev_allowance - prev_taken, 0)

        # --- Current Cycle Taken ---
        cycle_taken = db.session.query(func.sum(UserLeave.days)).filter(
            UserLeave.empId == data['empId'],
            UserLeave.status == 'approved',
            and_(
                UserLeave.leavefrom >= start_range,
                UserLeave.leavefrom <= end_range
            )
        ).scalar() or 0

        cycle_limit = adminLeaveDetails.max_leave_once
        if calc_type == 'yearly':
            cycle_limit = adminLeaveDetails.max_leave_year

        total_available = cycle_limit + carried_forward
        if cycle_taken + totalDays > total_available:
            unpaidDays += (cycle_taken + totalDays) - total_available

        # --- Monthly Limit (if exists) ---
        if hasattr(adminLeaveDetails, 'monthly_leave_limit') and adminLeaveDetails.monthly_leave_limit:
            monthly_limit = adminLeaveDetails.monthly_leave_limit
            leave_month = leaveStart.month
            leave_year = leaveStart.year
            current_month_start = datetime(leave_year, leave_month, 1).date()
            current_month_end = (
                datetime(leave_year, leave_month + 1, 1) - timedelta(days=1)
                if leave_month < 12 else datetime(leave_year, 12, 31).date()
            )

            prev_month_start = (
                datetime(leave_year - 1, 12, 1).date() if leave_month == 1
                else datetime(leave_year, leave_month - 1, 1).date()
            )
            prev_month_end = (
                datetime(leave_year - 1, 12, 31).date() if leave_month == 1
                else datetime(leave_year, leave_month, 1).date() - timedelta(days=1)
            )

            # Paid leaves in current month
            current_month_leaves = db.session.query(UserLeave.days, UserLeave.unpaidDays).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                and_(
                    UserLeave.leavefrom >= current_month_start,
                    UserLeave.leavefrom <= current_month_end
                )
            ).all()

            current_month_paid = sum(days - (unpaid or 0) for days, unpaid in current_month_leaves)

            # Previous unused
            prev_month_taken = db.session.query(func.sum(UserLeave.days)).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                and_(
                    UserLeave.leavefrom >= prev_month_start,
                    UserLeave.leavefrom <= prev_month_end
                )
            ).scalar() or 0

            prev_unused = max(monthly_limit - prev_month_taken, 0)
            monthly_available = monthly_limit + prev_unused

            if current_month_paid >= monthly_available:
                monthly_unpaid = totalDays
            elif current_month_paid + totalDays > monthly_available:
                monthly_unpaid = (current_month_paid + totalDays) - monthly_available
            else:
                monthly_unpaid = 0

            unpaidDays = max(unpaidDays, monthly_unpaid)

        # --- Max Leave per Year ---
        yearlyLeaveTaken = db.session.query(func.sum(UserLeave.days)).filter(
            UserLeave.empId == user.empId,
            UserLeave.status == 'approved',
            extract('year', UserLeave.leavefrom) == currentYear
        ).scalar() or 0

        if yearlyLeaveTaken + totalDays > adminLeaveDetails.max_leave_year:
            yearly_unpaid = (yearlyLeaveTaken + totalDays) - adminLeaveDetails.max_leave_year
            unpaidDays = max(unpaidDays, yearly_unpaid)

        newLeave = UserLeave(
            panelData=user.panelData.id,
            empId=data['empId'],
            leavetype=leavetype,
            leavefrom=leaveStart,
            leaveto=leaveEnd,
            reason=data['reason'],
            name=user.userName,
            email=user.email,
            days=totalDays,
            status='pending',
            unpaidDays=unpaidDays
        )

        db.session.add(newLeave)
        db.session.commit()

        socketio.emit(
            'leave_request',
            {
                "title": "New Leave Request",
                "message": f"{user.userName} has requested leave from {leaveStart} to {leaveEnd}",
                "empId": user.empId,
                "days": int(totalDays),
                "unpaidDays": int(unpaidDays),
                "leaveType": leavetype
            },
            room=superadmin.companyEmail
        )

        return jsonify({"status": "success", "message": "Leave request submitted"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Internal Server Error", "error": str(e)}), 500


@user.route('/leave', methods=['GET'])
def get_leave_details():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user or auth token provided"}), 409

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        # Pagination & filtering inputs
        page = request.args.get('page', default=1, type=int)
        limit = request.args.get('limit', default=10, type=int)
        status = request.args.get('status', type=str)
        offset = (page - 1) * limit

        all_leaves = user.panelData.userLeaveData or []

        # Filter by leave status if provided
        if status:
            all_leaves = [leave for leave in all_leaves if leave.status == status]

        # Sort by applied date (most recent first)
        all_leaves = sorted(all_leaves, key=lambda x: x.createdAt or datetime.min, reverse=True)

        # Compute totals
        total_records = len(all_leaves)
        total_pages = math.ceil(total_records / limit)

        total_days = sum([leave.days or 0 for leave in all_leaves])
        unpaid_total = sum([leave.unpaidDays or 0 for leave in all_leaves])
        paid_total = total_days - unpaid_total

        # Paginate
        paginated_leaves = all_leaves[offset:offset + limit]

        # Format leave records
        leave_list = []
        for leave in paginated_leaves:
            leave_list.append({
                "id": leave.id,
                "leaveType": leave.leavetype,
                "leaveFrom": leave.leavefrom.strftime('%Y-%m-%d') if leave.leavefrom else None,
                "leaveTo": leave.leaveto.strftime('%Y-%m-%d') if leave.leaveto else None,
                "days": leave.days,
                "unpaidDays": leave.unpaidDays,
                "status": leave.status,
                "reason": leave.reason,
                "appliedOn": leave.createdAt.strftime('%Y-%m-%d') if leave.createdAt else 'N/A'
            })

        return jsonify({
            "status": "success",
            "message": "Leave history fetched successfully",
            "summary": {
                "totalLeaves": total_days,
                "paidLeaves": paid_total,
                "unpaidLeaves": unpaid_total,
                "recordCount": total_records
            },
            "pagination": {
                "page": page,
                "limit": limit,
                "totalPages": total_pages,
                "hasMore": page < total_pages
            },
            "data": leave_list
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500



# ====================================
#   USER ANNOUNCE AND POLL SECTION
# ====================================


@user.route('/poll', methods=['POST'])
def check_pole():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "No user or auth token provided",
            }), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "User not found",
            }), 404

        data = request.get_json()
        announcement_id = data.get('announcement_id')
        selected_option = data.get('selected_option')

        if not announcement_id or selected_option is None:
            return jsonify({
                "status": "error",
                "message": "Announcement ID and selected_option are required",
            }), 400

        announcement = Announcement.query.filter_by(id=announcement_id).first()
        if not announcement:
            return jsonify({
                "status": "error",
                "message": "Announcement not found",
            }), 404

        if selected_option == 1 and announcement.poll_option_1:
            announcement.votes_option_1 += 1
        elif selected_option == 2 and announcement.poll_option_2:
            announcement.votes_option_2 += 1
        elif selected_option == 3 and announcement.poll_option_3:
            announcement.votes_option_3 += 1
        elif selected_option == 4 and announcement.poll_option_4:
            announcement.votes_option_4 += 1
        else:
            return jsonify({
                "status": "error",
                "message": "Selected option is invalid or not available",
            }), 400

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Your vote was recorded successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/announcement', methods=['GET'])
def get_announcement():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "No user or auth token",
            }), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "No user found",
            }), 200

        useradmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not useradmin:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 409

        allAnnouncement = useradmin.superadminPanel.adminAnnouncement

        result = []
        for ann in allAnnouncement:
            if not ann.is_published:
                continue
            if ann.scheduled_time and ann.scheduled_time > datetime.utcnow():
                continue

            liked_by_user = Likes.query.filter_by(
                announcement_id=ann.id,
                empId=userID
            ).first() is not None

            comment_list = [{
                "id": c.id,
                "empId": c.empId,
                "comment": c.comments,
                "created_at": c.created_at.isoformat()
            } for c in ann.comments]

            result.append({
                "id": ann.id,
                "title": ann.title,
                "content": ann.content,
                "images": ann.images,
                "video": ann.video,
                "is_published": ann.is_published,
                "created_at": ann.created_at,
                "scheduled_time": ann.scheduled_time if ann.scheduled_time else None,
                "likes_count": len(ann.likes),
                "liked_by_user": liked_by_user,
                "comments": comment_list,
                "poll": {
                    "question": ann.poll_question,
                    "options": [
                        {"text": ann.poll_option_1, "votes": ann.votes_option_1},
                        {"text": ann.poll_option_2, "votes": ann.votes_option_2},
                        {"text": ann.poll_option_3, "votes": ann.votes_option_3},
                        {"text": ann.poll_option_4, "votes": ann.votes_option_4}
                    ] if ann.poll_question else None
                }
            })

        return jsonify({
            "status": "success",
            "announcements": result
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/announcement/<int:announcement_id>', methods=['POST'])
def interact_with_announcement(announcement_id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({"status": "error", "message": "No user found"}), 404

        data = request.get_json() or {}
        like = data.get('like')
        comment_text = data.get('comment', '').strip()

        announcement = Announcement.query.get(announcement_id)
        if not announcement:
            return jsonify({"status": "error", "message": "Announcement not found"}), 404

        response = {"status": "success", "message": []}

        if like is not None:
            existing_like = Likes.query.filter_by(announcement_id=announcement_id, empId=user.empId).first()
            if like:
                if not existing_like:
                    db.session.add(Likes(announcement_id=announcement_id, empId=user.empId))
                    response["message"].append("Like Successfully.")
                else:
                    response["message"].append("You have already liked this.")
            else:
                if existing_like:
                    db.session.delete(existing_like)
                    response["message"].append("unliked")
                else:
                    response["message"].append("not_liked_yet")

        if comment_text:
            new_comment = Comments(
                announcement_id=announcement_id,
                empId=user.empId,
                comments=comment_text
            )
            db.session.add(new_comment)
            response["actions"].append("commented")

        db.session.commit()

        return jsonify(response), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


# ====================================
#   USER NOTICE AND HOLIDAY SECTION
# ====================================


@user.route('/notice', methods=['GET'])
def get_Notice():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 404

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "User not found",
            }), 200

        userAdmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not userAdmin:
            return jsonify({
                "status": "error",
                "message": "Unauthorized access",
            }), 403

        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)

        query = Notice.query.filter_by(superpanel=userAdmin.superadminPanel.id)
        pagination = query.order_by(Notice.createdAt.desc()).paginate(page=page, per_page=limit, error_out=False)

        notice_list = [{
            "id": n.id,
            "notice": n.notice,
            "createdAt": n.createdAt.isoformat() if n.createdAt else None
        } for n in pagination.items]

        return jsonify({
            "status": "success",
            "notices": notice_list,
            "pagination": {
                "page": pagination.page,
                "per_page": pagination.per_page,
                "total_pages": pagination.pages,
                "total_items": pagination.total
            }
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/holiday', methods=['GET'])
def holidays():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 404

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 200

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 200

        holiday_list = superadmin.superadminPanel.adminHolidays if hasattr(superadmin.superadminPanel, 'adminHolidays') else []

        if not holiday_list:
            return jsonify({
                "status": "error",
                "message": "No holidays yet",
            }), 200

        today = datetime.utcnow().date()
        upcoming = []
        past = []

        for holiday in holiday_list:
            if holiday.is_enabled is False:
                continue

            holiday_info = {
                "id": holiday.id,
                "name": holiday.name,
                "date": holiday.date.strftime('%Y-%m-%d'),
                "country": holiday.country,
                "year": holiday.year,
                "is_enabled": holiday.is_enabled if holiday.is_enabled is not None else True,
                "description": None 
            }

            if holiday.date >= today:
                upcoming.append(holiday_info)
            else:
                past.append(holiday_info)

        upcoming.sort(key=lambda x: x['date'])
        past.sort(key=lambda x: x['date'])

        return jsonify({
            "status": "success",
            "message": "Holiday list fetched successfully",
            "upcoming": upcoming,
            "past": past
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e),
        }), 500


# ====================================
#        USER ASSETS SECTION
# ====================================


@user.route('/assets', methods=['POST'])
def request_assets():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
            }), 401  # Changed from 404 to 401

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "User not found",
            }), 200

        if not hasattr(user, 'panelData') or not user.panelData:
            return jsonify({
                "status": "error",
                "message": "User panel data not found"
            }), 200

        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": "No JSON data provided"
            }), 400

        required_fields = ['productName', 'qty']

        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    "status": "error",
                    "message": f"Missing or empty required field: {field}"
                }), 400

        # Extract and validate data
        category = data.get('category')
        productId = data.get('productId')
        condition = data.get('condition')
        location = data.get('location')
        qty = data.get('qty', 1)

        try:
            qty = int(qty)
            if qty <= 0:
                return jsonify({
                    "status": "error",
                    "message": "Quantity must be a positive number"
                }), 400
        except (ValueError, TypeError):
            return jsonify({
                "status": "error",
                "message": "Quantity must be a valid number"
            }), 400

        purchaseDate = None
        if data.get('purchaseDate'):
            try:
                purchaseDate = datetime.strptime(data['purchaseDate'], '%Y-%m-%d')
            except ValueError:
                return jsonify({
                    "status": "error",
                    "message": "Invalid purchaseDate format. Use YYYY-MM-DD"
                }), 400

        warrantyTill = None
        if data.get('warrantyTill'):
            try:
                warrantyTill = datetime.strptime(data['warrantyTill'], '%Y-%m-%d')
                # Validate warranty date is not in the past
                if warrantyTill < datetime.now():
                    return jsonify({
                        "status": "error",
                        "message": "Warranty date cannot be in the past"
                    }), 400
            except ValueError:
                return jsonify({
                    "status": "error",
                    "message": "Invalid warrantyTill format. Use YYYY-MM-DD"
                }), 400

        if purchaseDate and purchaseDate > datetime.now():
            return jsonify({
                "status": "error",
                "message": "Purchase date cannot be in the future"
            }), 400

        asset = ProductAsset(
            superpanel=user.panelData.id,
            productId=productId,
            productName=data['productName'].strip(),  # Strip whitespace
            category=category.strip() if category else None,
            qty=qty,
            department=getattr(user, 'department', None),  # Safe access
            purchaseDate=purchaseDate,
            warrantyTill=warrantyTill,
            condition=condition.strip() if condition else None,
            status='pending',
            location=location.strip() if location else None,
            assignedTo=str(user.empId) if hasattr(user, 'empId') and user.empId else str(userId),
            username=str(user.userName) if hasattr(user, 'userName') and user.userName else None,
            dateofrequest=datetime.now()  # Add request timestamp
        )

        db.session.add(asset)
        db.session.commit()

        try:
            if hasattr(user.panelData, 'MyAssets'):
                if user.panelData.MyAssets is None:
                    user.panelData.MyAssets = []
                user.panelData.MyAssets.append(asset)
                db.session.commit()
        except Exception as e:
            print(f"Warning: Could not add asset to user's MyAssets: {str(e)}")

        return jsonify({
            "status": "success",
            "message": "Asset request submitted successfully",
            "data": {
                "asset_id": asset.id,
                "product_name": asset.productName,
                "status": asset.status,
                "request_date": asset.dateofrequest.strftime('%Y-%m-%d %H:%M:%S') if hasattr(asset, 'dateofrequest') and asset.dateofrequest else None
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error in request_assets: {str(e)}")  # Log the error
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/assets', methods=['GET'])
def get_assets():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({
                "status": "error",
                "message": "Unauthorized"
            }), 401

        user = User.query.filter_by(id=userId).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "User not found"
            }), 200

        if not hasattr(user, 'panelData') or not user.panelData:
            return jsonify({
                "status": "error",
                "message": "User panel data not found"
            }), 400

        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        status_filter = request.args.get('status')

        if page < 1:
            page = 1
        if limit < 1 or limit > 100:
            limit = 10

        user_assets = []

        # Try getting from panelData.MyAssets
        if hasattr(user.panelData, 'MyAssets') and user.panelData.MyAssets:
            try:
                if hasattr(user.panelData.MyAssets, '__iter__'):
                    user_assets = list(user.panelData.MyAssets)
                else:
                    user_assets = [user.panelData.MyAssets]
            except Exception:
                user_assets = []

        # Fallback: query by assignedTo
        if not user_assets:
            try:
                user_assets = ProductAsset.query.filter(
                    db.or_(
                        ProductAsset.assignedTo == str(userId),
                        ProductAsset.assignedTo == str(getattr(user, 'empId', userId))
                    )
                ).all()
            except Exception:
                user_assets = []

        # Fallback: query all by panel if nothing found
        if not user_assets and hasattr(user.panelData, 'id'):
            try:
                user_assets = ProductAsset.query.filter_by(
                    superpanel=user.panelData.id
                ).all()
            except Exception:
                user_assets = []

        if not user_assets:
            return jsonify({
                "status": "success",
                "message": "No assets found",
                "data": [],
                "page": page,
                "total_pages": 0,
                "total_assets": 0
            }), 200

        # Filter assets by user ownership
        filtered_assets = []
        for asset in user_assets:
            try:
                assigned_to = getattr(asset, 'assignedTo', None)
                if assigned_to:
                    if (str(assigned_to) == str(userId) or 
                        str(assigned_to) == str(getattr(user, 'empId', ''))):
                        filtered_assets.append(asset)
                else:
                    filtered_assets.append(asset)
            except Exception as e:
                print(f"Debug: Error processing asset: {str(e)}")
                continue

        # Apply status filter if provided and not 'all'
        if status_filter and status_filter.lower() != "all":
            filtered_assets = [
                asset for asset in filtered_assets 
                if hasattr(asset, 'status') and asset.status == status_filter
            ]

        total = len(filtered_assets)
        start = (page - 1) * limit
        end = start + limit
        paginated_assets = filtered_assets[start:end]

        asset_list = []
        for asset in paginated_assets:
            try:
                asset_data = {
                    "id": getattr(asset, 'id', None),
                    "productId": getattr(asset, 'productId', None),
                    "productName": getattr(asset, 'productName', None),
                    "category": getattr(asset, 'category', None),
                    "qty": getattr(asset, 'qty', None),
                    "department": getattr(asset, 'department', None),
                    "status": getattr(asset, 'status', None),
                    "condition": getattr(asset, 'condition', None),
                    "location": getattr(asset, 'location', None),
                    "assignedTo": getattr(asset, 'assignedTo', None),
                    "dateofrequest": None,
                    "purchaseDate": None,
                    "warrantyTill": None
                }

                if hasattr(asset, 'dateofrequest') and asset.dateofrequest:
                    try:
                        asset_data["dateofrequest"] = asset.dateofrequest.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        asset_data["dateofrequest"] = str(asset.dateofrequest)

                if hasattr(asset, 'purchaseDate') and asset.purchaseDate:
                    try:
                        asset_data["purchaseDate"] = asset.purchaseDate.strftime('%Y-%m-%d')
                    except:
                        asset_data["purchaseDate"] = str(asset.purchaseDate)

                if hasattr(asset, 'warrantyTill') and asset.warrantyTill:
                    try:
                        asset_data["warrantyTill"] = asset.warrantyTill.strftime('%Y-%m-%d')
                    except:
                        asset_data["warrantyTill"] = str(asset.warrantyTill)

                asset_list.append(asset_data)

            except Exception as e:
                print(f"Debug: Error processing individual asset: {str(e)}")
                continue

        return jsonify({
            "status": "success",
            "data": asset_list,
            "page": page,
            "total_pages": (total + limit - 1) // limit if total > 0 else 0,
            "total_assets": total
        }), 200

    except Exception as e:
        print(f"Debug: Exception in get_assets: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500
    

# ====================================
#        USER PROJECT SECTION
# ====================================


#assign project
@user.route('/project', methods=['POST'])
def user_add_project():
    try:
        user, err, status = get_authorized_user(required_section="admin", required_permissions="edit")
        if err:
            return err, status

        if not user.superadmin_panel_id:
            return jsonify({"status": "error", "message": "User is not part of any panel"}), 404

        title = request.form.get('title')
        description = request.form.get('description')
        lastDate = request.form.get('lastDate')
        status_value = request.form.get('status')
        links = request.form.getlist('links') or []
        files = request.form.getlist('files') or []
        emp_ids = request.form.getlist('empIDs')

        if not title or not lastDate:
            return jsonify({
                "status": "error",
                "message": "Title and Last Date are required."
            }), 400

        try:
            lastDate_dt = datetime.fromisoformat(lastDate)
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid date format for 'lastDate'. Use YYYY-MM-DD."
            }), 400

        new_task = TaskManagement(
            superpanelId=user.superadmin_panel_id,
            title=title,
            description=description,
            lastDate=lastDate_dt,
            status=status_value,
            links=links,
            files=files
        )
        db.session.add(new_task)
        db.session.flush()  # Get task ID before commit

        assigned_users = []

        for emp_id in emp_ids:
            assigned_user = User.query.filter_by(empId=emp_id).first()
            if not assigned_user or not assigned_user.panelData:
                continue

            task_user = TaskUser(
                taskPanelId=new_task.id,
                userPanelId=assigned_user.panelData.id,
                user_emp_id=assigned_user.empId,
                user_userName=assigned_user.userName,
                image=assigned_user.profileImage or ""
            )
            db.session.add(task_user)

            socketio.emit(
                'notification',
                {
                    'title': '📌 New Project Assigned',
                    'message': f'You have been assigned a new project: {title}',
                    'taskId': new_task.id,
                    'type': 'task'
                },
                room=assigned_user.empId
            )

            assigned_users.append({
                "emp_id": assigned_user.empId,
                "userName": assigned_user.userName,
                "profileImage": assigned_user.profileImage
            })

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Project created and assigned successfully.",
            "taskId": new_task.id,
            "assigned_to": assigned_users
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/myproject', methods=['GET'])
def get_assigned_projects():
    try:
        user, err, status = get_authorized_user(required_section="admin", required_permissions="view")
        if err:
            return err, status

        if not user.panelData:
            return jsonify({"status": "error", "message": "User panel not found"}), 404

        assigned_tasks = TaskUser.query.filter_by(userPanelId=user.panelData.id).all()

        if not assigned_tasks:
            return jsonify({"status": "success", "projects": []}), 200

        projects = []
        for task_user in assigned_tasks:
            task = TaskManagement.query.get(task_user.taskPanelId)
            if not task:
                continue

            assigned_users = []
            for assigned_user in task.users:
                assigned_users.append({
                    "userPanelId": assigned_user.userPanelId,
                    "empId": assigned_user.user_emp_id,
                    "userName": assigned_user.user_userName,
                    "image": assigned_user.image,
                    "isCompleted": assigned_user.is_completed
                })

            # Get comments for this task
            comments = []
            for comment in task.comments:
                comments.append({
                    "id": comment.id,
                    "userId": comment.userId,
                    "username": comment.username,
                    "comment": comment.comments,
                    "timestamp": comment.timestamp.isoformat() if hasattr(comment, "timestamp") and comment.timestamp else None
                })

            projects.append({
                "taskId": task.id,
                "title": task.title,
                "description": task.description,
                "assignedAt": task.assignedAt.isoformat() if task.assignedAt else None,
                "lastDate": task.lastDate.isoformat() if task.lastDate else None,
                "status": task.status or "ongoing",
                "priority": task.priority,
                "links": task.links or [],
                "files": task.files or [],
                "isCompleted": task_user.is_completed,
                "comments": comments,
                "assignedUsers": assigned_users
            })

        return jsonify({
            "status": "success",
            "projects": projects
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


#assigned project
@user.route('/project', methods=['GET'])
def get_user_tasks_with_chat():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.filter_by(id=userId).first()
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel not found"}), 404

        # Get all tasks assigned to this user
        assigned_tasks = TaskUser.query.options(joinedload(TaskUser.taskmanagement)) \
            .filter_by(user_emp_id=user.empId).all()

        task_list = []

        for assigned in assigned_tasks:
            task = assigned.taskmanagement
            if not task:
                continue

            # Comments (chat) from relationship
            comments = []
            for comment in task.comments:
                comments.append({
                    "id": comment.id,
                    "userId": comment.userId,
                    "username": comment.username,
                    "comment": comment.comments,
                    "timestamp": comment.timestamp.isoformat() if hasattr(comment, 'timestamp') and comment.timestamp else None
                })

            # Assigned users
            assigned_users = []
            for task_user in task.users:
                assigned_users.append({
                    "userPanelId": task_user.userPanelId,
                    "empId": task_user.user_emp_id,
                    "userName": task_user.user_userName,
                    "image": task_user.image,
                    "isCompleted": task_user.is_completed
                })

            task_data = {
                "task_id": task.id,
                "title": task.title,
                "description": task.description,
                "assignedAt": task.assignedAt.isoformat() if task.assignedAt else None,
                "lastDate": task.lastDate.isoformat() if task.lastDate else None,
                "status": task.status or "ongoing",
                "priority": task.priority,
                "links": task.links or [],
                "files": task.files or [],
                "is_completed": assigned.is_completed,
                "chat": comments,
                "assignedUsers": assigned_users
            }

            task_list.append(task_data)

        return jsonify({
            "status": "success",
            "message": "Tasks fetched successfully",
            "data": task_list
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/project/<int:task_id>', methods=['PUT'])
def update_task_status_and_comment(task_id):
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.filter_by(id=userId).first()
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel not found"}), 404

        task = TaskManagement.query.get(task_id)
        if not task:
            return jsonify({"status": "error", "message": "Task not found"}), 404

        if task.status in ["completed", "incomplete"]:
            return jsonify({
                "status": "error",
                "message": f"Task is already marked as '{task.status}' and cannot be updated."
            }), 403

        comment_text = request.form.get('comment', '').strip()
        mark_complete_raw = request.form.get('mark_complete', 'false').lower()
        mark_complete = mark_complete_raw == 'true'

        task_user = TaskUser.query.filter_by(
            taskPanelId=task_id,
            userPanelId=user.panelData.id
        ).first()

        if not task_user:
            return jsonify({
                "status": "error",
                "message": "Task not assigned to this user"
            }), 403

        if comment_text:
            new_comment = TaskComments(
                taskPanelId=task_id,
                taskId=task_id,
                userId=str(user.empId),
                username=user.userName,
                comments=comment_text
            )
            db.session.add(new_comment)

        if mark_complete:
            task_user.is_completed = True

        db.session.flush()

        all_assigned = TaskUser.query.filter_by(taskPanelId=task_id).all()
        all_completed = all(tu.is_completed for tu in all_assigned)

        if all_completed:
            task.status = "completed"
        elif task.lastDate and datetime.utcnow() > task.lastDate:
            task.status = "incomplete"
        else:
            task.status = "ongoing"

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Task updated successfully",
            "task_status": task.status,
            "user_completed": task_user.is_completed
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


# ====================================
#        USER PROMOTION SECTION
# ====================================

@user.route('/promotion', methods=['GET'])
def get_promotion():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "Unauthorized"
            }), 401

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "User not found"
            }), 200

        if not user.panelData:
            return jsonify({
                "status": "error",
                "message": "User panel data not found"
            }), 200

        promotions = UserPromotion.query.filter_by(userpanel=user.panelData.id).order_by(
            UserPromotion.dateofpromotion.desc()
        ).all()

        promotion_data = []
        for promo in promotions:
            promotion_data.append({
                "promotion_id": promo.id,
                "empId": promo.empId,
                "new_designation": promo.new_designation,
                "previous_department": promo.previous_department,
                "new_department": promo.new_department,
                "description": promo.description,
                "dateofpromotion": promo.dateofpromotion.isoformat()
            })

        return jsonify({
            "status": "success",
            "promotions": promotion_data
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/promotion/<int:promotion_id>', methods=['PUT'])
def update_promotion_description(promotion_id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({
                "status": "error",
                "message": "Unauthorized"
            }), 401

        user = User.query.filter_by(id=userID).first()
        if not user:
            return jsonify({
                "status": "error",
                "message": "User not found"
            }), 404

        if not user.panelData:
            return jsonify({
                "status": "error",
                "message": "User panel data not found"
            }), 404

        promotion = UserPromotion.query.filter_by(
            id=promotion_id,
            userpanel=user.panelData.id
        ).first()

        if not promotion:
            return jsonify({
                "status": "error",
                "message": "Promotion record not found"
            }), 404

        data = request.get_json()
        if not data or 'description' not in data:
            return jsonify({
                "status": "error",
                "message": "Description field is required"
            }), 400

        promotion.description = data['description']
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Promotion description updated",
            "promotion_id": promotion.id
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


# ====================================
#        USER JOB SECTION
# ====================================

@user.route('/jobinfo', methods=['POST'])
def add_job_info():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.get(userID)
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel data not found"}), 200

        existing_info = JobInfo.query.filter_by(panelData=user.panelData.id).first()
        if existing_info:
            return jsonify({"status": "error", "message": "Job info already exists"}), 400

        data = request.get_json()
        job_info = JobInfo(
            panelData=user.panelData.id,
            position=data.get('position'),
            jobLevel=data.get('jobLevel'),
            department=data.get('department'),
            location=data.get('location'),
            reporting_manager=data.get('reporting_manager'),
            join_date=datetime.strptime(data['join_date'], '%Y-%m-%d') if data.get('join_date') else None,
            total_time=data.get('total_time'),
            employement_type=data.get('employement_type'),
            probation_period=data.get('probation_period'),
            notice_period=data.get('notice_period'),
            contract_number=data.get('contract_number'),
            contract_type=data.get('contract_type'),
            start_date=datetime.strptime(data['start_date'], '%Y-%m-%d') if data.get('start_date') else None,
            end_date=datetime.strptime(data['end_date'], '%Y-%m-%d') if data.get('end_date') else None,
            working_type=data.get('working_type'),
            shift_time=datetime.strptime(data['shift_time'], '%Y-%m-%d %H:%M:%S') if data.get('shift_time') else None,
            previous_position=data.get('previous_position'),
            position_date=datetime.strptime(data['position_date'], '%Y-%m-%d') if data.get('position_date') else None,
            transfer_location=data.get('transfer_location'),
            reason_for_change=data.get('reason_for_change')
        )

        db.session.add(job_info)
        db.session.commit()

        return jsonify({"status": "success", "message": "Job info added successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Server error", "error": str(e)}), 500


@user.route('/jobinfo', methods=['PUT'])
def update_or_create_job_info():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.get(userID)
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel data not found"}), 404

        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        job_info = JobInfo.query.filter_by(panelData=user.panelData.id).first()

        if not job_info:
            # Create new job info
            job_info = JobInfo(panelData=user.panelData.id)
            db.session.add(job_info)

        # Fields to update
        for field in [
            'position', 'location', 'reporting_manager',
            'total_time', 'employement_type', 'probation_period', 'notice_period',
            'contract_number', 'contract_type', 'working_type', 'previous_position',
            'transfer_location', 'reason_for_change'
        ]:
            if field in data:
                setattr(job_info, field, data[field])

        # Date/time fields
        date_fields = {
            'join_date': '%Y-%m-%d',
            'start_date': '%Y-%m-%d',
            'end_date': '%Y-%m-%d',
            'position_date': '%Y-%m-%d',
            'shift_time': '%Y-%m-%d %H:%M:%S'
        }

        for field, fmt in date_fields.items():
            if field in data:
                try:
                    setattr(job_info, field, datetime.strptime(data[field], fmt))
                except ValueError:
                    return jsonify({"status": "error", "message": f"Invalid date format for {field}, expected {fmt}"}), 400

        db.session.commit()

        return jsonify({"status": "success", "message": "Job info saved successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Server error", "error": str(e)}), 500


@user.route('/jobinfo', methods=['GET'])
def get_job_info():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.get(userID)
        if not user or not user.panelData:
            return jsonify({
                "status": "success",
                "field_filled": False,
                "message": "User or panel data not found",
                "data": None
            }), 200

        job_info = JobInfo.query.filter_by(panelData=user.panelData.id).first()
        if not job_info:
            return jsonify({
                "status": "success",
                "field_filled": False,
                "message": "Job info not found",
                "data": None
            }), 200

        def fmt(date):
            return date.strftime('%Y-%m-%d') if date else None

        def fmt_dt(date):
            return date.strftime('%Y-%m-%d %H:%M:%S') if date else None

        return jsonify({
            "status": "success",
            "field_filled": True,
            "data": {
                "position": job_info.position,
                "jobLevel": job_info.jobLevel,
                "department": job_info.department,
                "location": job_info.location,
                "reporting_manager": job_info.reporting_manager,
                "join_date": fmt(job_info.join_date),
                "total_time": job_info.total_time,
                "employement_type": job_info.employement_type,
                "probation_period": job_info.probation_period,
                "notice_period": job_info.notice_period,
                "contract_number": job_info.contract_number,
                "contract_type": job_info.contract_type,
                "start_date": fmt(job_info.start_date),
                "end_date": fmt(job_info.end_date),
                "working_type": job_info.working_type,
                "shift_time": fmt_dt(job_info.shift_time),
                "previous_position": job_info.previous_position,
                "position_date": fmt(job_info.position_date),
                "transfer_location": job_info.transfer_location,
                "reason_for_change": job_info.reason_for_change
            }
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Server error",
            "error": str(e)
        }), 500


# ====================================
#        USER LOCATION SECTION
# ====================================

@user.route('/location', methods=['GET'])
def get_admin_location_for_user():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({
                "status": "error",
                "message": "Unauthorized access – user token missing"
            }), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.superadminId:
            return jsonify({
                "status": "error",
                "message": "User not found or not associated with any admin"
            }), 200

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin or not superadmin.superadminPanel:
            return jsonify({
                "status": "error",
                "message": "Admin panel not found"
            }), 200

        location = AdminLocation.query.filter_by(superpanel=superadmin.superadminPanel.id).first()
        if not location:
            return jsonify({
                "status": "error",
                "message": "Admin has not set a location yet"
            }), 200

        return jsonify({
            "status": "success",
            "message": "Admin location retrieved successfully",
            "data": {
                "latitude": location.latitude,
                "longitude": location.longitude
            }
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal server error",
            "error": str(e)
        }), 500



# ====================================
#    USER ADDITIONAL DETAILS SECTION 
# ====================================

@user.route('/leavenames', methods=['GET'])   #get all leaves names set by admin for leave section
def get_leave_names_for_user():
    try:
        userId = g.user.get('userID') if g.user else None
        if not userId:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.filter_by(id=userId).first()
        if not user or not user.superadmin_panel_id:
            return jsonify({"status": "error", "message": "User or panel not found"}), 404

        leave_names = AdminLeaveName.query.filter_by(adminLeaveName=user.superadmin_panel_id).all()
        result = [{"id": ln.id, "name": ln.name} for ln in leave_names]

        return jsonify({
            "status": "success",
            "leave_names": result
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500



@user.route('/department/users', methods=['GET'])  #get all users from their department only for project management
def get_users_in_same_department():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.department:
            return jsonify({'status': 'error', 'message': 'User or department not found'}), 200

        search_query = request.args.get('search', '', type=str).strip().lower()
        page = request.args.get('page', 1, type=int)
        per_page = 5

        base_query = User.query.filter_by(
            superadminId=user.superadminId,
            department=user.department
        )

        if search_query:
            base_query = base_query.filter(User.userName.ilike(f"%{search_query}%"))

        paginated_users = base_query.order_by(User.userName.asc()).paginate(page=page, per_page=per_page, error_out=False)

        result = [{
            'id': u.id,
            'empId': u.empId,
            'userName': u.userName,
            'email': u.email,
            'userRole': u.userRole,
        } for u in paginated_users.items]

        return jsonify({
            'status': 'success',
            'department': user.department,
            'search': search_query,
            'pagination': {
                'current_page': page,
                'per_page': per_page,
                'total_users': paginated_users.total,
                'total_pages': paginated_users.pages,
                'has_next': paginated_users.has_next,
                'has_prev': paginated_users.has_prev,
            },
            'users': result
        }), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@user.route('/organization/users', methods=['GET'])  #get list of allusers under his organization for ticket raise and assign
def get_all_users_under_organization():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

        current_user = User.query.filter_by(id=user_id).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        search = request.args.get('search', '', type=str).strip().lower()
        department = request.args.get('department', '', type=str).strip().lower()
        user_role = request.args.get('userRole', '', type=str).strip().lower()
        page = request.args.get('page', 1, type=int)
        per_page = 10

        query = User.query.filter_by(superadminId=current_user.superadminId)

        if search:
            query = query.filter(User.userName.ilike(f"%{search}%"))
        if department:
            query = query.filter(User.department.ilike(department))
        if user_role:
            query = query.filter(User.userRole.ilike(user_role))

        paginated_users = query.order_by(User.userName.asc()).paginate(page=page, per_page=per_page, error_out=False)

        users_list = []
        for user in paginated_users.items:
            users_list.append({
                'id': user.id,
                'empId': user.empId,
                'userName': user.userName,
                'department': user.department,
                'profileImage': user.profileImage,
                'userRole': user.userRole,
            })

        return jsonify({
            'status': 'success',
            'total_users': paginated_users.total,
            'page': page,
            'total_pages': paginated_users.pages,
            'has_next': paginated_users.has_next,
            'has_prev': paginated_users.has_prev,
            'filters': {
                'search': search if search else None,
                'department': department if department else None,
                'userRole': user_role if user_role else None
            },
            'users': users_list
        }), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
