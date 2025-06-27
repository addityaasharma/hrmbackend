@superAdminBP.route('/project', methods=['POST'])
def add_Project():
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return None, jsonify({"status": "error", "message": "No auth token"}), 401

        superadmin = SuperAdmin.query.filter_by(id=userID).first()
        if not superadmin:
            user = User.query.filter_by(id=userID).first()
            if not user or user.userRole.lower() != 'teamlead':
                return None, jsonify({"status": "error", "message": "Unauthorized"}), 403
            
            superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
            if not superadmin:
                return None, jsonify({"status": "error", "message": "No superadmin found"}), 404

        title = request.form.get('title')
        description = request.form.get('description')
        lastDate = request.form.get('lastDate')
        status = request.form.get('status')
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
                "message": "Invalid date format for 'lastDate'. Use YYYY-MM-DD or ISO."
            }), 400

        new_task = TaskManagement(
            superpanelId=superadmin.superadminPanel.id,
            title=title,
            description=description,
            lastDate=lastDate_dt,
            status=status,
            links=links,
            files=files
        )
        db.session.add(new_task)
        db.session.flush()

        assigned_users = []

        for emp_id in emp_ids:
            print(f"Checking emp_id: {emp_id}")
            user = User.query.filter_by(empId=emp_id).first()
            if not user:
                continue
            if user and user.panelData:
                user_panel = user.panelData
                task_user = TaskUser(
                    taskPanelId=new_task.id,
                    userPanelId=user_panel.id,
                    user_emp_id=user.empId,
                    user_userName=getattr(user, 'userName', 'Unknown'),
                    image=getattr(user, 'profileImage', '')
                )
                db.session.add(task_user)

                assigned_users.append({
                    "emp_id": user.empId,
                    "userName": user.userName,
                    "profileImage": user.profileImage
                })

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Project and task assignments added successfully",
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


@superAdminBP.route('/project', methods=['GET'])
def get_all_projects():
    try:
        superadmin, err, status = get_authorized_superadmin()
        if err:
            return err, status

        tasks = TaskManagement.query.options(
            joinedload(TaskManagement.users),
            joinedload(TaskManagement.comments)
        ).filter_by(
            superpanelId=superadmin.superadminPanel.id
        ).order_by(TaskManagement.assignedAt.desc()).all()

        grouped_tasks = {
            "completed": [],
            "ongoing": [],
            "incomplete": []
        }

        for task in tasks:
            assigned_users = []
            all_completed = True
            any_assigned = False

            for user in task.users:
                any_assigned = True
                assigned_users.append({
                    "userPanelId": user.userPanelId,
                    "empId": user.user_emp_id,
                    "userName": user.user_userName,
                    "image": user.image,
                    "isCompleted": user.is_completed
                })
                if not user.is_completed:
                    all_completed = False

            if all_completed and any_assigned:
                task_status = "completed"
            elif not all_completed and task.lastDate and datetime.utcnow() > task.lastDate:
                task_status = "incomplete"
            else:
                task_status = "ongoing"

            comments = [{
                "id": c.id,
                "userId": c.userId,
                "username": c.username,
                "comment": c.comments,
                "timestamp": c.timestamp.isoformat() if hasattr(c, "timestamp") and c.timestamp else None
            } for c in task.comments]

            task_data = {
                "id": task.id,
                "title": task.title,
                "description": task.description,
                "assignedAt": task.assignedAt.isoformat() if task.assignedAt else None,
                "lastDate": task.lastDate.isoformat() if task.lastDate else None,
                "links": task.links,
                "files": task.files,
                "status": task_status,
                "comments": comments,
                "assignedUsers": assigned_users
            }

            grouped_tasks[task_status].append(task_data)

        return jsonify({
            "status": "success",
            "tasks": grouped_tasks
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@superAdminBP.route('/project/<int:task_id>', methods=['DELETE'])
def delete_project(task_id):
    try:
        superadmin, err, status = get_authorized_superadmin()
        if err:
            return err, status

        task = TaskManagement.query.filter_by(
            id=task_id,
            superpanelId=superadmin.superadminPanel.id
        ).first()

        if not task:
            return jsonify({
                "status": "error",
                "message": "Task not found or unauthorized"
            }), 404

        db.session.delete(task)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Project and all associated comments deleted successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@superAdminBP.route('/project/<int:task_id>', methods=['PUT'])
def update_project(task_id):
    try:
        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No auth token"}), 401

        superadmin = SuperAdmin.query.filter_by(id=userID).first()
        if not superadmin:
            user = User.query.filter_by(id=userID).first()
            if not user or user.userRole.lower() != 'teamlead':
                return jsonify({"status": "error", "message": "Unauthorized"}), 403
            superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
            if not superadmin:
                return jsonify({"status": "error", "message": "No superadmin found"}), 404

        task = TaskManagement.query.filter_by(id=task_id, superpanelId=superadmin.superadminPanel.id).first()
        if not task:
            return jsonify({"status": "error", "message": "Task not found"}), 404

        title = request.form.get('title')
        description = request.form.get('description')
        lastDate = request.form.get('lastDate')
        status = request.form.get('status')
        links = request.form.getlist('links') or []
        files = request.form.getlist('files') or []
        emp_ids = request.form.getlist('empIDs')  # Optional for reassignment

        if title:
            task.title = title
        if description:
            task.description = description
        if lastDate:
            try:
                task.lastDate = datetime.fromisoformat(lastDate)
            except ValueError:
                return jsonify({
                    "status": "error",
                    "message": "Invalid date format for 'lastDate'. Use ISO format."
                }), 400
        if status:
            if status.lower() not in ['ongoing', 'completed', 'incomplete']:
                return jsonify({
                    "status": "error",
                    "message": "Invalid status value"
                }), 400
            task.status = status.lower()

        task.links = links
        task.files = files

        if emp_ids:
            TaskUser.query.filter_by(taskPanelId=task_id).delete()
            db.session.flush()

            for emp_id in emp_ids:
                user = User.query.filter_by(empId=emp_id).first()
                if user and user.panelData:
                    task_user = TaskUser(
                        taskPanelId=task.id,
                        userPanelId=user.panelData.id,
                        user_emp_id=user.empId,
                        usersName=getattr(user, 'userName', 'Unknown'),
                        image=getattr(user, 'profileImage', '')
                    )
                    db.session.add(task_user)

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Task updated successfully",
            "taskId": task.id
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@superAdminBP.route('/salary', methods=['GET'])
def get_all_user_admin_data():
    try:
        superadmin, err, status = get_authorized_superadmin(required_section="dashboard", required_permissions="view")
        if err:
            return err, status

        # Get month and year from query params (fallback to current)
        query_month = request.args.get('month', type=int)
        query_year = request.args.get('year', type=int)

        today = datetime.utcnow().date()
        month = query_month if query_month else today.month
        year = query_year if query_year else today.year

        month_start = datetime(year, month, 1).date()
        if month == 12:
            month_end = datetime(year, 12, 31).date()
        else:
            month_end = (datetime(year, month + 1, 1) - timedelta(days=1)).date()

        users = User.query.filter_by(superadminId=superadmin.superId).all()
        user_data_list = []

        for user in users:
            panel_data = user.panelData

            # --- Punch Count ---
            punch_count = 0
            if panel_data:
                punch_count = db.session.query(PunchData).filter(
                    PunchData.panelData == panel_data.id,
                    PunchData.login >= month_start,
                    PunchData.login <= month_end
                ).count()

            # --- Leave Summary ---
            paid_days = 0
            unpaid_days = 0
            leave_count = 0
            if panel_data:
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

            # --- Job Info ---
            job_info = {
                "department": panel_data.userJobInfo[0].department if panel_data and panel_data.userJobInfo else None,
                "designation": panel_data.userJobInfo[0].designation if panel_data and panel_data.userJobInfo else None,
                "joiningDate": panel_data.userJobInfo[0].joiningDate.isoformat() if panel_data and panel_data.userJobInfo and panel_data.userJobInfo[0].joiningDate else None
            }

            # --- Basic Salary ---
            basic_salary = panel_data.userSalaryDetails[0].basic_salary if panel_data and panel_data.userSalaryDetails else None

            user_data_list.append({
                "empId": user.empId,
                "name": user.userName,
                "email": user.email,
                "role": user.userRole,
                "punch_count": punch_count,
                "leave_summary": {
                    "total_leaves": leave_count,
                    "paid_days": paid_days,
                    "unpaid_days": unpaid_days
                },
                "basic_salary": basic_salary,
                "jobInfo": job_info
            })

        # --- Admin-Side Info ---
        admin_panel = superadmin.superadminPanel

        # Bonus Policy Fix
        bonus_policy = [{
            "bonus_name": b.bonus_name,
            "bonus_method": b.bonus_method,
            "amount": b.amount,
            "apply": b.apply,
            "employeement_type": b.employeement_type,
            "department_type": b.department_type
        } for b in admin_panel.adminBonusPolicy]

        # Payroll Policy Fix
        payroll_policy = [{
            "policyname": p.policyname,
            "calculation_method": p.calculation_method,
            "overtimePolicy": p.overtimePolicy,
            "perhour": p.perhour,
            "pfDeduction": p.pfDeduction,
            "salaryHoldCondition": p.salaryHoldCondition,
            "disbursement": p.disbursement.isoformat() if p.disbursement else None,
            "employeementType": p.employeementType,
            "departmentType": p.departmentType
        } for p in admin_panel.adminPayrollPolicy]

        # Leave Policy Fix
        leave_policy = [{
            "leaveName": l.leaveName,
            "leaveType": l.leaveType,
            "probation": l.probation,
            "lapse_policy": l.lapse_policy,
            "calculationType": l.calculationType,
            "day_type": l.day_type,
            "encashment": l.encashment,
            "carryforward": l.carryforward,
            "max_leave_once": l.max_leave_once,
            "max_leave_year": l.max_leave_year,
            "monthly_leave_limit": l.monthly_leave_limit
        } for l in admin_panel.adminLeave]

        return jsonify({
            "status": "success",
            "data": {
                "users": user_data_list,
                "admin": {
                    "bonus_policy": bonus_policy,
                    "payroll_policy": payroll_policy,
                    "leave_policy": leave_policy
                }
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Failed to fetch user-admin data",
            "error": str(e)
        }), 500


@superAdminBP.route('/salary', methods=['GET'])
def get_all_user_admin_data():
    try:
        superadmin, err, status = get_authorized_superadmin(required_section="dashboard", required_permissions="view")
        if err:
            return err, status

        today = datetime.utcnow().date()
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(day=31)
        else:
            month_end = (today.replace(month=today.month + 1, day=1) - timedelta(days=1))

        users = User.query.filter_by(superadminId=superadmin.superId).all()
        user_data_list = []

        for user in users:
            panel_data = user.panelData

            # --- Punch count this month ---
            punch_count = 0
            if panel_data:
                punch_count = db.session.query(PunchData).filter(
                    PunchData.panelData == panel_data.id,
                    PunchData.login >= month_start,
                    PunchData.login <= month_end
                ).count()

            # --- Leave details this month ---
            paid_days = 0
            unpaid_days = 0
            leave_count = 0
            if panel_data:
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

            # --- Job info ---
            job_info = {
                "department": panel_data.userJobInfo[0].department if panel_data and panel_data.userJobInfo else None,
                "designation": panel_data.userJobInfo[0].designation if panel_data and panel_data.userJobInfo else None,
                "joiningDate": panel_data.userJobInfo[0].joiningDate.isoformat() if panel_data and panel_data.userJobInfo and panel_data.userJobInfo[0].joiningDate else None
            }

            # --- Basic Salary ---
            basic_salary = panel_data.userSalaryDetails[0].basic_salary if panel_data and panel_data.userSalaryDetails else None

            user_data_list.append({
                "empId": user.empId,
                "name": user.userName,
                "email": user.email,
                "role": user.userRole, 
                "basic_salary": user.currentSalary,
                "present": punch_count,
                "leave_summary": {
                    "absent": leave_count,
                    "paid_days": paid_days,
                    "unpaid_days": unpaid_days
                },
                "jobInfo": job_info
            })

        # --- Admin-Side Info ---
        admin_panel = superadmin.superadminPanel

        bonus_policy = [{
            "bonus_name": b.bonus_name,
            "amount": b.amount,
            "bonus_method": b.bonus_method,
            "apply": b.apply,
            "employeement_type": b.employeement_type,
            "department_type": b.department_type
        } for b in admin_panel.adminBonusPolicy]

        payroll_policy = [{
            "policyname": p.policyname,
            "calculation_method": p.calculation_method,
            "overtimePolicy": p.overtimePolicy,
            "perhour": p.perhour,
            "pfDeduction": p.pfDeduction,
            "salaryHoldCondition": p.salaryHoldCondition,
            "disbursement": p.disbursement.isoformat() if p.disbursement else None,
            "employeementType": p.employeementType,
            "departmentType": p.departmentType
        } for p in admin_panel.adminPayrollPolicy]

        leave_policy = [{
            "leaveName": l.leaveName,
            "leaveType": l.leaveType,
            "probation": l.probation,
            "lapse_policy": l.lapse_policy,
            "calculationType": l.calculationType,
            "day_type": l.day_type,
            "encashment": l.encashment,
            "carryforward": l.carryforward,
            "max_leave_once": l.max_leave_once,
            "max_leave_year": l.max_leave_year,
            "monthly_leave_limit": l.monthly_leave_limit
        } for l in admin_panel.adminLeave]

        shift = ShiftTimeManagement.query.filter_by(
            superpanel = admin_panel.id,
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
                        if(
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
                "users": user_data_list,
                "admin": {
                    "bonus_policy": bonus_policy,
                    "payroll_policy": payroll_policy,
                    "leave_policy": leave_policy
                },
                "shift_policy" : {
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
            "message": "Failed to fetch user-admin data",
            "error": str(e)
        }), 500
    

@superAdminBP.route('/message', methods=['POST'])
def admin_send_message():
    try:
        superadmin, err, status = get_authorized_superadmin(required_section="chat", required_permissions="edit")
        if err:
            return err, status

        receiver_id = request.form.get('recieverID')
        department_name = request.form.get('department')  # optional
        message_text = request.form.get('message')
        uploaded_file = request.files.get('file')

        if not receiver_id and not department_name:
            return jsonify({"status": "error", "message": "Receiver ID or Department is required"}), 400
        if not message_text and not uploaded_file:
            return jsonify({"status": "error", "message": "Message or file required"}), 400

        # File handling
        file_url = None
        message_type = 'text'

        if uploaded_file:
            filename = secure_filename(uploaded_file.filename)
            mimetype = uploaded_file.mimetype
            folder_path = os.path.join('static', 'uploads', 'chat_files')
            os.makedirs(folder_path, exist_ok=True)
            filepath = os.path.join(folder_path, filename)
            uploaded_file.save(filepath)
            file_url = filepath

            if mimetype.startswith("image/"):
                message_type = 'image' if not message_text else 'text_image'
            else:
                message_type = 'file' if not message_text else 'text_file'

        # Determine recipients
        if department_name:
            users = User.query.filter_by(superadminId=superadmin.superId, department=department_name).all()
            if not users:
                return jsonify({"status": "error", "message": "No users found in this department"}), 404
        else:
            user = User.query.filter_by(id=receiver_id).first()
            if not user:
                return jsonify({"status": "error", "message": "User not found"}), 404
            users = [user]

        # Send to all selected users
        for user in users:
            message = UserChat(
                panelData=user.panelData.id,
                senderID=superadmin.superId,
                recieverID=user.empId,
                message=message_text if message_text else None,
                image_url=file_url,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(message)
            db.session.flush()  # get created_at

            socketio.emit('receive_message', {
                'senderID': superadmin.superId,
                'recieverID': user.empId,
                'message': message_text,
                'file_url': file_url,
                'message_type': message_type,
                'timestamp': str(message.created_at)
            }, room=user.id)  # emit to individual user room

        db.session.commit()

        socketio.emit('message_sent', {'status': 'success'}, room=str(superadmin.superId))
        return jsonify({"status": "success", "message": "Message sent successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@superAdminBP.route('/all-users/<int:id>', methods=['GET'])
def all_users_or_one(id):
    try:
        superadmin, err, status = get_authorized_superadmin(required_section="employee", required_permissions="view")
        if err:
            return err, status

        superadminpanel = superadmin.superadminPanel
        if not superadminpanel:
            return jsonify({'status': 'error', 'message': 'No admin panel found with this user'}), 400

        all_users_query = superadminpanel.allUsers

        def get_user_access_list(user):
            return [{
                'section': access.section,
                'permission': access.permission,
                'allowed': access.allowed
            } for access in user.access_permissions]

        if id != 0:
            single_user = next((u for u in all_users_query if u.id == id), None)
            if not single_user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 200

            user_promotions = []
            if single_user.panelData:
                user_promotions = [{
                    "id": promo.id,
                    "empId": promo.empId,
                    "new_designation": promo.new_designation,
                    "previous_department": promo.previous_department,
                    "new_department": promo.new_department,
                    "description": promo.description,
                    "dateofpromotion": promo.dateofpromotion.strftime("%Y-%m-%d") if promo.dateofpromotion else None
                } for promo in single_user.panelData.UserPromotion]

            user_data = {
                'id': single_user.id,
                'profileImage': single_user.profileImage,
                'superadminId': single_user.superadminId,
                'userName': single_user.userName,
                'empId': single_user.empId,
                'email': single_user.email,
                'gender': single_user.gender,
                'number': single_user.number,
                'currentAddress': single_user.currentAddress,
                'permanentAddress': single_user.permanentAddress,
                'postal': single_user.postal,
                'city': single_user.city,
                'state': single_user.state,
                'country': single_user.country,
                'birthday': single_user.birthday.strftime("%Y-%m-%d"),
                'nationality': single_user.nationality,
                'panNumber': single_user.panNumber,
                'adharNumber': single_user.adharNumber,
                'uanNumber': single_user.uanNumber,
                'department': single_user.department,
                'onBoardingStatus': single_user.onBoardingStatus,
                'sourceOfHire': single_user.sourceOfHire,
                'currentSalary': single_user.currentSalary,
                'joiningDate': single_user.joiningDate.strftime("%Y-%m-%d") if single_user.joiningDate else None,
                'schoolName': single_user.schoolName,
                'degree': single_user.degree,
                'fieldOfStudy': single_user.fieldOfStudy,
                'dateOfCompletion': single_user.dateOfCompletion.strftime("%Y-%m-%d") if single_user.dateOfCompletion else None,
                'skills': single_user.skills,
                'shift': single_user.shift,
                'occupation': single_user.occupation,
                'company': single_user.company,
                'experience': single_user.experience,
                'duration': single_user.duration,
                'userRole': single_user.userRole,
                'managerId': single_user.managerId,
                'superadmin_panel_id': single_user.superadmin_panel_id,
                'created_at': single_user.created_at.strftime("%Y-%m-%d %H:%M:%S") if single_user.created_at else None,
                'access': get_user_access_list(single_user),
                'promotions': user_promotions
            }

            return jsonify({'status': 'success', 'user': user_data}), 200

        department = request.args.get('department')
        if department and department.lower() != 'all':
            all_users_query = [user for user in all_users_query if user.department and user.department.lower() == department.lower()]

        search_query = request.args.get('query')
        if search_query:
            all_users_query = [user for user in all_users_query if search_query.lower() in user.userName.lower()]

        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        start = (page - 1) * limit
        end = start + limit
        total_users = len(all_users_query)
        paginated_users = all_users_query[start:end]

        user_list = [
            {
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
                'birthday': user.birthday.strftime("%Y-%m-%d") if user.birthday else None,
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
                'created_at': user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else None,
                'access': get_user_access_list(user)
            }
            for user in paginated_users
        ]

        # total_users = len(all_users_query)
        male_count = sum(1 for user in all_users_query if user.gender and user.gender.lower() == "male")
        female_count = sum(1 for user in all_users_query if user.gender and user.gender.lower() == "female")

        return jsonify({
            'status': 'success',
            'page': page,
            'limit': limit,
            'total_users': total_users,
            'total_pages': (total_users + limit - 1) // limit,
            'users': user_list,
            'males': male_count,
            'females': female_count
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Internal Server Error', 'error': str(e)}), 500
    


@superAdminBP.route('/messagedepartment', methods=['POST'])
def admin_sendgroup_message():
    try:
        superadmin, err, status = get_authorized_superadmin(required_section="chat", required_permissions="edit")
        if err:
            return err, status

        receiver_id = request.form.get('recieverID')
        department_name = request.form.get('department')  # optional
        message_text = request.form.get('message')
        uploaded_file = request.files.get('file')

        if not receiver_id and not department_name:
            return jsonify({"status": "error", "message": "Receiver ID or Department is required"}), 400
        if not message_text and not uploaded_file:
            return jsonify({"status": "error", "message": "Message or file required"}), 400

        file_url = None
        message_type = 'text'

        if uploaded_file:
            filename = secure_filename(uploaded_file.filename)
            mimetype = uploaded_file.mimetype
            folder_path = os.path.join('static', 'uploads', 'chat_files')
            os.makedirs(folder_path, exist_ok=True)
            filepath = os.path.join(folder_path, filename)
            uploaded_file.save(filepath)
            file_url = filepath

            if mimetype.startswith("image/"):
                message_type = 'image' if not message_text else 'text_image'
            else:
                message_type = 'file' if not message_text else 'text_file'

        if department_name:
            users = User.query.filter_by(superadminId=superadmin.superId, department=department_name).all()
            if not users:
                return jsonify({"status": "error", "message": "No users found in this department"}), 404
        else:
            user = User.query.filter_by(id=receiver_id).first()
            if not user:
                return jsonify({"status": "error", "message": "User not found"}), 404
            users = [user]

        for user in users:
            message = UserChat(
                panelData=user.panelData.id,
                senderID=superadmin.superId,
                recieverID=user.empId,
                message=message_text if message_text else None,
                image_url=file_url,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(message)
            db.session.flush()  # get created_at

            socketio.emit('receive_message', {
                'senderID': superadmin.superId,
                'recieverID': user.empId,
                'message': message_text,
                'file_url': file_url,
                'message_type': message_type,
                'timestamp': str(message.created_at)
            }, room=user.id)  # emit to individual user room

        db.session.commit()

        socketio.emit('message_sent', {'status': 'success'}, room=str(superadmin.superId))
        return jsonify({"status": "success", "message": "Message sent successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


#important
@superAdminBP.route('/announcement', methods=['GET'])
def get_announcement():
    try:
        superadmin, err, status = get_authorized_superadmin(
            required_section="policy",
            required_permissions="view"
        )
        if err:
            return err, status

        userID = g.user.get('userID') if g.user else None
        if not userID:
            return jsonify({"status": "error", "message": "No user token found"}), 401

        allAnnouncement = superadmin.superadminPanel.adminAnnouncement

        filtered_announcements = sorted(
            [ann for ann in allAnnouncement if ann.is_published and (not ann.scheduled_time or ann.scheduled_time <= datetime.utcnow())],
            key=lambda x: x.created_at,
            reverse=True
        )

        result = []
        for ann in filtered_announcements:
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
                "created_at": ann.created_at.isoformat(),
                "scheduled_time": ann.scheduled_time.isoformat() if ann.scheduled_time else None,
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
                    ]
                } if ann.poll_question else None
            })

        return jsonify({
            "status": "success",
            "message": "Fetched published announcements",
            "data": result
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Internal Server Error",
            "error": str(e)
        }), 500


@user.route('/tickets', methods=['GET'])
def get_assigned_tickets_to_user():
    try:
        user_id = g.user.get('userID') if g.user else None
        if not user_id:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        user = User.query.filter_by(id=user_id).first()
        if not user or not user.panelData:
            return jsonify({"status": "error", "message": "User or panel data not found"}), 404

        emp_id = user.empId
        department = user.panelData.department  # assuming panelData has `department`

        # Fetch tickets assigned to this employee or to their department
        tickets = UserTicket.query.filter(
            or_(
                UserTicket.assigned_to_empId == emp_id,
                UserTicket.assigned_to_department == department
            )
        ).order_by(UserTicket.date.desc()).all()

        ticket_list = []
        for ticket in tickets:
            assignment = TicketAssignmentLog.query.filter(
                and_(
                    TicketAssignmentLog.ticket_id == ticket.id,
                    or_(
                        TicketAssignmentLog.assigned_to_empId == emp_id,
                        TicketAssignmentLog.assigned_to_department == department
                    )
                )
            ).order_by(TicketAssignmentLog.assigned_at.desc()).first()

            ticket_list.append({
                "ticket_id": ticket.id,
                "topic": ticket.topic,
                "problem": ticket.problem,
                "priority": ticket.priority,
                "status": ticket.status,
                "department": ticket.department,
                "document": ticket.document,
                "date": ticket.date.isoformat() if ticket.date else None,
                "assigned_by": assignment.assigned_by_empId if assignment else None,
                "assigned_at": assignment.assigned_at.isoformat() if assignment else None
            })

        return jsonify({
            "status": "success",
            "message": "Assigned tickets fetched successfully",
            "data": ticket_list
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal server error",
            "error": str(e)
        }), 500
    

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

        max_early = shift.MaxEarly
        grace_time = shift.GraceTime
        max_late = shift.MaxLateEntry

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
    
@user.route('/punchin', methods=['PUT'])
def punch_out_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        required_fields = ['logout', 'location', 'totalHour']
        if not all(field in data for field in required_fields):
            return jsonify({"status": "error", "message": "Missing fields (logout, location, totalHour)"}), 400

        logout_time = datetime.fromisoformat(data['logout'].replace('Z', '+00:00'))

        # Convert totalHour string to time object
        try:
            h, m, s = map(int, data['totalHour'].strip().split(':'))
            total_hour_time = time(hour=h, minute=m, second=s)
        except:
            return jsonify({"status": "error", "message": "Invalid totalHour format (HH:MM:SS expected)"}), 400

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

        if login_time < grace_time:
            login_status = "ontime"
        elif login_time <= max_late:
            login_status = "late"
        else:
            login_status = "halfday"  # Late beyond limit

        if logout_time < half_day_threshold:
            logout_status = "halfday"
        elif logout_time < shift_end:
            logout_status = "early_leave"
        else:
            logout_status = "fullday"

        if login_status == "halfday" or logout_status == "halfday":
            final_status = "halfday"
        elif logout_status == "early_leave":
            final_status = "early_leave"
        elif login_status == "late":
            final_status = "late"
        else:
            final_status = "fullday"

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

        superadmin = SuperAdmin.query.filter_by(superId=user.superadminId).first()
        if not superadmin:
            return jsonify({"status": "error", "message": "Leave policy not set by admin"}), 409

        # FIX: Check if adminLeave list exists and is not empty
        if not hasattr(superadmin.superadminPanel, 'adminLeave') or not superadmin.superadminPanel.adminLeave:
            return jsonify({'status': "error", "message": "Admin has not configured any leave policies"}), 404
        
        adminLeaveDetails = superadmin.superadminPanel.adminLeave[0]
        print(adminLeaveDetails)

        # Date parsing
        leaveStart = datetime.strptime(data['leavefrom'], "%Y-%m-%d").date()
        leaveEnd = datetime.strptime(data['leaveto'], "%Y-%m-%d").date()
        totalDays = (leaveEnd - leaveStart).days + 1

        today = datetime.utcnow().date()
        currentMonth = today.month
        currentYear = today.year
        unpaidDays = 0

        # -------- Condition 1: Probation --------
        if adminLeaveDetails.probation:
                if not user.duration:
                    return jsonify({"status": "error", "message": "User resignation date not set"}), 400
                if (user.duration - today).days <= 30:
                    return jsonify({"status": "error", "message": "You can't apply for leave within 1 month of resignation"}), 403

        # -------- Condition 2: Lapse Policy --------
        previousYearLeaves = 0
        if not adminLeaveDetails.lapse_policy:
            previousYearLeaves = db.session.query(func.sum(UserLeave.days)).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                UserLeave.from_date.between(f'{currentYear - 1}-01-01', f'{currentYear - 1}-12-31')
            ).scalar() or 0

        # -------- Condition 3: Calculation Type --------
        calc_type = adminLeaveDetails.calculationType
        start_range, end_range = None, None

        if calc_type == 'monthly':
            start_range = today.replace(day=1)
            if currentMonth == 12:
                end_range = today.replace(day=31)
            else:
                end_range = (today.replace(month=currentMonth + 1, day=1) - timedelta(days=1))

            prev_start = (today.replace(day=1) - timedelta(days=1)).replace(day=1)
            prev_end = prev_start.replace(day=28) + timedelta(days=4)
            prev_end = prev_end - timedelta(days=prev_end.day)

        elif calc_type == 'quarterly':
            start_month = 1 + 3 * ((currentMonth - 1) // 3)
            end_month = start_month + 2
            start_range = datetime(currentYear, start_month, 1).date()
            if end_month == 12:
                end_range = datetime(currentYear, 12, 31).date()
            else:
                end_range = (datetime(currentYear, end_month + 1, 1) - timedelta(days=1)).date()

            prev_start_month = start_month - 3 if start_month > 3 else 10
            prev_year = currentYear if start_month > 3 else currentYear - 1
            prev_start = datetime(prev_year, prev_start_month, 1).date()
            prev_end = (datetime(prev_year, prev_start_month + 3, 1) - timedelta(days=1)) if prev_start_month < 10 else datetime(prev_year, 12, 31).date()

        elif calc_type == 'yearly':
            start_range = datetime(currentYear, 1, 1).date()
            end_range = datetime(currentYear, 12, 31).date()
            prev_start = datetime(currentYear - 1, 1, 1).date()
            prev_end = datetime(currentYear - 1, 12, 31).date()

        # -------- Carryforward Logic --------
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

            unused = max(prev_allowance - prev_taken, 0)
            carried_forward = unused

        # -------- Leave Taken in Current Cycle --------
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

        # -------- NEW CONDITION: Monthly Leave Limit with Carryover --------
        if hasattr(adminLeaveDetails, 'monthly_leave_limit') and adminLeaveDetails.monthly_leave_limit:
            monthly_limit = adminLeaveDetails.monthly_leave_limit  # e.g., 2 leaves per month
            
            # Calculate current month range based on leave start date, not today's date
            leave_month = leaveStart.month
            leave_year = leaveStart.year
            
            current_month_start = datetime(leave_year, leave_month, 1).date()
            if leave_month == 12:
                current_month_end = datetime(leave_year, 12, 31).date()
            else:
                current_month_end = (datetime(leave_year, leave_month + 1, 1) - timedelta(days=1)).date()
            
            # Calculate previous month range
            if leave_month == 1:
                prev_month_start = datetime(leave_year - 1, 12, 1).date()
                prev_month_end = datetime(leave_year - 1, 12, 31).date()
            else:
                prev_month_start = datetime(leave_year, leave_month - 1, 1).date()
                if leave_month - 1 == 2:  # February
                    prev_month_end = datetime(leave_year, leave_month - 1, 28).date()
                    if leave_year % 4 == 0 and (leave_year % 100 != 0 or leave_year % 400 == 0):
                        prev_month_end = datetime(leave_year, leave_month - 1, 29).date()
                else:
                    prev_month_end = (datetime(leave_year, leave_month, 1) - timedelta(days=1)).date()
            
            # Get current month PAID leaves taken (approved leaves only)
            current_month_leaves = db.session.query(UserLeave.days, UserLeave.unpaidDays).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                and_(
                    UserLeave.leavefrom >= current_month_start,
                    UserLeave.leavefrom <= current_month_end
                )
            ).all()
            
            current_month_paid_taken = 0
            for leave_days, unpaid_days in current_month_leaves:
                paid_days = leave_days - (unpaid_days or 0)
                current_month_paid_taken += paid_days
            
            # Get previous month leaves taken
            prev_month_taken = db.session.query(func.sum(UserLeave.days)).filter(
                UserLeave.empId == data['empId'],
                UserLeave.status == 'approved',
                and_(
                    UserLeave.leavefrom >= prev_month_start,
                    UserLeave.leavefrom <= prev_month_end
                )
            ).scalar() or 0
            
            # Calculate available monthly leaves with carryover
            prev_month_unused = max(monthly_limit - prev_month_taken, 0)
            total_monthly_available = monthly_limit + prev_month_unused
            
            # Debug prints
            print(f"Monthly Limit Debug:")
            print(f"Monthly limit: {monthly_limit}")
            print(f"Current month PAID taken: {current_month_paid_taken}")
            print(f"Previous month taken: {prev_month_taken}")
            print(f"Previous month unused: {prev_month_unused}")
            print(f"Total monthly available: {total_monthly_available}")
            print(f"Current request days: {totalDays}")
            
            # Calculate monthly unpaid days
            if current_month_paid_taken >= total_monthly_available:
                # User has already exhausted monthly limit - ALL current leave days are unpaid
                monthly_unpaid = totalDays
                print(f"Case 1: All days unpaid = {monthly_unpaid}")
            elif current_month_paid_taken + totalDays > total_monthly_available:
                # User will exceed monthly limit with this request
                monthly_unpaid = (current_month_paid_taken + totalDays) - total_monthly_available
                print(f"Case 2: Partial unpaid = {monthly_unpaid}")
            else:
                # User is within monthly limit
                monthly_unpaid = 0
                print(f"Case 3: No unpaid days = {monthly_unpaid}")
            
            unpaidDays = max(unpaidDays, monthly_unpaid)
            print(f"Final unpaid days: {unpaidDays}")

        # -------- Condition 4: Max Leave in Year --------
        yearlyLeaveTaken = db.session.query(func.sum(UserLeave.days)).filter(
            UserLeave.empId == user.empId,
            UserLeave.status == 'approved',
            extract('year', UserLeave.leavefrom) == currentYear
        ).scalar() or 0

        if yearlyLeaveTaken + totalDays > adminLeaveDetails.max_leave_year:
            yearly_unpaid = (yearlyLeaveTaken + totalDays) - adminLeaveDetails.max_leave_year
            unpaidDays = max(unpaidDays, yearly_unpaid)

        # -------- Save User Leave Request --------
        newLeave = UserLeave(
            panelData=user.panelData.id,
            empId=data['empId'],
            leavetype=data['leavetype'],
            leavefrom=leaveStart,
            leaveto=leaveEnd,
            reason=data['reason'],
            name=user.userName,
            email=user.email,
            days=totalDays,
            status='pending',
            unpaidDays=max(unpaidDays, 0),
        )

        db.session.add(newLeave)
        db.session.commit()

        return jsonify({"status": "success", "message": "Leave Sent Successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Internal Server Error", "error": str(e)}), 500
