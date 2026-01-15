
**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/hospital-management-system-using-python-django-and-mysql/)
- Affected Version: [<= v1.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Broken Access Control / Privilege Escalation in Hospital Management System
- Affected URL: http://127.0.0.1:8000/Admin/AdminHome, http://127.0.0.1:8000/Pat/PatHome, http://127.0.0.1:8000/Doctor/DocHome, http://127.0.0.1:8000/Admin/DoctorList, http://127.0.0.1:8000/Admin/ManageSpecialization, http://127.0.0.1:8000/Admin/DoctorList, http://127.0.0.1:8000/Admin/RegUsers
- Vulnerable Parameter: /hms/hospital/docappsystem/adminviews.py

**Vulnerable Files:**

- File Name: /hms/hospital/
- Path: /hms/hospital/docappsystem/adminviews.py

**Vulnerability Type**

- Broken Access Control / Authorization Bypass CWE: CWE-284, CWE-639, CWE-862
- Severity Level: 9.1 (CRITICAL)
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

**Root Cause:**

Missing Authorization Checks-
Every admin function only checks authentication, not authorization:

Function: ADMINHOME() (Lines 8-20)
Endpoint: /Admin/AdminHome
Missing Check: No verification of user_type=1

```
# CURRENT VULNERABLE CODE
@login_required(login_url='/')  # Only checks if logged in
def ADMINHOME(request):
    # No check if user is admin
    doctor_count = DoctorReg.objects.all().count
    # ... returns data
```

What's Missing:

```# REQUIRED CHECK
if request.user.user_type != '1':  # Not admin
    return HttpResponseForbidden("Admin access required")

```

**Security Failures:**

- Missing Server-Side Authorization
- The application validates authentication only, not authorization.
- No role or privilege checks are enforced on sensitive endpoints.
- Any authenticated user can access functionality outside their assigned role.
- Users can escalate privileges by manually modifying URL paths.
- User roles (Admin, Doctor, Patient) exist but are not enforced.
- Administrative and sensitive endpoints are directly accessible.

**Impact:**

Successful exploitation of this vulnerability allows any authenticated user, including patients and doctors, to bypass authorization controls and gain unauthorized access to administrative and restricted functionality within the application. An attacker can escalate privileges by directly manipulating URL paths, resulting in administrative access without possessing administrative credentials. This enables unauthorized users to view, modify, and delete sensitive data across the system.

The impact includes unauthorized disclosure of sensitive healthcare information, such as patient personal and medical records, leading to severe confidentiality breaches and potential violations of healthcare data protection regulations. Additionally, attackers can perform unauthorized data modification and deletion, compromising data integrity and system reliability.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**

The Django Hospital Management System fails to implement server-side authorization checks on admin endpoints. Lower-privileged users (Doctor: user_type=2, Patient: user_type=3) can directly access admin functionality by manually changing the URL path from their respective dashboards to admin paths.

Example:
Patient logged in → URL: /Pat/PatHome
Manually change to → URL: /Admin/AdminHome
Result: Patient sees admin dashboard and can perform admin actions

The vulnerability exists following path:
http://127.0.0.1:8000/Admin/AdminHome

**Vulnerable Code Example:**

/hms/hospital/docappsystem/adminviews.py

<img width="639" height="229" alt="image" src="https://github.com/user-attachments/assets/bbe31881-5c0a-401c-82a6-51b16411821f" />

**Step-by-Step Reproduction:**

**First Scenario:**
1. Login as Admin
2. Navigate to: http://127.0.0.1:8000/Admin/AdminHome
3. Copy /Admin/AdminHome path
4. Now login with Patient account on different browser
5. Now replace **"/Pat/PatHome"** to the **/Admin/AdminHome** path
6. Observe that Admin dashboard loads successfully!
7. Verify Admin Access
8. Patient can now see:
- Total Doctor count
- Total Specialization count  
- Total Reg Users count
- Total Add Patients count
- Admin navigation menu
- Patient can perform Delete/Modify functions

**Screenshots**
[Attach screenshots showing:]

<img width="1880" height="765" alt="Screenshot 2026-01-15 at 14 51 25" src="https://github.com/user-attachments/assets/4120a3c9-b569-4dd4-9aa8-cfa3633a1daf" />

<img width="1078" height="415" alt="Screenshot 2026-01-15 at 14 55 03" src="https://github.com/user-attachments/assets/e52f0866-098a-4548-9b82-11482ccc05b5" />

<img width="1085" height="607" alt="Screenshot 2026-01-15 at 14 56 16" src="https://github.com/user-attachments/assets/1be3198b-6c5b-4d42-ae9f-f23795d0f281" />

**Second Scenario:**
1. Login as Admin
2. Navigate to: http://127.0.0.1:8000/Admin/AdminHome
3. Copy /Admin/AdminHome path
4. Now login with Doctor account on different browser
5. Now replace **/Doctor/DocHomePaste** to the **/Admin/AdminHome** path
6. Observe that Admin dashboard loads successfully!
7. Verify Admin Access
8. Patient can now see:
- Total Doctor count
- Total Specialization count  
- Total Reg Users count
- Total Add Patients count
- Admin navigation menu
- Doctor can perform Delete/Modify functions

**Screenshots**
[Attach screenshots showing:]

<img width="1880" height="765" alt="Screenshot 2026-01-15 at 14 51 25" src="https://github.com/user-attachments/assets/ff62954b-9a42-4b5a-9c62-58ea72286c62" />

<img width="1685" height="630" alt="Screenshot 2026-01-15 at 14 52 04" src="https://github.com/user-attachments/assets/c4ba2429-761e-4972-bb6c-53bc26c045b5" />

<img width="1656" height="555" alt="Screenshot 2026-01-15 at 14 53 18" src="https://github.com/user-attachments/assets/06082550-888f-483f-a0b0-53ccd6b6cb50" />

<img width="1413" height="866" alt="Screenshot 2026-01-15 at 14 53 34" src="https://github.com/user-attachments/assets/d6177400-472f-4654-a630-17800bf3b5f5" />

<img width="1689" height="835" alt="Screenshot 2026-01-15 at 13 45 40" src="https://github.com/user-attachments/assets/acf3f15b-908c-4535-a1d7-f1b6d94f2441" />

<img width="1893" height="819" alt="Screenshot 2026-01-15 at 13 46 02" src="https://github.com/user-attachments/assets/136c4b22-1607-475a-bccc-1f6b13f25375" />


**Impact Assessment:**

The Broken Access Control, allowing an attacker to:
- Patients can perform admin functions
- Any user can access any other user's functionality
- Doctors can access patient records they don't treat
- Data integrity compromised (unauthorized deletions/modifications)

**Affected Components:**

- Admin Dashboard functionality
- Manage Specialization
- Doctor List
- Registered Users
- Delete Functions

**Remediation Recommendations:**

**Immediate Fix**

1. Enforce Role-Based Access Control (RBAC)
- Implement centralized role-based authorization checks for all endpoints.
- Ensure that administrative functions are accessible only to users with administrative privileges.
- Do not rely on UI elements or URL structure to enforce access restrictions.

2. Server-Side Authorization Validation
- Do not rely solely on client-side controls. All privilege checks for account creation and role assignment should be validated on the server side.

3. Use Authorization Decorators or Middleware
- Apply authorization decorators (e.g., role-check decorators) to all sensitive views.
- Alternatively, implement middleware to centrally enforce access control rules based on user roles and requested paths.

4. Conduct security code review

# Secure Code Example:
1. Decorator-Based Authorization
```
from django.contrib.auth.decorators import user_passes_test
from django.http import HttpResponseForbidden

def is_admin(user):
    """Check if user is admin (user_type=1)"""
    return user.is_authenticated and user.user_type == '1'

       # Apply to EVERY admin function
@login_required(login_url='/')
@user_passes_test(is_admin, login_url='/unauthorized')
def ADMINHOME(request):
    # Now only accessible to admins
    doctor_count = DoctorReg.objects.all().count
    # ... rest of code
```

2. Manual Authorization Check Inside Function:

```
@login_required(login_url='/')
def ADMINHOME(request):
    # Add authorization check
    if request.user.user_type != '1':
        return HttpResponseForbidden(
            "Unauthorized: Admin access required"
        )
    
    # Rest of function
    doctor_count = DoctorReg.objects.all().count
    # ...
```

**References**

- OWASP Access Control Cheat Sheet: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
