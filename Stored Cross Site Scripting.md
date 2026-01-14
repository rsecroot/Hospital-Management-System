
**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/hospital-management-system-using-python-django-and-mysql/)
- Affected Version: [<= v1.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Stored Cross-Site Scripting (XSS) via Unrestricted SVG File Upload in Hospital Management System
- Affected URL: http://127.0.0.1:8000/Admin/ViewDoctorDetails/6, http://127.0.0.1:8000/Profile, http://127.0.0.1:8000/docsignup/, http://127.0.0.1:8000/PatientRegsitratios
- Vulnerable Parameter:  /hms/hospital/docappsystem/adminviews.py, /hms/hospital/docappsystem/docviews.py,/hms/hospital/docappsystem/userviews.py - Profile Pic

**Vulnerable Files:**

- File Name: /hms/hospital/
- Path: /hms/hospital/docappsystem/adminviews.py, /hms/hospital/docappsystem/docviews.py,/hms/hospital/docappsystem/userviews.py

**Vulnerability Type**

- Stored Cross-Site Scripting CWE: CWE-79, CWE-434, CWE-80, CWE-601
- Severity Level: 8.7 (HIGH)

**Root Cause:**

The vulnerability exists due to the following security deficiencies in the file upload implementation:

1. **Lack of File Type Validation:**
File: docviews.py, Function: DOCSIGNUP() (Lines 8-55), Endpoint: /docsignup or /doctor/signup
```def DOCSIGNUP(request):  # No @login_required decorator
    if request.method == "POST":
        pic = request.FILES.get('pic')  # No validation
        # ... other fields ...
        
        user = CustomUser(
            # ... other fields ...
            profile_pic = pic,  # Directly saved
        )
        user.save()
```

2. **File: userviews.py, Function: PATIENTREGISTRATION() (Lines 14-52), Endpoint: /patreg or /patient/registration**
```def PATIENTREGISTRATION(request):  # No @login_required decorator
    if request.method == "POST":
        pic = request.FILES.get('pic')  # No validation
        # ... other fields ...
        
        user = CustomUser(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            user_type=3,
            profile_pic = pic,  # Directly saved
        )
        user.save()
```
**Security Failures:**

- No file extension validation (accepts .svg, .html, .js, any extension)
- No MIME type verification
- No content sanitization or inspection
- No use of Django's FileExtensionValidator
- No verification that uploaded file is actually an image
- Files served with original MIME type (image/svg+xml), allowing script execution

**Impact:**

Hospital Management System Django application accepts file uploads without validation. Missing FileExtensionValidator and content verification. Allows SVG files with embedded JavaScript to be stored and rendered.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**

A stored cross-site scripting (XSS) vulnerability exists in the profile image upload functionality of the application. An attacker can upload a malicious file containing JavaScript payloads while registering as a doctor or patient. The uploaded file is later rendered without proper sanitization in administrative interfaces, causing arbitrary JavaScript execution in the context of privileged users such as administrators.

The vulnerability exists in following locations:
http://127.0.0.1:8000/Admin/ViewDoctorDetails/6
http://127.0.0.1:8000/Profile
http://127.0.0.1:8000/docsignup/
http://127.0.0.1:8000/PatientRegsitratios

The application accepts SVG files without content inspection or sanitization. When these files are rendered in the browser (either by viewing user profiles or opening images in new tabs), the embedded JavaScript executes in the security context of any user viewing the content, including other administrators.

Key Vulnerability Aspects:

- Unauthenticated Access: No login required to upload malicious files
- Multiple Entry Points: Doctor registration, Patient registration
- No File Validation: Accepts any file type (SVG, HTML, executable content)
- Admin Trigger Point: XSS executes when admin views registered user lists
- Persistent Storage: Malicious files stored permanently in database

**Vulnerable Code Example:**

/hms/hospital/docappsystem/adminviews.py
/hms/hospital/docappsystem/docviews.py
/hms/hospital/docappsystem/userviews.py

<img width="905" height="827" alt="Screenshot 2026-01-14 at 17 03 39" src="https://github.com/user-attachments/assets/e5a21677-42f7-4939-9cb0-7b56280aa2b5" />

<img width="719" height="620" alt="Screenshot 2026-01-14 at 17 04 13" src="https://github.com/user-attachments/assets/9daedd83-c05c-4e3d-bbcd-b0f594cf96a4" />

**Step-by-Step Reproduction:**
### **Trigger XSS as Admin**

**First Scenario:**
1. Login as Admin
2. Navigate to: http://127.0.0.1:8000/Profile
3. Click "Browse..." under "Upload Profile Pic"
4. Select: malicious.svg
5. Click "Update"
6. File uploaded to: /malicious.svg and triggerd as XSS attack.

<img width="1399" height="861" alt="Screenshot 2026-01-14 at 13 53 14" src="https://github.com/user-attachments/assets/5a8cb08f-ec98-49ba-bff4-5473d9df523b" />

<img width="1855" height="683" alt="Screenshot 2026-01-14 at 13 55 30" src="https://github.com/user-attachments/assets/7fe89d93-22a5-45e4-ac83-955e8e3eba0a" />

<img width="1053" height="796" alt="Screenshot 2026-01-14 at 13 55 39" src="https://github.com/user-attachments/assets/be03e464-95aa-4363-b858-2ae0a243dd78" />


**Second Scenario:**
1. Login as Doctor
2. Navigate to: http://127.0.0.1:8000/Profie
3. Click "Browse..." under "Upload Profile Pic"
4. Right Click and open image in new tab on Profile Pic
5. Triggerd as XSS attack.

<img width="1493" height="873" alt="Screenshot 2026-01-14 at 14 08 27" src="https://github.com/user-attachments/assets/f82e0be1-df01-4968-9d8b-ab37018b70b2" />

<img width="1856" height="721" alt="Screenshot 2026-01-14 at 14 08 41" src="https://github.com/user-attachments/assets/fe477fb4-2ff1-4c29-8b72-04db0b1c5116" />

<img width="1146" height="803" alt="Screenshot 2026-01-14 at 14 08 48" src="https://github.com/user-attachments/assets/f9f059fb-a192-4fb1-b77b-86a95c83b110" />

**Third Scenario:**
1. Login as Admin
2. Navigate to "Doctor lists"
3. View Registered doctor list and click on view profile
4. Right Click and open image in new tab on Profile Pic
5. Triggerd as XSS attack.

<img width="1820" height="885" alt="Screenshot 2026-01-14 at 14 09 38" src="https://github.com/user-attachments/assets/45d4e581-0f6f-4af1-932d-c3de1eefb876" />

<img width="1654" height="752" alt="Screenshot 2026-01-14 at 14 10 25" src="https://github.com/user-attachments/assets/8a25c378-48ca-4299-a15a-147398e702dd" />

<img width="1309" height="784" alt="Screenshot 2026-01-14 at 14 10 37" src="https://github.com/user-attachments/assets/3cbfbb6b-9628-4633-bdf8-e087fe96e658" />

**Fourth Scenario:**
1. Login as User/Patient
2. Navigate to: http://127.0.0.1:8000/Profie
3. Click "Browse..." under "Upload Profile Pic"
4. Right Click and open image in new tab on Profile Pic
5. Triggerd as XSS attack.

<img width="1312" height="772" alt="Screenshot 2026-01-14 at 14 11 41" src="https://github.com/user-attachments/assets/e845f683-b446-43f9-8424-4b6e9112097b" />

<img width="1843" height="468" alt="Screenshot 2026-01-14 at 14 12 10" src="https://github.com/user-attachments/assets/a91a01f3-4eec-4735-aa1d-ff45e394269e" />

<img width="1331" height="891" alt="Screenshot 2026-01-14 at 14 12 17" src="https://github.com/user-attachments/assets/2047d1f6-f7d6-4a3b-a855-2360a604ca9b" />

**Fifth Scenario:**
1. Register as Doctor and User/Patient
2. Navigate to: http://127.0.0.1:8000/docsignup/  and http://127.0.0.1:8000/PatientRegsitratios
3. Click "Browse..." under "Upload Profile Pic" and click on register 
4. Now login as Doctor or patient profile and click on image and it will trigger an XSS attack
5. Also login as Admin profile and navigate to doctor list and view profile
6. Right Click and open image in new tab on Profile Pic
7. Triggerd as XSS attack.

<img width="1276" height="1176" alt="Screenshot 2026-01-14 at 17 21 14" src="https://github.com/user-attachments/assets/c6ff6213-a909-4100-98b5-64c91508e922" />

<img width="1802" height="952" alt="Screenshot 2026-01-14 at 17 22 14" src="https://github.com/user-attachments/assets/660040dd-af73-41d0-b2d4-2b59af939f81" />

<img width="1674" height="698" alt="Screenshot 2026-01-14 at 17 22 57" src="https://github.com/user-attachments/assets/f31c3830-b93b-420e-9185-c8ce5de1cf56" />

<img width="946" height="751" alt="Screenshot 2026-01-14 at 17 23 06" src="https://github.com/user-attachments/assets/ba184379-7616-462d-9d48-fbf0046756cb" />


**Impact Assessment:**

A critical security vulnerability exists in the application’s file upload and profile management functionality, allowing stored cross-site scripting (XSS) attacks across multiple user roles, including administrators, doctors, and patients. The application permits the upload of malicious files (e.g., profile images) that are stored server-side and rendered without proper validation or sanitization.

This flaw can be exploited through several vectors, including public registration workflows as well as authenticated profile update features. Malicious payloads are executed when affected profiles or user listings are viewed, including within administrative interfaces, without requiring any user interaction.

The presence of multiple exploitation paths significantly increases risk, as the vulnerability is not confined to a single feature or role, but represents a system-wide input validation and output handling failure. Immediate remediation is required to prevent account takeover, data breaches, regulatory violations, and reputational damage.

**Attack Chain**

- An unauthenticated attacker registers a new doctor or patient account via the public homepage.
- During registration, the attacker uploads a malicious file containing a stored XSS payload.
- The payload is stored on the server and associated with the user profile.
- An administrator accesses the doctor management interface.
- The stored XSS payload executes in the administrator’s browser.

**Affected Components:**

- Admin Profile Picture Upload Functionality
- Admin Doctor list Functionality
- Doctor List View (Admin Panel)
- Patient Registration (Public Access)
- Patient Registration (Public Access)
- Registered Users View (Admin Panel)
- File Storage and Serving
- File Rendering - Admin/SubAdmin Page (XSS TRIGGER POINT)

**Remediation Recommendations:**

**Immediate Fix**

1. Disallow Dangerous File Types
- Block uploads of executable formats such as:.svg, .html, .htm, .xml
- Use a strict allowlist (e.g., .jpg, .png, .pdf).

2. Enforce Proper Content-Type Handling
- Validate file content using server-side MIME type checks.
- Do not rely solely on client-provided Content-Type headers.

3. Sanitize SVG Files (If SVG Is Required)
- Remove <script>, event handlers (onload, onclick), and external references.
- Use a trusted SVG sanitization library.

4. Serve Uploaded Files Safely
- Serve uploads from a separate domain (e.g., uploads.example-cdn.com).
- Apply the following HTTP headers:
Content-Disposition: attachment
Content-Type: application/octet-stream
X-Content-Type-Options: nosniff

5. Implement Content Security Policy (CSP)
- Use a restrictive CSP to limit script execution: Content-Security-Policy: default-src 'none'; img-src 'self'

6. Disable Inline JavaScript Execution
- Avoid rendering user-uploaded content directly within application pages.

7. Conduct security code review

# Secure Code Example:
1. Add File Validation to All Registration Functions
```from django.core.exceptions import ValidationError
from PIL import Image
import os

ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif']
ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif']
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

def validate_profile_picture(file):
    """Validate uploaded profile pictures"""
    
    if not file:
        return None
    
    # Check extension
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f'Invalid file type. Allowed: jpg, png, gif')
    
    # Check MIME type
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise ValidationError(f'Invalid content type: {file.content_type}')
    
    # Check file size
    if file.size > MAX_FILE_SIZE:
        raise ValidationError('File too large (max 2MB)')
    
    # Verify actual image
    try:
        img = Image.open(file)
        img.verify()
        file.seek(0)  # Reset file pointer
    except Exception:
        raise ValidationError('Invalid image file')
    
    return file```


**#2. Update Doctor Registration:**
```
def DOCSIGNUP(request):
    specialization = Specialization.objects.all()
    if request.method == "POST":
        pic = request.FILES.get('pic')
        
        # VALIDATE FILE
        try:
            if pic:
                pic = validate_profile_picture(pic)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('docsignup')
        
        # ... rest of code ...
```
**References**

- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-80: https://cwe.mitre.org/data/definitions/80.html
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
