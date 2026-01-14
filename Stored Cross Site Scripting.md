
**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/news-portal-using-python-django-and-mysql/)
- Affected Version: [<= v1.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Stored Cross-Site Scripting (XSS) via Unrestricted SVG File Upload in News Management System
- Affected URL: http://127.0.0.1:8000/AdminProfile, http://127.0.0.1:8000/AddSubadmin, http://127.0.0.1:8000/ViewSubadmin/9
- Vulnerable Parameter:  /newsportal/onps/adminviews.py, /newsportal/onps/views.py - Profile Pic

**Vulnerable Files:**

- File Name: /newsportal/
- Path: /newsportal/onps/adminviews.py, /newsportal/onps/views.py

**Vulnerability Type**

- Stored Cross-Site Scripting CWE: CWE-79, CWE-434, CWE-80
- Severity Level: 8.7 (HIGH)

**Root Cause:**

The vulnerability exists due to the following security deficiencies in the file upload implementation:

1. **Lack of File Type Validation:**
```# VULNERABLE CODE EXAMPLE from adminviews.py (Line 22)
pic = request.FILES.get('profile_pic') 

# File is directly assigned without any checks
user = CustomUser(
    # ... other fields ...
    profile_pic = pic, 
)
user.save()
```

2. **Profile Picture Update - ADMIN_PROFILE_UPDATE Function:**
File: views.py, Lines: 126-147

Function: ADMIN_PROFILE_UPDATE(request)

```@login_required(login_url = '/')
def ADMIN_PROFILE_UPDATE(request):
    if request.method == "POST":
        profile_pic = request.FILES.get('profile_pic')

if profile_pic !=None and profile_pic != "":
               customuser.profile_pic = profile_pic 
            customuser.save()
```

3. **Subadmin Profile Update - SUBADMIN_PROFILE_UPDATE Function:**

File: adminviews.py, Lines: 89-122
Function: SUBADMIN_PROFILE_UPDATE(request)
```
@login_required(login_url='/')
def SUBADMIN_PROFILE_UPDATE(request):
    if request.method == "POST":
        profile_pic = request.FILES.get('profile_pic')

  if profile_pic:
                customuser.profile_pic = profile_pic 
            customuser.save()
```
**Security Failures:**

- No file extension validation (accepts .svg, .html, .js, any extension)
- No MIME type verification
- No content sanitization or inspection
- No use of Django's FileExtensionValidator
- No verification that uploaded file is actually an image
- Files served with original MIME type (image/svg+xml), allowing script execution

**Impact:**

Django application accepts file uploads without validation. Missing FileExtensionValidator and content verification. Allows SVG files with embedded JavaScript to be stored and rendered.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**

The Django News Management Application contains multiple Stored Cross-Site Scripting (XSS) vulnerabilities through unrestricted file upload functionality. The application fails to properly validate, sanitize, and restrict file types during the upload process across multiple endpoints including profile picture uploads and news post image uploads.

An authenticated attacker can exploit this vulnerability by uploading malicious files (SVG, HTML, or specially crafted image files) containing JavaScript code. When other users (including administrators) view pages that display these uploaded files, the malicious JavaScript executes in their browser context, potentially leading to session hijacking, credential theft, privilege escalation, and complete account takeover.

The vulnerability exists in three locations:
http://127.0.0.1:8000/AdminProfile
http://127.0.0.1:8000/AddSubadmin
http://127.0.0.1:8000/ViewSubadmin/9

The application accepts SVG files without content inspection or sanitization. When these files are rendered in the browser (either by viewing user profiles or opening images in new tabs), the embedded JavaScript executes in the security context of any user viewing the content, including other administrators.

**Vulnerable Code Example:**

/News-Portal-Python-Django-Project/newsportal/onps/adminviews.py
/News-Portal-Python-Django-Project/newsportal/onps/views.py

<img width="564" height="101" alt="Screenshot 2026-01-12 at 16 40 15" src="https://github.com/user-attachments/assets/81a9e7e3-d24c-4d74-ac05-cc01b8da458e" />

<img width="602" height="163" alt="Screenshot 2026-01-12 at 16 40 53" src="https://github.com/user-attachments/assets/c39d3342-3182-4cff-ae48-c4ba20e5fa79" />

**Step-by-Step Reproduction:**
### **Trigger XSS as Admin**

**First Scenario:**
1. Login as Admin
2. Navigate to: http://127.0.0.1:8000/AdminProfile, http://127.0.0.1:8000/ViewSubadmin/9
3. Click "Browse..." under "Upload Profile Pic"
4. Select: malicious.svg
5. Click "Update"
6. File uploaded to: /malicious.svg and triggerd as XSS attack.

**Second Scenario:**
1. Login as SubAdmin
2. Navigate to: http://127.0.0.1:8000/AddSubadmin
3. Right Click and open image in new tab on Profile Pic
4. Triggerd as XSS attack.

**Screenshots**
[Attach screenshots showing:]

<img width="1877" height="1214" alt="Screenshot 2026-01-11 at 18 55 03" src="https://github.com/user-attachments/assets/a81223c3-e0ae-44f5-87c7-9abc9bf72bb6" />

<img width="1517" height="1244" alt="Screenshot 2026-01-11 at 18 52 59" src="https://github.com/user-attachments/assets/c8a12f8c-5ba9-4e1d-aabd-33e20b96826b" />

<img width="1594" height="990" alt="Screenshot 2026-01-11 at 18 53 05" src="https://github.com/user-attachments/assets/7e0c21cb-61b9-41e8-95e8-26431aa5aee8" />

<img width="1640" height="1082" alt="Screenshot 2026-01-12 at 16 48 02" src="https://github.com/user-attachments/assets/57ae5700-10bd-4843-9882-7478d2237789" />

<img width="1594" height="990" alt="Screenshot 2026-01-11 at 18 53 05" src="https://github.com/user-attachments/assets/557e2ad5-e757-4a17-bf36-f5d1b2817498" />

**Impact Assessment:**

The XSS executes with administrator privileges, allowing an attacker to:
- Admin can upload malicious SVG
- XSS executes when viewing Admin/SubAdmin profiles
- Session hijacking possible
- Admin account compromise

**Affected Components:**

- Profile Picture Upload Functionality
- Admin Profile Upload Functionality
- SubAdmin Profile Update Functionality
- News Post Image Upload Functionality
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
1. Implement File Type Validation
from django.core.exceptions import ValidationError
import os
from PIL import Image

ALLOWED_IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif']
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_image_file(file):
    """Validate uploaded image files"""
    
    # Check file extension
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValidationError(f'Unsupported file extension. Allowed: {", ".join(ALLOWED_IMAGE_EXTENSIONS)}')
    
    # Check file size
    if file.size > MAX_FILE_SIZE:
        raise ValidationError(f'File size exceeds maximum limit of {MAX_FILE_SIZE / (1024*1024)}MB')
    
    # Verify actual image content (not just extension)
    try:
        img = Image.open(file)
        img.verify()
    except Exception:
        raise ValidationError('Invalid image file')
    
    # Check MIME type
    if file.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
        raise ValidationError(f'Invalid content type: {file.content_type}')
    
    return file

**#2. Update All Upload Functions:**

@login_required(login_url='/')
def ADD_SUBADMIN(request):
    if request.method == "POST":
        pic = request.FILES.get('profile_pic')
        
        try:
            if pic:
                validate_image_file(pic)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('add_subadmin')
        
        # ... rest of the code ...

**References**

- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-80: https://cwe.mitre.org/data/definitions/80.html
