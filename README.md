Overview

This is a command-line password manager written in C that allows users to securely store, update, retrieve, and delete passwords. 
The manager uses SHA-256 hashing for secure master password protection , Uses ceaser cipher for password crypotgraphy 
integrates with the Have I Been Pwned (HIBP) API to check for password breaches.

Features

Master Password Protection: Secure access to all stored passwords using a master password.

Password Masking: Hides passwords during input.

(CRUD)Add, Get, Update, Delete Passwords: Supports password management operations.

Password Generation: Generates random passwords of specified lengths then gives you power to automatically add them.

Password Breach Check: Checks if a password has been compromised using the HIBP API.

Usage Logging: Logs all password-related actions.


Getting Started

Prerequisites

C compiler (e.g., gcc)

OpenSSL library for SHA-256 hashing

cURL library for API calls


**You can install them using:**

*sudo apt-get install gcc libssl-dev libcurl4-openssl-dev*

Installation

1. Clone the repository:

git clone https://github.com/your-username/KYL-password_manager.git
cd KYL-password_manager


2. Compile the program:

~gcc main.c -o password_manager -lcrypto -lcurl~
or 
Just use the 'make' command for make file to handle this



**Usage**

for intended use you will have to set it in ENVIROMENT VARIABLE of your PC.

Setting the Master Password

On the first run, you'll be prompted to set a master password.

**Commands**
![f683b1ab-7847-49a7-82cc-d9291e915c82](https://github.com/user-attachments/assets/420a78e2-e1ac-48bb-9ba1-4df08f1da864)
![54b5597a-7e07-4af8-b99b-ccd6574be948](https://github.com/user-attachments/assets/a200f3fe-66bf-4d6f-8e57-f52de86de196)

**Examples**

To add a password:

KYL add twitter MySecurePassword123

To check if a password has been breached:

KYL check MySecurePassword123


**Security Features**

Master Password: Uses SHA-256 for hashing.

HIBP Integration: Ensures passwords haven’t been compromised.

Uses ceaser cipher for password encryption.

**Future Enhancements**

Implementing password encryption for stored passwords.

Adding multi-factor authentication (MFA) support.

Integrating a GUI interface for ease of use.


*Contributing*


Contributions are welcome! Feel free to open an issue or submit a pull request.

License

This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments

OpenSSL for cryptographic functions

Have I Been Pwned for the password breach API

**To allow Windows users to access your password manager like a package manager by adding it to their environment variables, follow these steps:**

1. Create a .bat File (Windows Executable Script):

Create a .bat file named KYL.bat in the directory containing your compiled executable. This file should have the following content:

@echo off
path\to\your\compiled\executable.exe %*

Replace path\to\your\compiled\executable.exe with the actual path to your executable file.



2. Add the Directory to the PATH Environment Variable:

Right-click on "This PC" or "My Computer" and select "Properties."

Click on "Advanced system settings" and then "Environment Variables."

Find the Path variable under "System variables" and select "Edit."

Click "New" and add the path to the directory containing your .bat file.

Click "OK" to save the changes.



3. Test the Setup:

Open a new Command Prompt and type KYL followed by any of the commands. It should work without needing to specify the full path.
Now, Windows users will be able to use your password manager from any command prompt window just KYL.

**FOR UNIX BASED SYSTEM USERS CHECKOUT MY LINKDN VIDEO**
