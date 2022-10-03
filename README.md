#### User Account Operations

## Script app to perform operations on Active Directory accounts (on-prem) without granting admins required permissions. It's a simple file based ouput between app/back-end, secured with NTFS permissions. I built it for a RBAC-based AD where admins didn't have necessary permissions. Consits of app and back-end/batch script.

#### This repository is not maintained!

**The application and script has been tested in Powershell 4 and 5 on Windows Server 2012 R2/2016. It requires the Active Directory PS-module. You could publish it as a virtual app on a server with the module installed.**

_Specify the names of app access and fallback groups, and service account for the app/back-end script in config file AppADSettings.csv._
_Operating admin users must have read NTFS-permission to the encryption key file. Do NOT grant them access to the hashed service account password-file, only grant the service account permission to it's hashed password-file._

_The encrypting key is used for operated users password._

_Restrict NTFS read-access on the config files and write/modify-access on output file locations to the access and fallback groups._

_Restrict the AD permissions for the service account on the user target OUs to only the app operations/attributes._

There's a "authorization-function" inside the app, which is just a visible way to show the admin user if they're missing access group membership. The above mentioned NTFS-permission for the output location is how you actually secure authorized usage.


### The app enable admins to delete, disable, enable, clear lockout, set or reset account expiration date and force reset or set password on other users.
### It also shows the current status for the operated/selected user, for example when disabled, account expiration date and lock status/time.

Admins get the option to enforce a password change when enabling a user.

All passwords are automatically generated(Defined in the app-script)

Admins get prompted for verification before deleting an account.

To display timestamp of disabled users you need to add a timestamp on users description field when you disable them. 
The back-end script sets the users description with a timestamp and optional text when disabling them, if enabled in the config file. (There's also the option "InactiveStamp" in the config file, in case you also disable your users for inactivity and stamp their description field differently.)

You can use Task scheduler to trigger the back-end script when a output file is created or modified. Import the example file I provided(TaskUserAccOps.xml), and set output file path in the trigger and script path in the action. It also requires you to enable file audit(Object Access in Local Security Policy, and enable read/modify audit on the output-file folder.)

### Config file settings:

* For enabling an account you can configure the options _move accounts_ and _clear any attribute_(e.g. description).

* For disabling an account you can configure the options to _move the account_, _add text to the description with an optional timestamp_ and _clearing any attribut_.  

* The scope of users/admins to manage is defined by OU in the config file.

* The back-end script logs each operation to a text-file. Specify output path the in the config file.

* You can restrict maximum allowed account expirate date in the config file.

* Optional: In the config file you have the option to specify a 2nd output file, separately for each operation executed by the back-end script, for further account proccessing by another script if you wish. The output file is then just renamed to the 2nd name when it has been processed.



There's a greyed out button for management of 2nd account type(e.g. admin accounts), but needs setting up in the scripts, the same way as user accounts. 

There's no possibility for audit logging in the two scripts.

Compile UserAccOpsApp.ps1 into EXE. I use PS2EXE https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-Convert-PowerShell-9e4e07f1 (Run with NoConsole parameter to build a Windows App without the Powershell console.)




