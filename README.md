# STIG for macOS High Sierra - Script and Configuration Profile Remediation
## INFO:

The STIG is available on IASE at: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems,mac-os

## USAGE:
### Add the following scripts to your Jamf Pro

##### 1_STIG_Set_Priorities.sh
This script will require additional configuration prior to deployment.

Sets organizational compliance for each listed item, which gets written to STIG_security_score.plist. Values default to "true".

To disregard a given item set the value to "false" by changing the associated comment: AOSX_13_00000X="true" or AOSX_13_00000X="false"

The script writes to /Library/Application Support/SecurityScoring/STIG_security_score.plist by default.

##### 2_STIG_Audit_Compliance.sh
Run this before and after 3_STIG_Remediation to audit the remediation.

Reads the plist at /Library/Application Support/SecurityScoring/STIG_security_score.plist. For items prioritized (listed as "true,") the script queries against the current computer/user environment to determine compliance against each item.

Items that pass compliance do not require further remediation and are set to "false" in the STIG_security_score.plist.

Non-compliant items are recorded at /Library/Application\ Support/SecurityScoring/STIG_audit

##### 3_STIG_Remediation.sh
Reads the plist at /Library/Application Support/SecurityScoring/org_security_score.plist.

For items still prioritized (listed as "true,") the script applies recommended remediation actions for the client/user.

### Create a single Jamf Policy using all three scripts
* 1_STIG_Set_Priorities.sh – Script Priority: Before
* 2_STIG_Audit_Compliance.sh – Script Priority: Before
* 3_STIG_Remediation.sh – Script Priority: Before
* 2_STIG_Audit_Compliance.sh – Script Priority: After

### Set the following options for the Jamf Policy
* Recurring trigger to track compliance over time (Daily, weekly, or Monthly)
* Update Inventory

### Create Extension Attributes using the following scripts
##### 2.5_STIG_Audit_List Extension Attribute
Set as Data Type "String."
Reads contents of /Library/Application\ Support/SecurityScoring/STIG_audit file and records to Jamf Pro inventory record.

##### 2.6_STIG_Audit_Count Extension Attribute
Set as Data Type "Integer." 
Reads contents of /Library/Application\ Support/SecurityScoring/STIG_audit file and records count of items to Jamf Pro inventory record. Usable with smart group logic (2.6_STIG_Audit_Count greater than 0) to immediately determine computers not in compliance.

##### 2.7_STIG_suidfilelist Extension Attribute
Set as Data Type "String."
Reads contents of /Library/Application\ Support/SecurityScoring/STIG_suidfilelist file and records to Jamf Pro inventory record.

## REMEDIATED USING CONFIGURATION PROFILES:
The following Configuration profiles are available in mobileconfig and plist form. Mobileconfigs can be uploaded to Jamf Pro as Configuration Profiles.

### 10.13 STIG - Certificates mobileconfig
* AOSX_13_000750 - Certificate payload

### 10.13 STIG - Disable Bluetooth mobileconfig
* AOSX_13_000065 - Custom payload > com.apple.MCXBluetooth.plist > DisableBluetooth=true
* AOSX_13_000955 - Custom payload > com.apple.MCXBluetooth.plist > DisableBluetooth=true
* AOSX_13_000965 - Custom payload > com.apple.MCXBluetooth.plist > DisableBluetooth=true

### 10.13 STIG - Disable com.apple.digihub
* AOSX_13_000085 - Custom payload > com.apple.digihub.blank.cd.appeared > action=1
* AOSX_13_000090 - Custom payload > com.apple.digihub.blank.dvd.appeared > action=1
* AOSX_13_000095 - Custom payload > com.apple.digihub.cd.music.appeared > action=1
* AOSX_13_000100 - Custom payload > com.apple.digihub.cd.picture.appeared > action=1
* AOSX_13_000105 - Custom payload > com.apple.digihub.dvd.video.appeared > action=1

### 10.13 STIG - Disable Hot Corners
* AOSX_13_000006 - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0

### 10.13 STIG - Disable iTunes Sharing
* AOSX_13_000862 -Custom payload > com.apple.applicationaccess > allowiTunesFileSharing=false
* AOSX_13_001140 - Custom payload > com.apple.itunes > disableSharedMusic=true

### 10.13 STIG - Disable Location Services
* AOSX_13_000535 - Custom payload > com.apple.MCX > DisableLocationServices=true

### 10.13 STIG - Passcode
* AOSX_13_000585 - Passcode payload > Require alphanumeric value (checked)
* AOSX_13_000587 - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
* AOSX_13_000587 - Passcode payload > Allow simple value (unchecked)
* AOSX_13_000590 - Passcode payload > MINIMUM PASSCODE LENGTH 15
* AOSX_13_001324 - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15
* AOSX_13_001325 - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
* AOSX_13_002085 - Passcode payload > MAXIMUM PASSCODE AGE 60
* AOSX_13_002090 - Passcode payload > PASSCODE HISTORY 5

### 10.13 STIG - Restrictions
* AOSX_13_000475 - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app/"
* AOSX_13_000490 - Restrictions payload > Applications > Disallow "/Applications/Messages.app/"
* AOSX_13_000505 - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
* AOSX_13_000507 - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
* AOSX_13_000510 - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
* AOSX_13_000515 - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
* AOSX_13_000517 - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
* AOSX_13_000518 - Restrictions payload > Functionality > Allow use of Camera (unchecked)
* AOSX_13_000520 - Restrictions payload > Preferences > disable selected items "iCloud"
* AOSX_13_000521 - Restrictions payload > Preferences > disable selected items "Internet Accounts"
* AOSX_13_000522 - Restrictions payload > Preferences > disable selected items "Dictation & Speech"
* AOSX_13_000523 - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
* AOSX_13_000523 - Custom payload > com.apple.assistant.support > allowAssistant=false
* AOSX_13_000531 - Restrictions payload > Functionality > Allow iCloud Find My Mac (unchecked)
* AOSX_13_000551 - Restrictions payload > Functionality > Allow Touch ID to unlock device (unchecked)
* AOSX_13_000557 - Restrictions payload > Functionality > Allow iCloud Back to My Mac (unchecked)
* AOSX_13_000558 - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
* AOSX_13_000559 - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
* AOSX_13_000560 - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
* AOSX_13_000561 - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
* AOSX_13_000562 - Restrictions payload > Functionality > Allow iCloud Drive > Desktop & Documents (unchecked)
* AOSX_13_000850 - Restrictions payload > Media > EXTERNAL DISKS: Allow (unchecked)
* AOSX_13_002050 - Restrictions payload > Media > Allow AirDrop (unchecked)
* AOSX_13_362149 - Restrictions payload > Applications > Disallow "/Users/"

### 10.13 STIG - Security_and_Privacy - LoginWindow
* AOSX_13_000005 - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
* AOSX_13_000007 - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (un-checked)
* AOSX_13_000010 - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less)
* AOSX_13_000020 - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (checked)
* AOSX_13_000025 - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time)
* AOSX_13_000530 - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
* AOSX_13_000554 - Login Window payload > Options > Allow Guest User (unchecked)
* AOSX_13_000556 - Login Window payload > Options > Disable Siri setup during login (checked)
* AOSX_13_000710 - Security & Privacy payload > General > Mac App Store and identified developers (selected) 
* AOSX_13_000711 - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
* AOSX_13_000925 - Login Window payload > Options > Disable automatic login (checked)
* AOSX_13_000930 - Login Window payload > Window > Name and password text fields (selected)
* AOSX_13_001125 - Login Window payload > Options > Disable Apple ID setup during login (checked)

### 10.13 STIG - Smart Card
* AOSX_13_030014 - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
* AOSX_13_067035 - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)

## RECOMMENDED STIG EXCEPTIONS
* AOSX_13_000110 – Managed by a directory server (AD) – The macOS system must automatically remove or disable temporary user accounts after 72 hours.
* AOSX_13_000115 – Managed by a directory server (AD) – The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
* AOSX_13_000142 – NFS is not applicable for 10.13 and higher.
* AOSX_13_000143 – NFS is not applicable for 10.13 and higher.
* AOSX_13_000585 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_000587 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_000590 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_001235 – There is no way to automate this.
* AOSX_13_001324 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_001325 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_001327 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_002085 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
* AOSX_13_002090 – DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.

## NOTES
