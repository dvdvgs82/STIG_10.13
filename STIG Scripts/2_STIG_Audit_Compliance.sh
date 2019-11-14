#!/bin/bash
#
# root check
if [ "$(/usr/bin/whoami)" != "root" ]; then
  /bin/echo "This script must be run as root or sudo."
  exit 0
fi
#
####################################################################################################
#
# The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
# MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
# OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.
#
# IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
# MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
# AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
# STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################################################
#
# DESCRIPTION
# APPLE macOS 10.13 (HIGH SIERRA) SECURITY TECHNICAL IMPLEMENTATION GUIDE (STIG)
# These scripts automate and verify the U_Apple_OS_X_10-13_V1R2_STIG
#
# The STIG is available on IASE at:
# https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems,mac-os
#
# The STIG viewer is available on IASE at:
# http://iase.disa.mil/stigs/Pages/stig-viewing-guidance.aspx
#
# These scripts are used to Audit and Remediate STIG compliance.
# They should be audited whenever the STIG is updated for macOS.
#
# Once these scripts are run, several of the settings cannot be easily rolled back.
#
# CAT I		Any vulnerability, the exploitation of which will directly and immediately result in loss of Confidentiality, Availability, or Integrity. (Most severe)
# CAT II	Any vulnerability, the exploitation of which has a potential to result in loss of Confidentiality, Availability, or Integrity.
# CAT III	Any vulnerability, the existence of which degrades measures to protect against loss of Confidentiality, Availability, or Integrity.
#
#####################################################################################################
#
# USAGE
# Reads from plist at $LogDir/STIG_security_score.plist by default.
# For "true" items, runs query for current computer/user compliance.
# Non-compliant items are logged to $LogDir/STIG_audit
LogDir="/Library/Application Support/SecurityScoring"
plistlocation="$LogDir/STIG_security_score.plist"
auditfilelocation="$LogDir/STIG_audit"
currentUser="$(python -c 'from SystemConfiguration import SCDynamicStoreCopyConsoleUser; import sys; username = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])[0]; username = [username,""][username in [u"loginwindow", None, u""]]; sys.stdout.write(username + "\n");')"
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | /usr/bin/awk -F ": " '{print $2}' | xargs)"
logFile="$LogDir/STIGremediation.log"

if [[ $(/usr/bin/tail -n 1 "$logFile") = *"Remediation complete" ]]; then
	/bin/echo "Append to existing logFile"
 	/bin/echo "$(/bin/date -u)" "Beginning Audit" >> "$logFile"; else
 	/bin/echo "Create new logFile"
 	/bin/echo "$(/bin/date -u)" "Beginning Audit" > "$logFile"	
fi

if [[ ! -e $plistlocation ]]; then
	/bin/echo "No scoring file present"
	exit 0
fi

# Cleanup audit file to start fresh
[ -f "$auditfilelocation" ] && /bin/rm "$auditfilelocation"
/usr/bin/touch "$auditfilelocation"

#####################################################################################################
#
# Group ID (Vulid): V-81463
# Group Title: SRG-OS-000031-GPOS-00012
# Rule ID: SV-96177r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000005
# Rule Title: The macOS system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.
# 
# Vulnerability Discussion: A default screen saver must be configured for all users, as the screen saver will act as a session time-out lock for the system and must conceal the 
# contents of the screen from unauthorized users. The screen saver must not display any sensitive information or reveal the contents of the locked session screen. Publicly viewable 
# images can include static or dynamic images such as patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen.
# 
# Check Content: 
# To view the currently selected screen saver for the logged-on user, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep loginWindowModulePath
# 
# If there is no result or defined "loginWindowModulePath", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000060
#
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
# Verify organizational score
AOSX_13_000005="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000005)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000005" = "1" ]; then
	AOSX_13_000005_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'loginWindowModulePath')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000005_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000005 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000005 -bool false; else
		/bin/echo "* AOSX_13_000005 A default screen saver must be configured for all users via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000005 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81465
# Group Title: SRG-OS-000031-GPOS-00012
# Rule ID: SV-96179r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000006
# Rule Title: The macOS system must be configured to disable hot corners.
# 
# Vulnerability Discussion: Although hot corners can be used to initiate a session lock or launch useful applications, they can also be configured to disable an automatic 
# session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.
# 
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but 
# does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to 
# vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
# 
# Check Content: 
# To check if the system is configured to disable hot corners, run the following commands:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous
# 
# If the return is null, or does not equal:
# wvous-bl-corner = 0;
# wvous-br-corner = 0;
# wvous-tl-corner = 0;
# wvous-tr-corner = 0;
# this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000060
#
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0
# Verify organizational score
AOSX_13_000006="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000006)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000006" = "1" ]; then
	AOSX_13_000006_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous)"
	AOSX_13_000006_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-bl-corner\" = 0;')"
	AOSX_13_000006_Audit3="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-br-corner\" = 0;')"
	AOSX_13_000006_Audit4="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-tl-corner\" = 0;')"
	AOSX_13_000006_Audit5="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-tr-corner\" = 0;')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000006_Audit1" != "" ]] && [[ "$AOSX_13_000006_Audit2" > "0" ]] && [[ "$AOSX_13_000006_Audit3" > "0" ]] && [[ "$AOSX_13_000006_Audit4" > "0" ]] && [[ "$AOSX_13_000006_Audit5" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000006 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000006 -bool false; else
		/bin/echo "* AOSX_13_000006 The macOS system must be configured to disable hot corners via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000006 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81467
# Group Title: SRG-OS-000028-GPOS-00009
# Rule ID: SV-96181r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000007
# Rule Title: The macOS system must be configured to prevent Apple Watch from terminating a session lock.
# 
# Vulnerability Discussion: Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and 
# prevents unauthorized users from accessing the current user's account.
# 
# Check Content: 
# To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock = 0;"
# 
# If there is no result, this is a finding.
# 
# Fix Text: This setting is enforced using the "Security & Privacy" configuration profile.
# 
# CCI: CCI-000056
#
# Configuration Profile - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (unchecked)
# Verify organizational score
AOSX_13_000007="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000007)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000007" = "1" ]; then
	AOSX_13_000007_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowAutoUnlock = 0;')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000007_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000007 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000007 -bool false; else
		/bin/echo "* AOSX_13_000007 The macOS system must be configured to prevent Apple Watch from terminating a session lock via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000007 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81469
# Group Title: SRG-OS-000029-GPOS-00010
# Rule ID: SV-96183r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000010
# Rule Title: The macOS system must initiate a session lock after a 15-minute period of inactivity.
# 
# Vulnerability Discussion: A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity. 
# This mitigates the risk that a user might forget to manually lock the screen before stepping away from the computer.
# 
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system 
# but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior 
# to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
# 
# Check Content: 
# To check if the system has a configuration profile configured to enable the screen saver after a time-out period, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep loginWindowIdleTime
# 
# The check should return a value of "900" or less for "loginWindowIdleTime".
# 
# If it does not, this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000057
#
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
# Verify organizational score
AOSX_13_000010="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000010)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000010" = "1" ]; then
	AOSX_13_000010_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep loginWindowIdleTime | /usr/bin/awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000010_Audit" -le "900" ]] && [[ "$AOSX_13_000010_Audit" != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000010 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000010 -bool false; else
		/bin/echo "* AOSX_13_000010 A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000010 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81471
# Group Title: SRG-OS-000028-GPOS-00009
# Rule ID: SV-96185r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000020
# Rule Title: The macOS system must retain the session lock until the user reestablishes access using established identification and authentication procedures.
# 
# Vulnerability Discussion: Users must be prompted to enter their passwords when unlocking the screen saver. 
# The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account.
# 
# Check Content: 
# To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPassword
# 
# If there is no result, or if "askForPassword" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000056
#
# Configuration Profile - Security & Privacy Payload > General > Require password after sleep or screen saver begins (checked)
# Verify organizational score
AOSX_13_000020="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000020" = "1" ]; then
	AOSX_13_000020_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'askForPassword = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000020_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000020 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000020 -bool false; else
		/bin/echo "* AOSX_13_000020 Users must be prompted to enter their passwords when unlocking the screen saver via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000020 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81473
# Group Title: SRG-OS-000028-GPOS-00009
# Rule ID: SV-96187r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000025
# Rule Title: The macOS system must initiate the session lock no more than five seconds after a screen saver is started.
# 
# Vulnerability Discussion: A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the 
# ability for a session to be truly locked, requiring authentication to unlock.
# 
# Check Content: 
# To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay
# 
# If there is no result, or if "askForPasswordDelay" is not set to "5.0" or less, this is a finding.
# 
# Fix Text: This setting is enforced using the "Security and Privacy Policy" configuration profile.  
# 
# CCI: CCI-000056
# 
# Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time)
# Verify organizational score
AOSX_13_000025="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000025)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000025" = "1" ]; then
	AOSX_13_000025_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay | /usr/bin/awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000025_Audit" -le "5" ]] && [[ "$AOSX_13_000025_Audit" != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000025 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000025 -bool false; else
		/bin/echo "* AOSX_13_000025 The macOS system must initiate the session lock no more than five seconds after a screen saver is started via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000025 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81475
# Group Title: SRG-OS-000032-GPOS-00013
# Rule ID: SV-96189r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000030
# Rule Title: The macOS system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.
# 
# Vulnerability Discussion: Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, 
# such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to proceed. 
# Auditing successful and unsuccessful attempts to switch to another user account and the escalation of privileges mitigates this risk.
# 
# Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Attempts to log in as another user are logged by way of the "lo" flag.
# 
# If "lo" is not listed in the result of the check, this is a finding.
# 
# Fix Text: To ensure the appropriate flags are enabled for auditing, run the following command:
# 
# /usr/bin/sudo sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000067
# CCI: CCI-000172
# 
# Verify organizational score
AOSX_13_000030="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000030)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000030" = "1" ]; then
	AOSX_13_000030_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000030_Audit = *"lo"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000030 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000030 -bool false; else
		/bin/echo "* AOSX_13_000030 Ensure the appropriate flags are enabled for /etc/security/audit_control - lo." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000030 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81477
# Group Title: SRG-OS-000033-GPOS-00014
# Rule ID: SV-96191r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000035
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote 
# access sessions including transmitted data and data during preparation for transmission – Enable remote access through SSH.
# 
# Vulnerability Discussion: Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.
# 
# Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, 
# non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
# 
# Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection 
# (e.g., Remote Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based 
# on the security categorization of the information.
# 
# Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188, SRG-OS-000425-GPOS-00189, SRG-OS-000426-GPOS-00190
# 
# Check Content: 
# For systems that allow remote access through SSH, run the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd
# 
# If the results do not show the following, this is a finding.
# 
# "com.openssh.sshd" => false
# 
# Fix Text: To enable the SSH service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000068
# CCI: CCI-002418
# CCI: CCI-002420
# CCI: CCI-002421
# CCI: CCI-002422
#
# Enable remote access through SSH
# Verify organizational score
AOSX_13_000035="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000035)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000035" = "1" ]; then
	AOSX_13_000035_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_13_000035_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000035_Audit1 = *"false"* ]] || [[ $AOSX_13_000035_Audit2 = *"On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000035 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000035 -bool false; else
		/bin/echo "* AOSX_13_000035 Enable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000035 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
# Disable remote access through SSH
# Verify organizational score
AOSX_13_000035off="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000035off)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000035off" = "1" ]; then
	AOSX_13_000035off_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_13_000035off_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000035off_Audit1 = *"true"* ]] || [[ $AOSX_13_000035off_Audit2 = *"Off"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000035off passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000035off -bool false; else
		/bin/echo "* AOSX_13_000035off Disable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000035off fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81479
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96193r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000050
# Rule Title: The macOS system must be configured to disable rshd service.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, 
# may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not 
# related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The "rshd" service must be disabled.
# 
# Check Content: 
# To check if the "rshd" service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.rshd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.rshd" => true
# 
# Fix Text: To disable the "rshd" service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.rshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_13_000050="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000050)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000050" = "1" ]; then
	AOSX_13_000050_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.rshd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000050_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000050 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000050 -bool false; else
		/bin/echo "* AOSX_13_000050 The macOS system must be configured to disable rshd service." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000050 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81481
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96195r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000055
# Rule Title: The macOS system must enforce requirements for remote connections to the information system.
# 
# Vulnerability Discussion: The Screen Sharing feature allows remote users to view or control the desktop of the current user. 
# A malicious user can take advantage of screen sharing to gain full access to the system remotely, either with stolen credentials 
# or by guessing the username and password. Disabling Screen Sharing mitigates this risk.
# 
# Check Content: 
# To check if the Screen Sharing service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.screensharing" => true
# 
# Fix Text: To disable the Screen Sharing service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_000055="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000055)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000055" = "1" ]; then
	AOSX_13_000055_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000055_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000055 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000055 -bool false; else
		/bin/echo "* AOSX_13_000055 The macOS system must enforce requirements for remote connections to the information system. Disable Screen Sharing service." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000055 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81483
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96197r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000065
# Rule Title: The macOS system must be configured with Bluetooth turned off unless approved by the organization.
# 
# Vulnerability Discussion: The Bluetooth kernel extension must be disabled, as wireless access introduces unnecessary security risks. 
# Disabling Bluetooth support with a configuration profile mitigates this risk.
# 
# Check Content: 
# If Bluetooth connectivity is required to facilitate use of approved external devices, this is not applicable.
# 
# To check if Bluetooth is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth
# 
# If the return is null or is not "DisableBluetooth = 1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Bluetooth Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
# Verify organizational score
AOSX_13_000065="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000065)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000065" = "1" ]; then
	AOSX_13_000065_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableBluetooth = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000065_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000065 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000065 -bool false; else
		/bin/echo "* AOSX_13_000065 The macOS system must be configured with Bluetooth turned off via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000065 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81485
# Group Title: SRG-OS-000300-GPOS-00118
# Rule ID: SV-96199r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000070
# Rule Title: The macOS system must be configured with Wi-Fi support software disabled.
# 
# Vulnerability Discussion: Use of Wi-Fi to connect to unauthorized networks may facilitate the exfiltration of mission data.
# 
# Satisfies: SRG-OS-000300-GPOS-00118, SRG-OS-000480-GPOS-00227
# 
# Check Content: 
# If the system requires Wi-Fi to connect to an authorized network, this is not applicable.
# 
# To check if the Wi-Fi network device is disabled, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices
# 
# A disabled device will have an asterisk in front of its name.
# 
# If the Wi-Fi device is missing this asterisk, this is a finding.
# 
# Fix Text: To disable the Wi-Fi network device, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off  
# 
# CCI: CCI-001443
# CCI: CCI-001444
# CCI: CCI-002418
# 
# Verify organizational score
AOSX_13_000070="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000070)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000070" = "1" ]; then
	AOSX_13_000070_Audit="$(/usr/sbin/networksetup -listallnetworkservices | /usr/bin/grep 'Wi-Fi')"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000070_Audit = "*"* ]] || [[ $AOSX_13_000070_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000070 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000070 -bool false; else
		/bin/echo "* AOSX_13_000070 The macOS system must be configured with Wi-Fi support software disabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000070 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81487
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96201r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000075
# Rule Title: The macOS system must be configured with Infrared [IR] support disabled.
# 
# Vulnerability Discussion: IR kernel support must be disabled to prevent users from controlling the system with IR devices. By default, 
# if IR is enabled, the system will accept IR control from any remote device.
# 
# Check Content: 
# To check if IR support is disabled, run the following command:
# 
# /usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled
# 
# If the result is not "0", this is a finding.
# 
# Fix Text: To disable IR, run the following command:
# 
# /usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool FALSE  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_000075="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000075)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000075" = "1" ]; then
	AOSX_13_000075_Audit="$(/usr/bin/defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000075_Audit = "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000075 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000075 -bool false; else
		/bin/echo "* AOSX_13_000075 The macOS system must be configured with Infrared [IR] support disabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000075 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81489
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96203r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000085
# Rule Title: The macOS system must be configured with automatic actions disabled for blank CDs.
# 
# Vulnerability Discussion: Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus 
# software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for blank CDs mitigates this risk.
# 
# Check Content: 
# If an approved HBSS DCM/DLP solution is installed, this is not applicable.
# 
# To check if the system has the correct setting for blank CDs in the configuration profile, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.blank.cd.appeared'
# 
# If this is not defined or "action" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Custom payload > com.apple.digihub.blank.cd.appeared > action=1
# Verify organizational score
AOSX_13_000085="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000085)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000085" = "1" ]; then
	AOSX_13_000085_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.blank.cd.appeared')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000085_Audit" = *"action = 1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000085 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000085 -bool false; else
		/bin/echo "* AOSX_13_000085 The macOS system must be configured with automatic actions disabled for blank CDs via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000085 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81491
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96205r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000090
# Rule Title: The macOS system must be configured with automatic actions disabled for blank DVDs.
# 
# Vulnerability Discussion: Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus 
# software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for blank DVDs mitigates this risk.
# 
# Check Content: 
# If an approved HBSS DCM/DLP solution is installed, this is not applicable.
# 
# To check if the system has the correct setting for blank DVDs in the configuration profile, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.blank.dvd.appeared'
# 
# If this is not defined or "action" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Custom payload > com.apple.digihub.blank.dvd.appeared > action=1
# Verify organizational score
AOSX_13_000090="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000090)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000090" = "1" ]; then
	AOSX_13_000090_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.blank.dvd.appeared')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000090_Audit" = *"action = 1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000090 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000090 -bool false; else
		/bin/echo "* AOSX_13_000090 The macOS system must be configured with automatic actions disabled for blank DVDs via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000090 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81493
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96207r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000095
# Rule Title: The macOS system must be configured with automatic actions disabled for music CDs.
# 
# Vulnerability Discussion: Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus 
# software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for music CDs mitigates this risk.
# 
# Check Content: 
# If an approved HBSS DCM/DLP solution is installed, this is not applicable.
# 
# To check if the system has the correct setting for music CDs in the configuration profile, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.music.appeared'
# 
# If this is not defined or "action" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000366
# 
# Configuration Profile - Custom payload > com.apple.digihub.cd.music.appeared > action=1
# Verify organizational score
AOSX_13_000095="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000095)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000095" = "1" ]; then
	AOSX_13_000095_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.music.appeared')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000095_Audit" = *"action = 1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000095 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000095 -bool false; else
		/bin/echo "* AOSX_13_000095 The macOS system must be configured with automatic actions disabled for music CDs via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000095 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81497
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96211r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000100
# Rule Title: The macOS system must be configured with automatic actions disabled for picture CDs.
# 
# Vulnerability Discussion: Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus 
# software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for picture CDs mitigates this risk.
# 
# Check Content: 
# If an approved HBSS DCM/DLP solution is installed, this is not applicable.
# 
# To check if the system has the correct setting for picture CDs in the configuration profile, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.picture.appeared'
# 
# If this is not defined or "action" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000366
# 
# Configuration Profile - Custom payload > com.apple.digihub.cd.picture.appeared > action=1
# Verify organizational score
AOSX_13_000100="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000100)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000100" = "1" ]; then
	AOSX_13_000100_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.picture.appeared')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000100_Audit" = *"action = 1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000100 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000100 -bool false; else
		/bin/echo "* AOSX_13_000100 The macOS system must be configured with automatic actions disabled for picture CDs via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000100 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81499
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96213r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000105
# Rule Title: The macOS system must be configured with automatic actions disabled for video DVDs.
# 
# Vulnerability Discussion: Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus 
# software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for video DVDs mitigates this risk.
# 
# Check Content: 
# If an approved HBSS DCM/DLP solution is installed, this is not applicable.
# 
# To check if the system has the correct setting for video DVDs in the configuration profile, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.dvd.video.appeared'
# 
# If this is not defined or "action" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000366
# 
# Configuration Profile - Custom payload > com.apple.digihub.dvd.video.appeared > action=1
# Verify organizational score
AOSX_13_000105="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000105)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000105" = "1" ]; then
	AOSX_13_000105_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.dvd.video.appeared')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000105_Audit" = *"action = 1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000105 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000105 -bool false; else
		/bin/echo "* AOSX_13_000105 The macOS system must be configured with automatic actions disabled for video DVDs via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000105 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81501
# Group Title: SRG-OS-000002-GPOS-00002
# Rule ID: SV-96215r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000110
# Rule Title: The macOS system must automatically remove or disable temporary user accounts after 72 hours.
# 
# Vulnerability Discussion: If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be targeted by attackers to gain unauthorized access. 
# To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.
# 
# Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.
# 
# If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.
# 
# To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.
# 
# Check Content: 
# Verify if a password policy is enforced by a directory service by asking the System Administrator (SA) or Information System Security Officer (ISSO).
# 
# If no policy is enforced by a directory service, a password policy can be set with the "pwpolicy" utility. The variable names may vary depending on how the policy was set.
# 
# To check if the password policy is configured to disable a temporary account after 72 hours, run the following command to output the password 
# policy to the screen, substituting the correct user name in place of username:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2
# 
# If there is no output, and password policy is not controlled by a directory service, this is a finding.
# 
# Otherwise, look for the line "<key>policyCategoryAuthentication</key>".
# 
# In the array that follows, there should be a <dict> section that contains a check <string> that allows users to log in if "policyAttributeCurrentTime" 
# is less than the result of adding "policyAttributeCreationTime" to 72 hours (259299 seconds). The check might use a variable defined in its "policyParameters" section.
# 
# If the check does not exist or if the check adds too great an amount of time to "policyAttributeCreationTime", this is a finding.
# 
# Fix Text: This setting may be enforced using a configuration profile or by a directory service.
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current policy file, 
# substituting the correct user name in place of "username":
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the resulting password policy file in a text editor.
# 
# If other policy settings are present, and the line "<key>policyCategoryAuthentication</key>" already exists, 
# insert the following text after the <array> tag that immediately follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>policyAttributeCurrentTime < policyAttributeCreationTime + 259299</string>
# <key>policyIdentifier</key>
# <string>Disable Temporary Account</string>
# </dict>
# 
# At a minimum, edit the file to ensure that it contains the following text:
# 
# <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>policyAttributeCurrentTime < policyAttributeCreationTime + 259299</string>
# <key>policyIdentifier</key>
# <string>Disable Temporary Account</string>
# </dict>
# </array>
# </dict>
# </plist>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file, 
# substituting the correct user name in place of "username":
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies pwpolicy.plist  
# 
# CCI: CCI-000016
#
# Managed by a directory server (AD)
# Verify organizational score
AOSX_13_000110="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000110)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000110" = "1" ]; then
	AOSX_13_000110_Audit="$(/usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000110_Audit" = *"Active Directory"* ]] || [[ "$AOSX_13_000110_Audit" = *"CentrifyDC"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000110 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000110 -bool false; else
		/bin/echo "* AOSX_13_000110 The macOS system must automatically remove or disable temporary user accounts after 72 hours. Managed by a directory server (AD). Ensure the system is integrated into a directory services infrastructure." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000110 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81503
# Group Title: SRG-OS-000123-GPOS-00064
# Rule ID: SV-96217r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000115
# Rule Title: The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
# 
# Vulnerability Discussion: Emergency administrator accounts are privileged accounts established in response to crisis situations where the 
# need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. 
# If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
# 
# Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators 
# when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic 
# termination dates. However, an emergency administrator account is normally a different account created for use by vendors or system maintainers.
# 
# To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms 
# that meet or exceed access control policy requirements.
# 
# Check Content: 
# If an emergency account has been created on the system, check the expiration settings of a local account using the following command, replacing "username" with the correct value:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2
# 
# If there is output, verify that the account policies do not restrict the ability to log in after a certain date or amount of time.
# 
# If they do, this is a finding.
# 
# Fix Text: To remove all "pwpolicy" settings for an emergency account, run the following command, replacing
# "username" with the correct value:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username clearaccountpolicies
# 
# Otherwise, to change the password policy for an emergency account and only remove some policy sections, run the following command to save 
# a copy of the current policy file for the specified username:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the resulting password policy file in a text editor and remove any policyContent sections that would restrict the ability to log in 
# after a certain date or amount of time.
# 
# To remove the section cleanly, remove the entire text that begins with <dict>, contains the like <key>policyContent<'/key>, and ends with </dict>.
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies pwpolicy.plist  
# 
# CCI: CCI-001682
# 
# Managed by a directory server (AD)
# Verify organizational score
AOSX_13_000115="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000115)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000115" = "1" ]; then
	AOSX_13_000115_Audit="$(/usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000115_Audit" = *"Active Directory"* ]] || [[ "$AOSX_13_000115_Audit" = *"CentrifyDC"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000115 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000115 -bool false; else
		/bin/echo "* AOSX_13_000115 The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours. Managed by a directory server (AD). Ensure the system is integrated into a directory services infrastructure." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000115 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81505
# Group Title: SRG-OS-000004-GPOS-00004
# Rule ID: SV-96219r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000120
# Rule Title: The macOS system must generate audit records for all account creations, modifications, disabling, and termination events; 
# privileged activities or other system-level access; all kernel module load, unload, and restart actions; all program initiations; 
# and organizationally defined events for all non-local maintenance and diagnostic sessions.
# 
# Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would 
# be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
# 
# Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000327-GPOS-00127, 
# SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215, SRG-OS-000471-GPOS-00216, SRG-OS-000476-GPOS-00221, SRG-OS-000477-GPOS-00222
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Administrative and Privileged access, including administrative use of the command line tools "kextload" and "kextunload" and changes to 
# configuration settings are logged by way of the "ad" flag.
# 
# If "ad" is not listed in the result of the check, this is a finding.
# 
# Fix Text: To ensure the appropriate flags are enabled for auditing, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000018
# CCI: CCI-000172
# CCI: CCI-001403
# CCI: CCI-001404
# CCI: CCI-001405
# CCI: CCI-002234
# CCI: CCI-002884
# 
# Verify organizational score
AOSX_13_000120="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000120)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000120" = "1" ]; then
	AOSX_13_000120_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000120_Audit = *"ad"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000120 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000120 -bool false; else
		/bin/echo "* AOSX_13_000120 Ensure the appropriate flags are enabled for /etc/security/audit_control - ad." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000120 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81507
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96221r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000139
# Rule Title: The macOS system must be configured to disable SMB File Sharing unless it is required.
# 
# Vulnerability Discussion: File Sharing is usually non-essential and must be disabled if not required. Enabling any service increases the 
# attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# If SMB File Sharing is required, this is not applicable.
# 
# To check if the SMB File Sharing service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.smbd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.smbd" => true
# 
# Fix Text: To disable the SMB File Sharing service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.smbd
# /usr/bin/sudo /bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist # legacy command but still needed
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_13_000139="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000139)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000139" = "1" ]; then
	AOSX_13_000139_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.smbd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000139_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000139 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000139 -bool false; else
		/bin/echo "* AOSX_13_000139 The macOS system must be configured to disable SMB File Sharing unless it is required." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000139 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81509
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96223r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000140
# Rule Title: The macOS system must be configured to disable Apple File (AFP) Sharing.
# 
# Vulnerability Discussion: File Sharing is non-essential and must be disabled. Enabling any service increases the attack surface for an intruder. 
# By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# To check if the Apple File (AFP) Sharing service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.AppleFileServer
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.AppleFileServer" => true
# 
# Fix Text: To disable the Apple File (AFP) Sharing service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.AppleFileServer
# /usr/bin/sudo /bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist # legacy command but still needed
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_13_000140="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000140)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000140" = "1" ]; then
	AOSX_13_000140_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.AppleFileServer)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000140_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000140 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000140 -bool false; else
		/bin/echo "* AOSX_13_000140 The macOS system must be configured to disable Apple File (AFP) Sharing." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000140 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81511
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96225r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000141
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.
# 
# Vulnerability Discussion: If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is 
# non-essential and NFS services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. Enabling 
# any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# If the NFS daemon is required, this is not applicable.
# 
# To check if the NFS daemon is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.nfsd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.nfsd" => true
# 
# Fix Text: To disable the NFS daemon, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.nfsd
# /usr/bin/sudo /bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.nfsd.plist # legacy command but still needed
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_13_000141="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000141)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000141" = "1" ]; then
	AOSX_13_000141_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.nfsd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000141_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000141 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000141 -bool false; else
		/bin/echo "* AOSX_13_000141 The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000141 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81513
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96227r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000142
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) lock daemon unless it is required.
# 
# Vulnerability Discussion: If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is 
# non-essential and NFS services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. Enabling 
# any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# If the NFS lock daemon is required, this is not applicable.
# 
# To check if the NFS lock daemon is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.lockd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.lockd" => true
# 
# Fix Text: To disable the NFS lock daemon, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.lockd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_13_000142="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000142)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000142" = "1" ]; then
	AOSX_13_000142_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.lockd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000142_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000142 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000142 -bool false; else
		/bin/echo "* AOSX_13_000142 The macOS system must be configured to disable the Network File System (NFS) lock daemon unless it is required." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000142 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81515
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96229r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000143
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) stat daemon unless it is required.
# 
# Vulnerability Discussion: If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is 
# non-essential and NFS services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. 
# Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# If the NFS stat daemon is required, this is not applicable.
# 
# To check if the NFS stat daemon is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.statd.notify
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.statd.notify" => true
# 
# Fix Text: To disable the NFS stat daemon, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.statd.notify
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_13_000143="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000143)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000143" = "1" ]; then
	AOSX_13_000143_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.statd.notify)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000143_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000143 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000143 -bool false; else
		/bin/echo "* AOSX_13_000143 The macOS system must be configured to disable the Network File System (NFS) stat daemon unless it is required." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000143 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81517
# Group Title: SRG-OS-000480-GPOS-00231
# Rule ID: SV-96231r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000155
# Rule Title: The macOS system firewall must be configured with a default-deny policy.
# 
# Vulnerability Discussion: An approved firewall must be installed and enabled to work in concert with the macOS Application Firewall. When configured correctly, 
# firewalls protect computers from network attacks by blocking or limiting access to open network ports.
# 
# Check Content: 
# Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved firewall is loaded on the system. The recommended system is the McAfee HBSS.
# 
# If no firewall is installed on the system, this is a finding.
# 
# If a firewall is installed and it is not configured with a "default-deny" policy, this is a finding.
# 
# Fix Text: Install an approved HBSS or firewall solution onto the system and configure it with a "default-deny" policy.  
# 
# CCI: CCI-000366
# CCI: CCI-002080
# 
# Verify organizational score
AOSX_13_000155="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000155)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000155" = "1" ]; then
	# If client fails, then note category in audit file
	if [[ -f "/Library/McAfee/agent/bin/cmdagent" ]]; then # Check for the McAfee cmdagent
		/bin/echo $(/bin/date -u) "AOSX_13_000155 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000155 -bool false; else
		/bin/echo "* AOSX_13_000155 The macOS system firewall must be configured with a default-deny policy. – Managed by McAfee EPO. Install McAfee EPO Agent." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000155 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81519
# Group Title: SRG-OS-000023-GPOS-00006
# Rule ID: SV-96233r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000186
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system.
# 
# Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security 
# notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
# 
# System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
# 
# The banner must be formatted in accordance with DTM-08-060.
# 
# Check Content: 
# Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system.
# 
# Check to see if the operating system has the correct text listed in the "/etc/banner" file with the following command:
# 
# # more /etc/banner
# 
# The command should return the following text:
# "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
# 
# By using this IS (which includes any device attached to this IS), you consent to the following conditions:
# 
# -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, 
# network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
# 
# -At any time, the USG may inspect and seize data stored on this IS.
# 
# -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or 
# used for any USG-authorized purpose.
# 
# -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
# 
# -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged 
# communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. 
# Such communications and work product are private and confidential. See User Agreement for details."
# 
# If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
# 
# If the text in the "/etc/banner" file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
# 
# Fix Text: Create a text file containing the required DoD text.
# 
# Name the file "banner" and place it in "/etc/".  
# 
# CCI: CCI-000048
#
# Verify organizational score
AOSX_13_000186="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000186)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000186" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -f "/etc/banner" ]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000186 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000186 -bool false; else
		/bin/echo "* AOSX_13_000186 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000186 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81521
# Group Title: SRG-OS-000023-GPOS-00006
# Rule ID: SV-96235r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000187
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
# 
# Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and 
# security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
# 
# System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
# 
# The banner must be formatted in accordance with DTM-08-060.
# 
# Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007
# 
# Check Content: 
# For systems that allow remote access through SSH, run the following command to verify that "/etc/banner" is displayed before granting access:
# 
# # /usr/bin/grep Banner /etc/ssh/sshd_config
# 
# If the sshd Banner configuration option does not point to "/etc/banner", this is a finding.
# 
# Fix Text: For systems that allow remote access through SSH, modify the "/etc/ssh/sshd_config" file to add or update the following line:
# 
# Banner /etc/banner  
# 
# CCI: CCI-000048
# CCI: CCI-000050
#
# Verify organizational score
AOSX_13_000187="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000187)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000187" = "1" ]; then
	AOSX_13_000187_Audit="$(/usr/bin/grep ^"Banner /etc/banner" /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000187_Audit = "Banner /etc/banner" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000187 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000187 -bool false; else
		/bin/echo "* AOSX_13_000187 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000187 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81523
# Group Title: SRG-OS-000023-GPOS-00006
# Rule ID: SV-96237r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000195
# Rule Title: The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.
# 
# Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security 
# notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
# 
# System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
# 
# The banner must be formatted in accordance with DTM-08-060.
# 
# Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088
# 
# Check Content: 
# The policy banner will show if a "PolicyBanner.rtf" or "PolicyBanner.rtfd" exists in the "/Library/Security" folder. Run this command to show the contents of that folder:
# 
# /bin/ls -l /Library/Security/PolicyBanner.rtf*
# 
# If neither "PolicyBanner.rtf" nor "PolicyBanner.rtfd" exists, this is a finding.
# 
# The banner text of the document MUST read:
# 
# "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any 
# device attached to this IS), you consent to the following conditions:
# -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, 
# network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
# -At any time, the USG may inspect and seize data stored on this IS.
# -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed 
# or used for any USG authorized purpose.
# -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
# -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged 
# communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. 
# Such communications and work product are private and confidential. See User Agreement for details."
# 
# If the text is not worded exactly this way, this is a finding.
# 
# Fix Text: Create an RTF file containing the required text. Name the file "PolicyBanner.rtf" or "PolicyBanner.rtfd" and place it in "/Library/Security/".  
# 
# CCI: CCI-000048
# CCI: CCI-000050
# CCI: CCI-001384
# CCI: CCI-001385
# CCI: CCI-001386
# CCI: CCI-001387
# CCI: CCI-001388
#
# Verify organizational score
AOSX_13_000195="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000195)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000195" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -f "/Library/Security/PolicyBanner."* ]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000195 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000195 -bool false; else
		/bin/echo "* AOSX_13_000195 The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000195 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81525
# Group Title: SRG-OS-000470-GPOS-00214
# Rule ID: SV-96239r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000200
# Rule Title: The macOS system must generate audit records for DoD-defined events such as successful/unsuccessful logon attempts, successful/unsuccessful 
# direct access attempts, starting and ending time for user access, and concurrent logons to the same account from different sources.
# 
# Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it 
# would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
# 
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
# 
# Satisfies: SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Logon events are logged by way of the "aa" flag.
# 
# If "aa" is not listed in the result of the check, this is a finding.
# 
# Fix Text: To ensure the appropriate flags are enabled for auditing, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000172
# 
# Verify organizational score
AOSX_13_000200="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000200)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000200" = "1" ]; then
	AOSX_13_000200_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000200_Audit = *"aa"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000200 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000200 -bool false; else
		/bin/echo "* AOSX_13_000200 Ensure the appropriate flags are enabled for /etc/security/audit_control - aa." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000200 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81527
# Group Title: SRG-OS-000037-GPOS-00015
# Rule ID: SV-96241r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000230
# Rule Title: The macOS system must initiate session audits at system startup, using internal clocks with time stamps for audit records that meet a minimum 
# granularity of one second and can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT), in order to generate audit records containing 
# information to establish what type of events occurred, the identity of any individual or process associated with the event, including individual identities 
# of group account users, establish where the events occurred, source of the event, and outcome of the events including all account enabling actions, 
# full-text recording of privileged commands, and information about the use of encryption for access wireless access to and from the system.
# 
# Vulnerability Discussion: Without establishing what type of events occurred, when they occurred, and by whom it would be difficult to establish, 
# correlate, and investigate the events leading up to an outage or attack.
# 
# Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, 
# user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.
# 
# Associating event types with detected events in the operating system audit logs provides a means of investigating an attack, 
# recognizing resource utilization or capacity thresholds, or identifying an improperly configured operating system.
# 
# Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000040-GPOS-00018, SRG-OS-000041-GPOS-00019, 
# SRG-OS-000042-GPOS-00020, SRG-OS-000042-GPOS-00021, SRG-OS-000055-GPOS-00026, SRG-OS-000254-GPOS-00095, SRG-OS-000255-GPOS-00096, 
# SRG-OS-000255-GPOS-00096, SRG-OS-000299-GPOS-00117, SRG-OS-000303-GPOS-00120, SRG-OS-000358-GPOS-00145, SRG-OS-000359-GPOS-00146
# 
# Check Content: 
# To check if the audit service is running, use the following command:
# 
# /usr/bin/sudo /bin/launchctl list | /usr/bin/grep com.apple.auditd
# 
# If nothing is returned, the audit service is not running, and this is a finding.
# 
# Fix Text: To enable the audit service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist  
# 
# CCI: CCI-000130
# CCI: CCI-000131
# CCI: CCI-000132
# CCI: CCI-000133
# CCI: CCI-000134
# CCI: CCI-000135
# CCI: CCI-000159
# CCI: CCI-001444
# CCI: CCI-001464
# CCI: CCI-001487
# CCI: CCI-001889
# CCI: CCI-001890
# CCI: CCI-002130
#
# Verify organizational score
AOSX_13_000230="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000230)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000230" = "1" ]; then
	AOSX_13_000230_Audit="$(/bin/launchctl list | /usr/bin/grep com.apple.auditd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000230_Audit != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000230 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000230 -bool false; else
		/bin/echo "* AOSX_13_000230 The macOS system must initiate session audits at system startup." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000230 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81529
# Group Title: SRG-OS-000051-GPOS-00024
# Rule ID: SV-96243r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000240
# Rule Title: The macOS system must enable System Integrity Protection.
# 
# Vulnerability Discussion: The System Integrity Protection is vital to prevent unauthorized and unintended information transfer via shared system resources, 
# protect audit tools from unauthorized access, modification, and deletion, limit privileges to change software resident within software libraries, 
# limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.
# 
# SIP also ensures the presence of an audit record generation capability for DoD-defined auditable events for all operating system components, 
# supports on-demand and after-the-fact reporting requirements, does not alter original content or time ordering of audit records.
# 
# Satisfies: SRG-OS-000051-GPOS-00024, SRG-OS-000054-GPOS-00025, SRG-OS-000062-GPOS-00031, SRG-OS-000122-GPOS-00063, SRG-OS-000138-GPOS-00069, SRG-OS-000256-GPOS-00097, 
# SRG-OS-000257-GPOS-00098, SRG-OS-000258-GPOS-00099, SRG-OS-000259-GPOS-00100, SRG-OS-000348-GPOS-00136, SRG-OS-000349-GPOS-00137, SRG-OS-000350-GPOS-00138, 
# SRG-OS-000351-GPOS-00139, SRG-OS-000352-GPOS-00140, SRG-OS-000353-GPOS-00141, SRG-OS-000354-GPOS-00142, SRG-OS-000480-GPOS-00228, SRG-OS-000480-GPOS-00230
# 
# Check Content: 
# System Integrity Protection is a security feature, enabled by default, that protects certain system processes and files 
# from being modified or tampered with. Check the current status of "System Integrity Protection" with the following command:
# 
# /usr/bin/csrutil status
# 
# If the result does not show the following, this is a finding.
# 
# System Integrity Protection status: enabled
# 
# Fix Text: To reenable "System Integrity Protection", boot the affected system into "Recovery" mode, launch "Terminal" 
# from the "Utilities" menu, and run the following command:
# 
# /usr/bin/csrutil enable  
# 
# CCI: CCI-000154
# CCI: CCI-000158
# CCI: CCI-000169
# CCI: CCI-000366
# CCI: CCI-001090
# CCI: CCI-001493
# CCI: CCI-001494
# CCI: CCI-001495
# CCI: CCI-001499
# CCI: CCI-001875
# CCI: CCI-001876
# CCI: CCI-001877
# CCI: CCI-001878
# CCI: CCI-001879
# CCI: CCI-001880
# CCI: CCI-001881
# CCI: CCI-001882
#
# Verify organizational score
AOSX_13_000240="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000240)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000240" = "1" ]; then
	AOSX_13_000240_Audit="$(/usr/bin/csrutil status)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000240_Audit = *"enabled"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000240 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000240 -bool false; else
		/bin/echo "* AOSX_13_000240 The macOS system must enable System Integrity Protection. To reenable System Integrity Protection, boot the affected system into Recovery mode, launch Terminal from the Utilities menu, and run the following command: /usr/bin/csrutil enable" >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000240 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81531
# Group Title: SRG-OS-000341-GPOS-00132
# Rule ID: SV-96245r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000295
# Rule Title: The macOS system must allocate audit record storage capacity to store at least one weeks worth of audit records when audit 
# records are not immediately sent to a central audit record storage facility.
# 
# Vulnerability Discussion: The audit service must be configured to require that records are kept for seven days or longer before deletion 
# when there is no central audit record storage facility. When "expire-after" is set to "7d", the audit service will not delete audit logs 
# until the log data is at least seven days old.
# 
# Check Content: 
# The check displays the amount of time the audit system is configured to retain audit log files. The audit system will not delete logs 
# until the specified condition has been met. To view the current setting, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^expire-after /etc/security/audit_control
# 
# If this returns no results, or does not contain "7d" or a larger value, this is a finding.
# 
# Fix Text: Edit the "/etc/security/audit_control" file and change the value for "expire-after" to the amount of time audit logs should be 
# kept for the system. Use the following command to set the "expire-after" value to "7d":
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-001849
# 
# Verify organizational score
AOSX_13_000295="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000295)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000295" = "1" ]; then
	AOSX_13_000295_Audit="$(/usr/bin/grep ^expire-after /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000295_Audit = *"7d"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000295 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000295 -bool false; else
		/bin/echo "* AOSX_13_000295 Change the value for /etc/security/audit_control - expire-after to 7d." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000295 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81533
# Group Title: SRG-OS-000343-GPOS-00134
# Rule ID: SV-96247r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000305
# Rule Title: The macOS system must provide an immediate warning to the System Administrator (SA) and Information System Security Officer 
# (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.
# 
# Vulnerability Discussion: The audit service must be configured to require a minimum percentage of free disk space in order to run. 
# This ensures that audit will notify the administrator that action is required to free up more disk space for audit logs.
# 
# When "minfree" is set to 25 percent, security personnel are notified immediately when the storage volume is 75 percent full and are able to 
# plan for audit record storage capacity expansion.
# 
# Check Content: 
# The check displays the "% free" to leave available for the system. The audit system will not write logs if the volume has less than this 
# percentage of free disk space. To view the current setting, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^minfree /etc/security/audit_control
# 
# If this returns no results, or does not contain "25", this is a finding.
# 
# Fix Text: Edit the "/etc/security/audit_control" file and change the value for "minfree" to "25" using the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control file".  
# 
# CCI: CCI-001855
# 
# Verify organizational score
AOSX_13_000305="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000305)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000305" = "1" ]; then
	AOSX_13_000305_Audit="$(/usr/bin/grep ^minfree /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000305_Audit = *"25"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000305 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000305 -bool false; else
		/bin/echo "* AOSX_13_000305 Change the value for /etc/security/audit_control - minfree to 25." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000305 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81535
# Group Title: SRG-OS-000344-GPOS-00135
# Rule ID: SV-96249r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000310
# Rule Title: The macOS system must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, of all audit failure events requiring real-time alerts.
# 
# Vulnerability Discussion: The audit service should be configured to immediately print messages to the console or email administrator users when an 
# auditing failure occurs. It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. 
# Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.
# 
# Check Content: 
# By default, "auditd" only logs errors to "syslog". To see if audit has been configured to print error messages to the console, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep logger /etc/security/audit_warn
# 
# If the argument "-s" is missing, or if "audit_warn" has not been otherwise modified to print errors to the console or send email alerts to the SA and ISSO, this is a finding.
# 
# Fix Text: To make "auditd" log errors to standard error as well as "syslogd", run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/bin/sudo /usr/sbin/audit -s  
# 
# CCI: CCI-001858
# 
# Verify organizational score
AOSX_13_000310="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000310)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000310" = "1" ]; then
	AOSX_13_000310_Audit="$(/usr/bin/grep logger /etc/security/audit_warn)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000310_Audit = *"-s"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000310 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000310 -bool false; else
		/bin/echo "* AOSX_13_000310 Change the value for /etc/security/audit_control - logger to -s." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000310 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# UPDATED FOR 10.14
#
# Group ID (Vulid): V-81537
# Group Title: SRG-OS-000355-GPOS-00143
# Rule ID: SV-96251r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000330
# Rule Title: The macOS system must, for networked systems, compare internal information system clocks at least every 24 hours with a server 
# that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the 
# appropriate DoD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).
# 
# Vulnerability Discussion: Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. 
# Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 
# Sources outside of the configured acceptable allowance (drift) may be inaccurate.
# 
# Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks 
# and systems connected over a network.
# 
# Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, 
# and tactical endpoints).
# 
# Satisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000356-GPOS-00144
# 
# Check Content: 
# The Network Time Protocol (NTP) service must be enabled on all networked systems. To check if the service is running, use the following command:
# 
# /usr/bin/sudo /bin/launchctl list | grep org.ntp.ntpd
# 
# If nothing is returned, this is a finding.
# 
# To verify that an authorized NTP server is configured, run the following command or examine "/etc/ntp.conf":
# 
# /usr/bin/sudo /usr/bin/grep ^server /etc/ntp.conf
# 
# Only approved time servers should be configured for use.
# 
# If no server is configured, or if an unapproved time server is in use, this is a finding.
# 
# Fix Text: To enable the NTP service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl load -w /System/Library/LaunchDaemons/org.ntp.ntpd.plist
# 
# To configure one or more time servers for use, edit "/etc/ntp.conf" and enter each hostname or IP address on a separate line, 
# prefixing each one with the keyword "server".  
# 
# CCI: CCI-001891
# CCI: CCI-002046
#
# Verify organizational score
# ALTERNATE - 10.13 and 10.14 uses timed not ntpd. This check works for 10.13 and 10.14.
AOSX_13_000330A="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000330A)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000330A" = "1" ]; then
	AOSX_13_000330A_Audit2="$(/usr/sbin/systemsetup -getusingnetworktime)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000330A_Audit2 = *"On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000330A passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000330A -bool false; else
		/bin/echo "* AOSX_13_000330A The macOS system must compare internal information system clocks at least every 24 with an NTP server. Set usingnetworktime to on." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000330A fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
AOSX_13_000330B="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000330B)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000330B" = "1" ]; then
	AOSX_13_000330B_Audit="$(/usr/bin/grep ^server /etc/ntp.conf)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000330B_Audit != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000330B passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000330B -bool false; else
		/bin/echo "* AOSX_13_000330B The macOS system must compare internal information system clocks at least every 24 with an NTP server. Ensure an authorized NTP server is configured." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000330B fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81539
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96253r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000331
# Rule Title: The macOS system must be configured with audit log files owned by root.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct ownership to prevent regular users from reading 
# audit logs. Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by root or 
# administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the ownership of the audit log files, run the following command:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | grep -v current
# 
# The results should show the owner (third column) to be "root".
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log file that returns an incorrect owner, run the following command:
# 
# /usr/bin/sudo chown root [audit log file]
# 
# [audit log file] is the full path to the log file in question.  
# 
# CCI: CCI-000162
#
# Verify organizational score
AOSX_13_000331="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000331)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000331" = "1" ]; then
	AOSX_13_000331_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep -v root)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000331_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000331 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000331 -bool false; else
		/bin/echo "* AOSX_13_000331 The macOS system must be configured with audit log files owned by root." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000331 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81541
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96255r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000332
# Rule Title: The macOS system must be configured with audit log folders owned by root.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct ownership to prevent regular users from reading 
# audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or 
# administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the ownership of the audit log folder, run the following command:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# The results should show the owner (third column) to be "root".
# 
# If it does not, this is a finding.
# 
# Fix Text: For any log folder that has an incorrect owner, run the following command:
# 
# /usr/bin/sudo chown root [audit log folder]  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_13_000332="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000332)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000332" = "1" ]; then
	AOSX_13_000332_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v root)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000332_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000332 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000332 -bool false; else
		/bin/echo "* AOSX_13_000332 The macOS system must be configured with audit log folders owned by root." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000332 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81543
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96257r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000333
# Rule Title: The macOS system must be configured with audit log files group-owned by wheel.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct group ownership to prevent regular users from 
# reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or 
# administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the group ownership of the audit log files, run the following command:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current
# 
# The results should show the group owner (fourth column) to be "wheel".
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log file that returns an incorrect group owner, run the following command:
# 
# /usr/bin/sudo chgrp wheel [audit log file]
# 
# [audit log file] is the full path to the log file in question.  
# 
# CCI: CCI-000162
#
# Verify organizational score
AOSX_13_000333="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000333)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000333" = "1" ]; then
	AOSX_13_000333_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep -v wheel)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000333_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000333 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000333 -bool false; else
		/bin/echo "* AOSX_13_000333 The macOS system must be configured with audit log files group-owned by wheel." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000333 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81545
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96259r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000334
# Rule Title: The macOS system must be configured with audit log folders group-owned by wheel.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct group ownership to prevent regular users from 
# reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by 
# root or administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the group ownership of the audit log folder, run the following command:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# The results should show the group (fourth column) to be "wheel".
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log folder that has an incorrect group, run the following command:
# 
# /usr/bin/sudo chgrp wheel [audit log folder]  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_13_000334="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000334)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000334" = "1" ]; then
	AOSX_13_000334_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v wheel)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000334_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000334 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000334 -bool false; else
		/bin/echo "* AOSX_13_000334 The macOS system must be configured with audit log folders group-owned by wheel." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000334 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81547
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96261r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000335
# Rule Title: The macOS system must be configured with audit log files set to mode 440 or less permissive.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct permissions to prevent regular users 
# from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable 
# only by root or administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the permissions of the audit log files, run the following command:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current
# 
# The results should show the permissions (first column) to be "440" or less permissive.
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log file that returns an incorrect permission value, run the following command:
# 
# /usr/bin/sudo chmod 440 [audit log file]
# 
# [audit log file] is the full path to the log file in question.  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_13_000335="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000335)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000335" = "1" ]; then
	AOSX_13_000335_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep -v 'r--r-----')"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000335_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000335 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000335 -bool false; else
		/bin/echo "* AOSX_13_000335 The macOS system must be configured with audit log files set to mode 440 or less permissive." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000335 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81549
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96263r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000336
# Rule Title: The macOS system must be configured with audit log folders set to mode 700 or less permissive.
# 
# Vulnerability Discussion: The audit service must be configured to create log folders with the correct permissions to prevent regular users 
# from reading audit logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable 
# only by root or administrative users with sudo, the risk is mitigated.
# 
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029
# 
# Check Content: 
# To check the permissions of the audit log folder, run the following command:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# The results should show the permissions (first column) to be "700" or less permissive.
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log folder that returns an incorrect permission value, run the following command:
# 
# /usr/bin/sudo chmod 700 [audit log folder]  
# 
# CCI: CCI-000162
# CCI: CCI-000163
# CCI: CCI-000164
# 
# Verify organizational score
AOSX_13_000336="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000336)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000336" = "1" ]; then
	AOSX_13_000336_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v 'drwx------')"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000336_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000336 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000336 -bool false; else
		/bin/echo "* AOSX_13_000336 The macOS system must be configured with audit log folders set to mode 700 or less permissive." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000336 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81551
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96265r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000337
# Rule Title: The macOS system must be configured so that log files must not contain access control lists (ACLs).
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct permissions to prevent regular users 
# from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable 
# only by root or administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check if a log file contains ACLs, run the following commands:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current
# 
# In the output from the above commands, ACLs will be listed under any file that may contain them (e.g., "0: group:admin allow list,readattr,reaadextattr,readsecurity").
# 
# If any such line exists, this is a finding.
# 
# Fix Text: For any log file that contains ACLs, run the following command:
# 
# /usr/bin/sudo chmod -N [audit log file]  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_13_000337="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000337)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000337" = "1" ]; then
	AOSX_13_000337_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep '+')"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000337_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000337 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000337 -bool false; else
		/bin/echo "* AOSX_13_000337 The macOS system must be configured so that log files must not contain access control lists (ACLs)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000337 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81553
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-96267r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000338
# Rule Title: The macOS system must be configured so that log folders must not contain access control lists (ACLs).
# 
# Vulnerability Discussion: The audit service must be configured to create log folders with the correct permissions to prevent regular users 
# from reading audit logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable 
# only by root or administrative users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check if a log folder contains ACLs, run the following commands:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# In the output from the above commands, ACLs will be listed under any folder that may contain them (e.g., "0: group:admin allow list,readattr,reaadextattr,readsecurity").
# 
# If any such line exists, this is a finding.
# 
# Fix Text: For any log folder that contains ACLs, run the following command:
# 
# /usr/bin/sudo chmod -N [audit log folder]  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_13_000338="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000338)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000338" = "1" ]; then
	AOSX_13_000338_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep '+')"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000338_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000338 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000338 -bool false; else
		/bin/echo "* AOSX_13_000338 The macOS system must be configured so that log folders must not contain access control lists (ACLs)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000338 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81555
# Group Title: SRG-OS-000366-GPOS-00153
# Rule ID: SV-96269r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000430
# Rule Title: The macOS system must have the security assessment policy subsystem enabled.
# 
# Vulnerability Discussion: Any changes to the hardware, software, and/or firmware components of the information system and/or application can 
# potentially have significant effects on the overall security of the system.
# 
# Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.
# 
# Check Content: 
# To check the status of the Security assessment policy subsystem, run the following command:
# 
# /usr/bin/sudo /usr/sbin/spctl --status | /usr/bin/grep enabled
# 
# If nothing is returned, this is a finding.
# 
# Fix Text: To enable the Security assessment policy subsystem, run the following command:
# 
# /usr/bin/sudo /usr/sbin/spctl --master-enable  
# 
# CCI: CCI-001749
# 
# Verify organizational score
AOSX_13_000430="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000430)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000430" = "1" ]; then
	AOSX_13_000430_Audit="$(/usr/sbin/spctl --status | /usr/bin/grep enabled)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000430_Audit = *"enabled"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000430 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000430 -bool false; else
		/bin/echo "* AOSX_13_000430 The macOS system must have the security assessment policy subsystem enabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000430 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81557
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96271r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000475
# Rule Title: The macOS system must be configured to disable the application FaceTime.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by 
# default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not 
# related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application FaceTime establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if there is a configuration policy defined for "Application Restrictions", run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "FaceTime"
# 
# If the result does not contain "/Applications/FaceTime.app", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app/"
# Verify organizational score
AOSX_13_000475="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000475)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000475" = "1" ]; then
	AOSX_13_000475_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep 'FaceTime.app')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000475_Audit" = *"/Applications/FaceTime.app"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000475 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000475 -bool false; else
		/bin/echo "* AOSX_13_000475 The macOS system must be configured to disable the application FaceTime via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000475 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81559
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96273r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000490
# Rule Title: The macOS system must be configured to disable the application Messages.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by 
# default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not 
# related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Messages establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if there is a configuration policy defined for "Application Restrictions", run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "Messages.app"
# 
# If the result does not contain "/Applications/Messages.app", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Messages.app/"
# Verify organizational score
AOSX_13_000490="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000490)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000490" = "1" ]; then
	AOSX_13_000490_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep 'Messages.app')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000490_Audit" = *"/Applications/Messages.app"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000490 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000490 -bool false; else
		/bin/echo "* AOSX_13_000490 The macOS system must be configured to disable the application Messages via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000490 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81561
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96275r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000505
# Rule Title: The macOS system must be configured to disable the iCloud Calendar services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by 
# default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Calendar establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Calendar is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudCalendar
# 
# If the result is not “allowCloudCalendar = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
# Verify organizational score
AOSX_13_000505="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000505)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000505" = "1" ]; then
	AOSX_13_000505_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudCalendar = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000505_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000505 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000505 -bool false; else
		/bin/echo "* AOSX_13_000505 The macOS system must be configured to disable the iCloud Calendar services via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000505 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81563
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96277r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000507
# Rule Title: The macOS system must be configured to disable the iCloud Reminders services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by 
# default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Reminders establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Reminders is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudReminders
# 
# If the result is not “allowCloudReminders = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
# Verify organizational score
AOSX_13_000507="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000507)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000507" = "1" ]; then
	AOSX_13_000507_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudReminders = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000507_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000507 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000507 -bool false; else
		/bin/echo "* AOSX_13_000507 The macOS system must be configured to disable the iCloud Reminders services via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000507 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81565
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96279r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000510
# Rule Title: The macOS system must be configured to disable iCloud Address Book services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by 
# default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Address Book establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Address Book is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudAddressBook
# 
# If the result is not “allowCloudAddressBook = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
# Verify organizational score
AOSX_13_000510="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000510)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000510" = "1" ]; then
	AOSX_13_000510_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudAddressBook = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000510_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000510 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000510 -bool false; else
		/bin/echo "* AOSX_13_000510 The macOS system must be configured to disable iCloud Address Book services via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000510 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81567
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96281r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000515
# Rule Title: The macOS system must be configured to disable the iCloud Mail services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided 
# by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Mail establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Mail is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudMail
# 
# If the result is not “allowCloudMail = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
# Verify organizational score
AOSX_13_000515="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000515)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000515" = "1" ]; then
	AOSX_13_000515_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudMail = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000515_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000515 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000515 -bool false; else
		/bin/echo "* AOSX_13_000515 The macOS system must be configured to disable the iCloud Mail services via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000515 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81569
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96283r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000517
# Rule Title: The macOS system must be configured to disable the iCloud Notes services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided 
# by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Notes establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Notes is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudNotes
# 
# If the result is not “allowCloudNotes = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
# Verify organizational score
AOSX_13_000517="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000517)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000517" = "1" ]; then
	AOSX_13_000517_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudNotes = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000517_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000517 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000517 -bool false; else
		/bin/echo "* AOSX_13_000517 The macOS system must be configured to disable the iCloud Notes services via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000517 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81571
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96285r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000518
# Rule Title: The macOS system must be configured to disable the camera.
# 
### This is the wrong Vulnerability Discussion. This is for AOSX_13_000520. This is just a typo in the STIG. The Check Content is correct. ###
#
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided 
# by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system preference panel's iCloud and Internet Accounts must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if the system has been configured to disable the camera, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCamera
# 
# If the result is not “allowCamera = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow use of Camera (unchecked)
# Verify organizational score
AOSX_13_000518="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000518)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000518" = "1" ]; then
	AOSX_13_000518_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCamera = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000518_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000518 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000518 -bool false; else
		/bin/echo "* AOSX_13_000518 The macOS system must be configured to disable the camera via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000518 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81573
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96287r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000520
# Rule Title: The macOS system must be configured to disable the system preference pane for iCloud.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, 
# provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software 
# not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system preference panes for iCloud and Internet Accounts must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if the system has the correct setting in the configuration profile to disable access to the iCloud preference pane, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 DisabledPreferencePanes | grep icloud
# 
# If the return is not “com.apple.preferences.icloud”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Preferences > disable selected items "iCloud"
# Verify organizational score
AOSX_13_000520="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000520)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000520" = "1" ]; then
	AOSX_13_000520_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 15 DisabledPreferencePanes | grep 'icloud')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000520_Audit" = *"com.apple.preferences.icloud"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000520 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000520 -bool false; else
		/bin/echo "* AOSX_13_000520 The macOS system must be configured to disable the system preference pane for iCloud via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000520 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81575
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96289r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000521
# Rule Title: The macOS system must be configured to disable the system preference pane for Internet Accounts.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, 
# may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not 
# related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system preference panes for iCloud and Internet Accounts must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if "Internet Accounts" has been disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 DisabledPreferencePanes | grep internetaccounts
# 
# If the return is not "com.apple.preferences.internetaccounts", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Preferences > disable selected items "Internet Accounts"
# Verify organizational score
AOSX_13_000521="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000521)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000521" = "1" ]; then
	AOSX_13_000521_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 15 DisabledPreferencePanes | grep 'internetaccounts')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000521_Audit" = *"com.apple.preferences.internetaccounts"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000521 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000521 -bool false; else
		/bin/echo "* AOSX_13_000521 The macOS system must be configured to disable the system preference pane for Internet Accounts via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000521 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81577
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96291r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000522
# Rule Title: The macOS system must be configured to disable the system preference pane for Siri.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by 
# default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not 
# related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system preference panes for Siri and dictation must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if "Siri" has been disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 DisabledPreferencePanes | grep speech
# 
# If the return is not “com.apple.preference.speech”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Preferences > disable selected items "Dictation & Speech"
# Verify organizational score
AOSX_13_000522="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000522)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000522" = "1" ]; then
	AOSX_13_000522_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 15 DisabledPreferencePanes | grep 'speech')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000522_Audit" = *"com.apple.preference.speech"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000522 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000522 -bool false; else
		/bin/echo "* AOSX_13_000522 The macOS system must be configured to disable the system preference pane for Siri via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000522 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81579
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96293r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000523
# Rule Title: The macOS system must be configured to disable Siri and dictation.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, 
# may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related 
# to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system preference panes for Siri and dictation must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if Siri and dictation has been disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(allowAssistant | IronwoodAllowed)'
# 
# If the return is null or not:
# “IronwoodAllowed = 0
# allowAssistant = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
# Configuration Profile - Custom payload > com.apple.assistant.support > allowAssistant=false
# Verify organizational score
AOSX_13_000523="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000523)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000523" = "1" ]; then
	AOSX_13_000523_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(allowAssistant | IronwoodAllowed)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000523_Audit" = *"IronwoodAllowed = 0"* ]] && [[ "$AOSX_13_000523_Audit" = *"allowAssistant = 0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000523 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000523 -bool false; else
		/bin/echo "* AOSX_13_000523 The macOS system must be configured to disable Siri and dictation via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000523 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81599
# Group Title:  SRG-OS-000096-GPOS-00050
# Rule ID:  SV-96313r1_rule
# Severity: CAT II
# Rule Version (STIG-ID):  AOSX_13_000530
# Rule Title: The macOS system must be configured to disable sending diagnostic and usage data to Apple.
# 
# Vulnerability Discussion:  To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by 
# default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services
# from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality of life issues.
# 
# Sending diagnostic and usage data to Apple must be disabled.
# 
# Check Content:  
# Sending diagnostic and usage data to Apple must be disabled.
# 
# To check if a configuration profile is configured to enforce this setting, run the following command:
# 
# /usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowDiagnosticSubmission
# 
# If "allowDiagnosticSubmission" is not set to "0", this is a finding.
# 
# Alternately, the setting is found in System Preferences >> Security & Privacy >> Privacy >> Analytics.
# 
# If the box that says "Share Mac Analytics" is checked, this is a finding.
# 
# Fix Text: This setting is enforced using the "Security and Privacy Policy" configuration profile.
# 
# The setting "Share Mac Analytics" is found in System Preferences >> Security & Privacy >> Privacy >> Analytics.
# 
# Uncheck the box that says "Share Mac Analytics"
# 
# To apply the setting from the command line, run the following commands:
# 
# /usr/bin/defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit
# /usr/bin/sudo /usr/bin/defaults write "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit -bool false
# /usr/bin/sudo /bin/chmod 644 /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist
# /usr/bin/sudo /usr/bin/chgrp admin /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist   
# 
# CCI: CCI-000382
#
# Configuration Profile - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
# Verify organizational score
AOSX_13_000530="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000530)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000530" = "1" ]; then
	AOSX_13_000530_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowDiagnosticSubmission = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000530_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000530 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000530 -bool false; else
		/bin/echo "* AOSX_13_000530 The macOS system must be configured to disable sending diagnostic and usage data to Apple via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000530 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81601
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96315r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000531
# Rule Title: The macOS system must be configured to disable the iCloud Find My Mac service.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by 
# default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple 
# services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality-of-life issues.
# 
# Find My Mac must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if Find My Mac is disabled, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudFMM
# 
# If the return is null or not “allowCloudFMM = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Find My Mac (unchecked)
# Verify organizational score
AOSX_13_000531="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000531)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000531" = "1" ]; then
	AOSX_13_000531_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudFMM = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000531_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000531 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000531 -bool false; else
		/bin/echo "* AOSX_13_000531 The macOS system must be configured to disable the iCloud Find My Mac service via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000531 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81603
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96317r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000535
# Rule Title: The macOS system must be configured to disable Location Services.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by
# default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide 
# multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality-of-life issues.
# 
# Location Services must be disabled.
# 
# Check Content: 
# Location Services must be disabled. To check if a configuration profile is configured to enforce this setting, run the following command:
# 
# /usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableLocationServices
# 
# If the return is null or not “DisableLocationServices = 1”, this is a finding.
# 
# The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services.
# 
# If the box that says "Enable Location Services" is checked, this is a finding.
# 
# To check if the setting was applied on the command line, run the following command:
# 
# /usr/bin/sudo /usr/bin/defaults read /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57` LocationServicesEnabled
# 
# If the result is "1" this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.
# 
# The setting "Enable Location Services" can be found in System Preferences >> Security & Privacy >> Privacy >> Location Services. 
# Uncheck the box that says "Enable Location Services".
# 
# It can also be set with the following command:
# 
# /usr/bin/sudo /usr/bin/defaults write /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57` LocationServicesEnabled -bool false  
# 
# CCI: CCI-000381
#
# Configuration Profile - Custom payload > com.apple.MCX > DisableLocationServices=true
# Verify organizational score
AOSX_13_000535="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000535)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000535" = "1" ]; then
	AOSX_13_000535_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableLocationServices = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000535_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000535 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000535 -bool false; else
		/bin/echo "* AOSX_13_000535 The macOS system must be configured to disable Location Services via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000535 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81605
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96319r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000545
# Rule Title: The macOS system must be configured to disable Bonjour multicast advertising.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by 
# default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple 
# services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality of life issues.
# 
# Bonjour multicast advertising must be disabled on the system.
# 
# Check Content: 
# To check if Bonjour multicast advertising has been disabled, run the following command:
# 
# /usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.mDNSResponder | /usr/bin/grep NoMulticastAdvertisements
# 
# If an error is returned, nothing is returned, or "NoMulticastAdvertisements" is not set to "1", this is a finding.
# 
# Fix Text: To configure Bonjour to disable multicast advertising, run the following command:
# 
# /usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true
# 
# The system will need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_13_000545="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000545)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000545" = "1" ]; then
	AOSX_13_000545_Audit="$(/usr/bin/defaults read /Library/Preferences/com.apple.mDNSResponder 2>/dev/null | /usr/bin/grep -c 'NoMulticastAdvertisements = 1')"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000545_Audit > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000545 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000545 -bool false; else
		/bin/echo "* AOSX_13_000545 The macOS system must be configured to disable Bonjour multicast advertising." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000545 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81607
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96321r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000550
# Rule Title: The macOS system must be configured to disable the UUCP service.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements 
# or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, 
# may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not 
# related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system must not have the UUCP service active.
# 
# Check Content: 
# To check if the UUCP service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.uucp
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.uucp" => true
# 
# Fix Text: To disable the UUCP service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.uucp
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_13_000550="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000550)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000550" = "1" ]; then
	AOSX_13_000550_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.uucp)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000550_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000550 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000550 -bool false; else
		/bin/echo "* AOSX_13_000550 The macOS system must be configured to disable the UUCP service." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000550 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81609
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96323r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000551
# Rule Title: The macOS system must disable the Touch ID feature.
# 
# Vulnerability Discussion: The Touch ID feature permits users to add additional fingerprints to unlock the host. 
# These fingerprints may be for the user or anyone else. Because unauthorized users may gain access to the system, the use of Touch ID must be limited.
# 
# Check Content: 
# To view the setting for Touch ID configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowFingerprintForUnlock
# 
# If the output is null, not "allowFingerprintForUnlock = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Restrictions payload > Functionality > Allow Touch ID to unlock device (unchecked)
# Verify organizational score
AOSX_13_000551="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000551)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000551" = "1" ]; then
	AOSX_13_000551_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowFingerprintForUnlock = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000551_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000551 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000551 -bool false; else
		/bin/echo "* AOSX_13_000551 The macOS system must disable the Touch ID feature via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000551 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81611
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96325r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000552
# Rule Title: The macOS system must obtain updates from a DoD-approved update server.
# 
# Vulnerability Discussion: Software update configuration. Point to DOD approved update server. Configure for automatic install of critical updates.
# 
# NOTE:Per Apple OS X 10.13 (High Sierra) Security Technical Implementation Guide (STIG)
# Overview 4. GENERAL SECURITY REQUIREMENTS 4.1 Software Updates
# This STIG requires that all updates come from an approved source. Apple is considered a DoD-approved source.
#
# Check Content: 
# To check if the CatalogURL is configured, run the following command:
# 
# defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL
# 
# 2017-11-30 22:21:41.805 defaults[1205:9595]
# 
# The domain/default pair of (/Library/Preferences/com.apple.SoftwareUpdate.plist, CatalogURL) does not exist.
# 
# If the output is not an error indicating the item "does not exist" or the output is not a DoD-approved update server, this is a finding.
# 
# Note: Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).
# 
# Fix Text: To remove the Apple software list from the system configuration run the following command:
# 
# sudo defaults delete /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_000552="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000552)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000552" = "1" ]; then
	AOSX_13_000552_Audit="$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL 2>/dev/null)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000552_Audit" = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000552 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000552 -bool false; else
		/bin/echo "* AOSX_13_000552 The macOS system must obtain updates from a DoD-approved update server. Apple is considered a DoD-approved source." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000552 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81613
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96327r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000553
# Rule Title: The macOS system must not have a root account.
# 
# Vulnerability Discussion: To assure individual accountability and prevent unauthorized access, organizational users must be 
# individually identified and authenticated.
# 
# Check Content: 
# To check if the root account is disabled, run the following command:
# 
# defaults read /var/db/dslocal/nodes/Default/users/root.plist passwd
# (
# "*"
# )
# 
# The output should be a single asterisk in quotes, as seen above. If the output is as follow, this is a finding:
# 
# (
# "********"
# )
# 
# Fix Text: Disable the root account with the following command:
# 
# /usr/sbin/dsenableroot -d  
# 
# CCI: CCI-000366
#
# The dsenableroot command is interactive and requires password entry. It is not ideal for a script.
# Optionally (not STIG approved) – /usr/bin/dscl . -create /Users/root UserShell /usr/bin/false
#
# Verify organizational score
AOSX_13_000553="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000553)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000553" = "1" ]; then
	AOSX_13_000553_Audit="$(/usr/bin/defaults read /var/db/dslocal/nodes/Default/users/root.plist passwd | /usr/bin/grep -F '"********"' )"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000553_Audit" = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000553 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000553 -bool false; else
		/bin/echo "* AOSX_13_000553 The macOS system must not have a root account. Disable root manually using the command: dsenableroot -d" >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000553 fix – Disable root manually using the command: dsenableroot -d" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81615
# Group Title: SRG-OS-000364-GPOS-00151
# Rule ID: SV-96329r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000554
# Rule Title: The macOS system must not have a guest account.
# 
# Vulnerability Discussion: Only authorized individuals should be allowed to obtain access to operating system components. 
# Permitting access via a guest account provides unauthenticated access to any person.
# 
# Check Content: 
# To check if the guest user exists, run the following command:
# 
# dscl . list /Users | grep -i Guest
# 
# To verify that Guest user cannot unlock volume, run the following command:
# 
# fdesetup list
# 
# To check if the system is configured to prohibit user installation of software, first check to ensure the Parental Controls are enabled with the following command:
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(DisableGuestAccount | EnableGuestAccount)’
# 
# If the result is null or not:
# DisableGuestAccount = 1;
# EnableGuestAccount = 0;
# This is a finding.
# 
# Fix Text: Remove the guest user with the following command:
# 
# sudo dscl . delete /Users/Guest
# 
# "This can also be managed with "Login Window Policy" configuration profile.  
# 
# CCI: CCI-001813
#
# Configuration Profile - Login Window payload > Options > Allow Guest User (unchecked)
# Verify organizational score
AOSX_13_000554="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000554)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000554" = "1" ]; then
	AOSX_13_000554_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(DisableGuestAccount | EnableGuestAccount)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000554_Audit" = *"DisableGuestAccount = 1"* ]] && [[ "$AOSX_13_000554_Audit" = *"EnableGuestAccount = 0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000554 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000554 -bool false; else
		/bin/echo "* AOSX_13_000554 The macOS system must not have a guest account via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000554 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81617
# Group Title: SRG-OS-000074-GPOS-00042
# Rule ID: SV-96331r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000555
# Rule Title: The macOS system must unload tftpd.
# 
# Vulnerability Discussion: The "tftp" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. 
# The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit.
# 
# If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. 
# Disabling ftp is one way to mitigate this risk. Administrators should be instructed to use an alternate service for data 
# transmission that uses encryption, such as SFTP.
# 
# Additionally, the "tftp" service uses UDP, which is not secure.
# 
# Check Content: 
# To check if the "tfptd" service is disabled, run the following command:
# 
# sudo launchctl print-disabled system | grep tftp
# 
# If "com.apple.tftp" is not set to "true", this is a finding.
# 
# Fix Text: To disable the "tfpd" service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl unload -w /System/Library/LaunchDaemons/tftp.plist
# /usr/bin/sudo /bin/launchctl disable system/com.apple.tftp 
#
# CCI: CCI-000197
# 
# Verify organizational score
AOSX_13_000555="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000555)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000555" = "1" ]; then
	AOSX_13_000555_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.tftp)"
	AOSX_13_000555_Audit2="$(/bin/launchctl list | /usr/bin/grep com.apple.tftpd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000555_Audit1 = *"true"* ]] && [[ $AOSX_13_000555_Audit2 != *"com.apple.tftp"* ]] ; then
		/bin/echo $(/bin/date -u) "AOSX_13_000555 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000555 -bool false; else
		/bin/echo "* AOSX_13_000555 The macOS system must unload tftpd." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000555 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81619
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96333r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000556
# Rule Title: The macOS system must disable Siri pop-ups.
# 
# Vulnerability Discussion: Users (and any processes acting on behalf of users) need to be uniquely identified and 
# authenticated for all accesses other than those accesses explicitly identified and documented by the organization, 
# which outlines specific user actions that can be performed on the Ubuntu operating system without identification or authentication.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if the "SkipSiriSetup" prompt is enabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipSiriSetup
# 
# If the output is null or "SkipSiriSetup" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
# Verify organizational score
AOSX_13_000556="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000556)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000556" = "1" ]; then
	AOSX_13_000556_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipSiriSetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000556_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000556 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000556 -bool false; else
		/bin/echo "* AOSX_13_000556 The macOS system must disable Siri pop-ups via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000556 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81621
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96335r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000557
# Rule Title: The macOS system must disable iCloud Back to My Mac feature.
# 
# Vulnerability Discussion: The Back to My Mac is an iCloud feature permitting users to connect to a Mac, AirPort Disk, 
# or Time Capsule using another Mac or another Internet connected device. When connected users can transfer data and 
# see a live version of the screen content.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the Back to My Mac configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudBTMM
# 
# If the output is null or not "allowCloudBTMM = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Back to My Mac (unchecked)
# Verify organizational score
AOSX_13_000557="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000557)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000557" = "1" ]; then
	AOSX_13_000557_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudBTMM = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000557_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000557 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000557 -bool false; else
		/bin/echo "* AOSX_13_000557 The macOS system must disable iCloud Back to My Mac feature via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000557 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81623
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96337r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000558
# Rule Title: The macOS system must disable iCloud Keychain synchronization.
# 
# Vulnerability Discussion: Requiring individuals to be authenticated with an individual authenticator prior to using a group 
# authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions 
# that can be taken with group account knowledge.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Keychain Synchronization configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudKeychainSync
# 
# If the output is null or not "allowCloudKeychainSync = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
# Verify organizational score
AOSX_13_000558="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000558)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000558" = "1" ]; then
	AOSX_13_000558_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudKeychainSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000558_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000558 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000558 -bool false; else
		/bin/echo "* AOSX_13_000558 The macOS system must disable iCloud Keychain synchronization via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000558 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81625
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96339r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000559
# Rule Title: The macOS system must disable iCloud document synchronization.
# 
# Vulnerability Discussion: Operating systems are capable of providing a wide variety of functions and services. 
# Some of the functions and services provided by default may not be necessary to support essential organizational operations. 
# Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, 
# doing so increases risk over limiting the services provided by any one component.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Document Synchronization configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDocumentSync
# 
# If the output is null or not "allowCloudDocumentSync = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
# Verify organizational score
AOSX_13_000559="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000559)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000559" = "1" ]; then
	AOSX_13_000559_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDocumentSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000559_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000559 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000559 -bool false; else
		/bin/echo "* AOSX_13_000559 The macOS system must disable iCloud document synchronization via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000559 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81627
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96341r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000560
# Rule Title: The macOS system must disable iCloud bookmark synchronization.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized 
# tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary 
# physical and logical ports/protocols on information systems.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Bookmark Synchronization configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudBookmarks
# 
# If the output is null or not "allowCloudBookmarks = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
# Verify organizational score
AOSX_13_000560="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000560)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000560" = "1" ]; then
	AOSX_13_000560_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudBookmarks = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000560_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000560 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000560 -bool false; else
		/bin/echo "* AOSX_13_000560 The macOS system must disable iCloud bookmark synchronization via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000560 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81629
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96343r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000561
# Rule Title: The macOS system must disable iCloud Photo Library.
# 
# Vulnerability Discussion: To support the requirements and principles of least functionality, the operating system must support the 
# organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to 
# only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Photo Library configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudPhotoLibrary
# 
# If the output is null or not "allowCloudPhotoLibrary = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
# Verify organizational score
AOSX_13_000561="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000561)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000561" = "1" ]; then
	AOSX_13_000561_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudPhotoLibrary = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000561_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000561 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000561 -bool false; else
		/bin/echo "* AOSX_13_000561 The macOS system must disable iCloud Photo Library via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000561 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81631
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96345r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000562
# Rule Title: The macOS system must disable iCloud Desktop And Documents.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Desktop And Documents configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDesktopAndDocuments
# 
# If the output is null or not "allowCloudDesktopAndDocuments = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive > Desktop & Documents (unchecked)
# Verify organizational score
AOSX_13_000562="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000562)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000562" = "1" ]; then
	AOSX_13_000562_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000562_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000562 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000562 -bool false; else
		/bin/echo "* AOSX_13_000562 The macOS system must disable iCloud Desktop And Documents via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000562 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81633
# Group Title: SRG-OS-000109-GPOS-00056
# Rule ID: SV-96347r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000565
# Rule Title: The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
# 
# Vulnerability Discussion: Administrators must never log in directly as root. To assure individual accountability and prevent unauthorized access, 
# logging in as root over a remote connection must be disabled. Administrators should only run commands as root after first authenticating 
# with their individual user names and passwords.
# 
# Check Content: 
# To check if SSH has root logins enabled, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config
# 
# If there is no result, or the result is set to "yes", this is a finding.
# 
# Fix Text: To ensure that "PermitRootLogin" is disabled by sshd, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config  
# 
# CCI: CCI-000770
#
# Verify organizational score
AOSX_13_000565="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000565)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000565" = "1" ]; then
	AOSX_13_000565_Audit="$(/usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000565_Audit" = "PermitRootLogin no" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000565 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000565 -bool false; else
		/bin/echo "* AOSX_13_000565 The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000565 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81635
# Group Title: SRG-OS-000112-GPOS-00057
# Rule ID: SV-96349r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000570
# Rule Title: The macOS system must implement NSA-approved cryptography to protect classified information in accordance with applicable 
# federal laws, Executive Orders, directives, policies, regulations, and standards.
# 
# Vulnerability Discussion: Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. 
# The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since 
# this provides assurance they have been tested and validated.
# 
# Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058, SRG-OS-000396-GPOS-00176
# 
# Check Content: 
# To check which protocol is configured for sshd, run the following:
# 
# /usr/bin/sudo /usr/bin/grep ^Protocol /etc/ssh/sshd_config
# 
# If there is no result or the result is not "Protocol 2", this is a finding.
# 
# Fix Text: To ensure that "Protocol 2" is used by sshd, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001941
# CCI: CCI-001942
# CCI: CCI-002450
#
# Verify organizational score
AOSX_13_000570="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000570)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000570" = "1" ]; then
	AOSX_13_000570_Audit="$(/usr/bin/grep ^Protocol /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000570_Audit" = "Protocol 2" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000570 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000570 -bool false; else
		/bin/echo "* AOSX_13_000570 The macOS system must implement NSA-approved cryptography to protect classified information..." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000570 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81637
# Group Title: SRG-OS-000071-GPOS-00039
# Rule ID: SV-96351r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000585
# Rule Title: The macOS system must enforce password complexity by requiring that at least one numeric character be used.
# 
# 
# Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. 
# Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
# Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, 
# the greater the number of possible combinations that need to be tested before the password is compromised.
# 
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, 
# run the following command to check if the system is configured to require that passwords contain at least one numeric character:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep requireAlphanumeric
# 
# If the result is null or is not “requireAlphanumeric = 1”, this is a finding.
# 
# If password policy is set with the "pwpolicy utility", run the following command instead:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryPasswordContent</key>".
# 
# If it does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# Otherwise, in the array section that follows it, there should be a <dict> section that contains a check <string> that "matches" the 
# variable "policyAttributePassword" to the regular expression "(.*[0-9].*){1,}+" or to a similar expression that will ensure 
# the password contains a character in the range 0-9 one or more times.
# 
# If this check allows users to create passwords without at least one numeric character, or if no such check exists, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor.
# 
# If the file does not yet contain any policy settings, replace <dict/> with <dict></dict>; then insert the following text after 
# the opening <dict> tag and before the closing </dict> tag.
# 
# The same text can also be used if the line "<key>policyCategoryPasswordContent</key>" is not present.
# 
# <key>policyCategoryPasswordContent</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
# <key>policyIdentifier</key>
# <string>com.apple.policy.legacy.requiresNumeric</string>
# <key>policyParameters</key>
# <dict>
# <key>minimumNumericCharacters</key>
# <integer>1</integer>
# </dict>
# </dict>
# </array>
# 
# If the file does contain policy settings, and the line "<key>policyCategoryPasswordContent</key>" does exist, insert the following 
# text after the opening <array> tag that comes right after it:
# 
# <dict>
# <key>policyContent</key>
# <string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
# <key>policyIdentifier</key>
# <string>com.apple.policy.legacy.requiresNumeric</string>
# <key>policyParameters</key>
# <dict>
# <key>minimumNumericCharacters</key>
# <integer>1</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password 
# change and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-000194
#
# Configuration Profile - Passcode payload > Require alphanumeric value (checked)
# Verify organizational score
AOSX_13_000585="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000585)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000585" = "1" ]; then
	AOSX_13_000585_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'requireAlphanumeric = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000585_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000585 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000585 -bool false; else
		/bin/echo "* AOSX_13_000585 The macOS system must enforce password complexity by requiring that at least one numeric character be used via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000585 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81639
# Group Title: SRG-OS-000266-GPOS-00101
# Rule ID: SV-96353r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000587
# Rule Title: The macOS system must enforce password complexity by requiring that at least one special character be used.
# 
# Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. 
# Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
# Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number 
# of possible combinations that need to be tested before the password is compromised. Special characters are those characters that are not alphanumeric. 
# Examples include: ~ ! @ # $ % ^ *.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, 
# run the following command to check if the system is configured to require that passwords contain at least one special character:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minComplexChars
# 
# If the return is null or not ” minComplexChars = 1”, this is a finding.
# 
# Run the following command to check if the system is configured to require that passwords not contain repeated sequential characters or 
# characters in increasing and decreasing sequential order:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowSimple
# 
# If "allowSimple" is not set to "0" or is undefined, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.  
# 
# CCI: CCI-001619
#
# Configuration Profile - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
# Configuration Profile - Passcode payload > Allow simple value (unchecked)
# Verify organizational score
AOSX_13_000587="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000587)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000587" = "1" ]; then
	AOSX_13_000587_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minComplexChars | /usr/bin/awk '{print $3-0}')"
	AOSX_13_000587_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowSimple = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000587_Audit1" -ge "1" ]] && [[ "$AOSX_13_000587_Audit2" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000587 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000587 -bool false; else
		/bin/echo "* AOSX_13_000587 The macOS system must enforce password complexity by requiring that at least one special character be used via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000587 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81641
# Group Title: SRG-OS-000078-GPOS-00046
# Rule ID: SV-96355r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000590
# Rule Title: The macOS system must enforce a minimum 15-character password length.
# 
# Vulnerability Discussion: The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the 
# effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps 
# to determine strength and how long it takes to crack a password. The use of more characters in a password helps to exponentially increase 
# the time and/or resources required to compromise the password.
# 
# Check Content: 
# To check the currently applied policies for passwords and accounts, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength
# 
# If the return is null or not “minLength = 15”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Passcode Policy" configuration profile.
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and 
# local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-000205
#
# Configuration Profile - Passcode payload > MINIMUM PASSCODE LENGTH 15
# Verify organizational score
AOSX_13_000590="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000590)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000590" = "1" ]; then
	AOSX_13_000590_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength | /usr/bin/awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000590_Audit" -ge "15" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000590 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000590 -bool false; else
		/bin/echo "* AOSX_13_000590 The macOS system must enforce a minimum 15-character password length via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000590 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81643
# Group Title: SRG-OS-000074-GPOS-00042
# Rule ID: SV-96357r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000605
# Rule Title: The macOS system must not use telnet.
# 
# Vulnerability Discussion: The "telnet" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. 
# The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit.
# 
# If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling telnet is one way 
# to mitigate this risk. Administrators should be instructed to use an alternate service for remote access sessions, non-local maintenance sessions, 
# and diagnostic communications that uses encryption, such as SSH.
# 
# Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
# 
# Check Content: 
# To check if the "telnet" service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.telnetd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.telnetd" => true
# 
# Fix Text: To disable the "telnet" service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.telnetd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000197
# CCI: CCI-000877
# CCI: CCI-001453
# CCI: CCI-002890
# CCI: CCI-003123
# 
# Verify organizational score
AOSX_13_000605="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000605)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000605" = "1" ]; then
	AOSX_13_000605_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.telnetd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000605_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000605 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000605 -bool false; else
		/bin/echo "* AOSX_13_000605 The macOS system must not use telnet." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000605 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81645
# Group Title: SRG-OS-000074-GPOS-00042
# Rule ID: SV-96359r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000606
# Rule Title: The macOS system must not use unencrypted FTP.
# 
# Vulnerability Discussion: The "ftp" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. 
# The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit.
# 
# If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling ftp is one way to 
# mitigate this risk. Administrators should be instructed to use an alternate service for data transmission that uses encryption, such as SFTP.
# 
# Check Content: 
# To check if the "ftp" service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.ftpd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.ftpd" => true
# 
# Fix Text: To disable the "ftp" service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.ftpd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000197
# 
# Verify organizational score
AOSX_13_000606="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000606)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000606" = "1" ]; then
	AOSX_13_000606_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.ftpd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000606_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000606 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000606 -bool false; else
		/bin/echo "* AOSX_13_000606 The macOS system must not use unencrypted FTP." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000606 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81647
# Group Title: SRG-OS-000366-GPOS-00153
# Rule ID: SV-96361r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000710
# Rule Title: The macOS system must allow only applications downloaded from the App Store to run.
# 
# Vulnerability Discussion: Gatekeeper settings must be configured correctly to only allow the system to run applications downloaded from the 
# Mac App Store or applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these 
# settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate 
# in order to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.
# 
# Check Content: 
# To verify only applications downloaded from the App Store are allowed to run, type the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(EnableAssessment | AllowIdentifiedDevelopers)’
# 
# If the return is null, or is not:
# AllowIdentifiedDevelopers = 1;
# EnableAssessment = 1;
# This is a finding.
# 
# Fix Text: This setting is enforced using the "Security and Privacy Policy" configuration profile.  
# 
# CCI: CCI-001749
#
# Configuration Profile - Security & Privacy payload > General > Mac App Store and identified developers (selected)
# Verify organizational score
AOSX_13_000710="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000710)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000710" = "1" ]; then
	AOSX_13_000710_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(AllowIdentifiedDevelopers | EnableAssessment)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000710_Audit" = *"AllowIdentifiedDevelopers = 1"* ]] && [[ "$AOSX_13_000710_Audit" = *"EnableAssessment = 1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000710 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000710 -bool false; else
		/bin/echo "* AOSX_13_000710 The macOS system must allow only applications downloaded from the App Store to run via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000710 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81649
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96363r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000711
# Rule Title: The macOS system must be configured so that end users cannot override Gatekeeper settings.
# 
# Vulnerability Discussion: Gatekeeper must be configured with a configuration profile to prevent regular users from overriding its setting. 
# If regular users are allowed to disable Gatekeeper or set it to a less restrictive setting, malware could be introduced into the system. 
# Gatekeeper is a security feature that ensures applications must be digitally signed by an Apple-issued certificate in order to run. 
# Digital signatures allow the macOS host to verify the application has not been modified by a malicious third party.
# 
# Check Content: 
# To verify the regular user cannot override Gatekeeper settings, type the following code:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableOverride
# 
# If "DisableOverride" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Security and Privacy Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
# Verify organizational score
AOSX_13_000711="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000711)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000711" = "1" ]; then
	AOSX_13_000711_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableOverride = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000711_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000711 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000711 -bool false; else
		/bin/echo "* AOSX_13_000711 The macOS system must be configured so that end users cannot override Gatekeeper settings via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000711 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81651
# Group Title: SRG-OS-000163-GPOS-00072
# Rule ID: SV-96365r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000720
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.
# 
# Vulnerability Discussion: SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds 
# before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized 
# personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly 
# terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.
# 
# Check Content: 
# The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:
# 
# /usr/bin/sudo /usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config
# 
# If the setting is not "900" or less, this is a finding.
# 
# Fix Text: To ensure that "ClientAliveInterval" is set correctly, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001133
#
# Verify organizational score
AOSX_13_000720="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000720)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000720" = "1" ]; then
	AOSX_13_000720_Audit="$(/usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000720_Audit" = "ClientAliveInterval 900" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000720 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000720 -bool false; else
		/bin/echo "* AOSX_13_000720 The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000720 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81653
# Group Title: SRG-OS-000163-GPOS-00072
# Rule ID: SV-96367r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000721
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.
# 
# Vulnerability Discussion: SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before 
# timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel 
# to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating 
# an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.
# 
# Check Content: 
# The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config
# 
# If the setting is not "ClientAliveCountMax 0", this is a finding.
# 
# Fix Text: To ensure that the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001133
#
# Verify organizational score
AOSX_13_000721="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000721)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000721" = "1" ]; then
	AOSX_13_000721_Audit="$(/usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000721_Audit" = "ClientAliveCountMax 0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000721 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000721 -bool false; else
		/bin/echo "* AOSX_13_000721 The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000721 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81655
# Group Title: SRG-OS-000163-GPOS-00072
# Rule ID: SV-96369r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000722
# Rule Title: The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.
# 
# Vulnerability Discussion: SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 
# seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity 
# for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. 
# In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.
# 
# Check Content: 
# The SSH daemon "LoginGraceTime" must be set correctly. To check the amount of time that a user can log on through SSH, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config
# 
# If the value is not set to "30" or less, this is a finding.
# 
# Fix Text: To ensure that "LoginGraceTime" is configured correctly, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001133
#
# Verify organizational score
AOSX_13_000722="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000722)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000722" = "1" ]; then
	AOSX_13_000722_Audit="$(/usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000722_Audit" = "LoginGraceTime 30" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000722 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000722 -bool false; else
		/bin/echo "* AOSX_13_000722 The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000722 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81657
# Group Title: SRG-OS-000066-GPOS-00034
# Rule ID: SV-96371r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000750
# Rule Title: The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider.
# 
# Vulnerability Discussion: DoD-approved certificates must be installed to the System Keychain so they will be available to all users.
# 
# For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. 
# For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at 
# medium assurance or higher, this Certification Authority will suffice. This control focuses on certificates with a visibility external 
# to the information system and does not include certificates related to internal system operations; for example, application-specific time services.
# 
# Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000478-GPOS-00223
# 
# Check Content: 
# To view a list of installed certificates, run the following command:
# 
# /usr/bin/sudo /usr/bin/security dump-keychain | /usr/bin/grep labl | awk -F\" '{ print $4 }'
# 
# If this list does not contain approved certificates, this is a finding.
# 
# Fix Text: Obtain the approved DOD certificates from the appropriate authority. Use Keychain Access from "/Applications/Utilities" to add certificates to the System Keychain.  
# 
# CCI: CCI-000185
# CCI: CCI-002450
#
# Configuration Profile - Certificate payload
# Verify organizational score
AOSX_13_000750="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000750)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000750" = "1" ]; then
	AOSX_13_000750_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'com.apple.security.root')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000750_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000750 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000750 -bool false; else
		/bin/echo "* AOSX_13_000750 The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000750 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81659
# Group Title: SRG-OS-000185-GPOS-00079
# Rule ID: SV-96373r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000780
# Rule Title: The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.
# 
# Vulnerability Discussion: Information at rest refers to the state of information when it is located on a secondary 
# storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, 
# desktops, and storage devices can be lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) 
# can be read, copied, or altered. By encrypting the system hard drive, the confidentiality and integrity of any data stored on the 
# system is ensured. FileVault Disk Encryption mitigates this risk.
# 
# Satisfies: SRG-OS-000185-GPOS-00079, SRG-OS-000404-GPOS-00183, SRG-OS-000405-GPOS-00184
# 
# Check Content: 
# To check if "FileVault 2" is enabled, run the following command:
# 
# /usr/bin/sudo /usr/bin/fdesetup status
# 
# If "FileVault" is "Off" and the device is a mobile device or the organization has determined that the drive must encrypt data at rest, this is a finding.
# 
# Fix Text: Open System Preferences >> Security and Privacy and navigate to the "FileVault" tab. Use this panel to configure full-disk encryption.
# 
# Alternately, from the command line, run the following command to enable "FileVault":
# 
# /usr/bin/sudo /usr/bin/fdesetup enable
# 
# After "FileVault" is initially set up, additional users can be added.  
# 
# CCI: CCI-001199
# CCI: CCI-002475
# CCI: CCI-002476
#
# Verify organizational score
AOSX_13_000780="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000780)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000780" = "1" ]; then
	AOSX_13_000780_Audit="$(/usr/bin/fdesetup status)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000780_Audit" = *"FileVault is On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000780 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000780 -bool false; else
		/bin/echo "* AOSX_13_000780 The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest – Enable FileVault." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000780 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81661
# Group Title: SRG-OS-000191-GPOS-00080
# Rule ID: SV-96375r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000835
# Rule Title: The macOS system must employ automated mechanisms to determine the state of system components with regard to 
# flaw remediation using the following frequency: continuously where HBSS is used; 30 days for any additional internal network 
# scans not covered by HBSS; and annually for external scans by Computer Network Defense Service Provider (CNDSP).
# 
# Vulnerability Discussion: An approved tool for continuous network scanning must be installed and configured to run.
# 
# Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating 
# system or other system components may remain vulnerable to the exploits presented by undetected software flaws.
# 
# To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using 
# HBSS and periodic scanning using other tools, as specified in the requirement.
# 
# Check Content: 
# Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved tool capable of continuous 
# scanning is loaded on the system. The recommended system is the McAfee HBSS.
# 
# If no such tool is installed on the system, this is a finding.
# 
# Fix Text: Install an approved HBSS solution onto the system.  
# 
# CCI: CCI-001233
#
# Verify organizational score
AOSX_13_000835="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000835)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000835" = "1" ]; then
	# If client fails, then note category in audit file
	if [[ -f "/Library/McAfee/agent/bin/cmdagent" ]]; then # Check for the McAfee cmdagent
		/bin/echo $(/bin/date -u) "AOSX_13_000835 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000835 -bool false; else
		/bin/echo "* AOSX_13_000835 The macOS system must employ automated mechanisms to determine the state of system components with regard to flaw remediation – Managed by McAfee EPO. Install McAfee EPO Agent." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000835 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81663
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96377r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000850
# Rule Title: The macOS system must restrict the ability of individuals to use USB storage devices.
# 
# Vulnerability Discussion: External hard drives, such as USB, must be disabled for users. USB hard drives are a potential vector 
# for malware and can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.
# 
# Check Content: 
# If an approved HBSS DCM/DLP solution is installed, this is not applicable.
# 
# To verify external USB drives are disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 3 harddisk-external
# 
# If the result is not “harddisk-external" = (
# eject,
# alert
# );”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Restrictions payload > Media > EXTERNAL DISKS: Allow (unchecked) 
# Verify organizational score
AOSX_13_000850="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000850)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000850" = "1" ]; then
	AOSX_13_000850_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 3 harddisk-external)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000850_Audit" = *"eject"* ]] && [[ "$AOSX_13_000850_Audit" = *"alert"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000850 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000850 -bool false; else
		/bin/echo "* AOSX_13_000850 The macOS system must restrict the ability of individuals to use USB storage devices via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000850 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81665
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96379r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000862
# Rule Title: The macOS system must be configured to not allow iTunes file sharing.
# 
# Vulnerability Discussion: Connections to unauthorized iOS devices (e.g., iPhones, iPods, and iPads) open the system to possible 
# compromise via exfiltration of system data. Disabling the iTunes file sharing blocks connections to iOS devices.
# 
# Check Content: 
# If iTunes file sharing is enabled, unauthorized disclosure could occur.
# 
# To verify that iTunes file sharing is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowiTunesFileSharing
# 
# If the result is null or is not “allowiTunesFileSharing = 0”, this is a finding
# 
# Fix Text: This setting is enforced using the “Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Custom payload > com.apple.applicationaccess > allowiTunesFileSharing=false
# Verify organizational score
AOSX_13_000862="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000862)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000862" = "1" ]; then
	AOSX_13_000862_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowiTunesFileSharing = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000862_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000862 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000862 -bool false; else
		/bin/echo "* AOSX_13_000862 The macOS system must be configured to not allow iTunes file sharing via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000862 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81667
# Group Title: SRG-OS-000480-GPOS-00229
# Rule ID: SV-96381r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000925
# Rule Title: The macOS system must not allow an unattended or automatic logon to the system.
# 
# Vulnerability Discussion: When automatic logons are enabled, the default user account is automatically logged on at boot 
# time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to 
# reboot the computer to log on. Disabling automatic logons mitigates this risk.
# 
# Check Content: 
# To check if the system is configured to automatically log on, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient
# 
# If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Login Window payload > Options > Disable automatic login (checked)
# Verify organizational score
AOSX_13_000925="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000925)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000925" = "1" ]; then
	AOSX_13_000925_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '"com.apple.login.mcx.DisableAutoLoginClient" = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000925_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000925 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000925 -bool false; else
		/bin/echo "* AOSX_13_000925 The macOS system must not allow an unattended or automatic logon to the system via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000925 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81669
# Group Title: SRG-OS-000480-GPOS-00229
# Rule ID: SV-96383r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000930
# Rule Title: The macOS system logon window must be configured to prompt for username and password, rather than show a list of users.
# 
# Vulnerability Discussion: The logon window must be configured to prompt all users for both a username and a password. 
# By default, the system displays a list of known users at the logon screen. This gives an advantage to an attacker with 
# physical access to the system, as the attacker would only have to guess the password for one of the listed accounts.
# 
# Check Content: 
# To check if the logon window is configured to prompt for user name and password, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SHOWFULLNAME
# 
# If there is no result, or "SHOWFULLNAME" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Login Window payload > Window > Name and password text fields (selected)
# Verify organizational score
AOSX_13_000930="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000930)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000930" = "1" ]; then
	AOSX_13_000930_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SHOWFULLNAME = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000930_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000930 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000930 -bool false; else
		/bin/echo "* AOSX_13_000930 The macOS system logon window must be configured to prompt for username and password, rather than show a list of users via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000930 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81671
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96385r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000950
# Rule Title: The macOS firewall must have logging enabled.
# 
# Vulnerability Discussion: Firewall logging must be enabled. This ensures that malicious network activity will be logged to the system.
# 
# Check Content: 
# If HBSS is used, this is not applicable.
# 
# To check if the macOS firewall has logging enabled, run the following command:
# 
# /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | /usr/bin/grep on
# 
# If the result does not show "on", this is a finding.
# 
# Fix Text: To enable the firewall logging, run the following command:
# 
# /usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_000950="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000950)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000950" = "1" ]; then
	AOSX_13_000950_Audit="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000950_Audit" = *"Log mode is on"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000950 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000950 -bool false; else
		/bin/echo "* AOSX_13_000950 The macOS firewall must have logging enabled. If HBSS is used, this is not applicable. The recommended system is the McAfee HBSS." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000950 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81673
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96387r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000955
# Rule Title: The macOS system must be configured so that Bluetooth devices are not allowed to wake the computer.
# Most effectively managed by disabling Bluetooth.
# 
# Vulnerability Discussion: A session lock is a temporary action taken when a user stops work and moves away from the 
# immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
# 
# The session lock is implemented at the point where session activity can be determined.
# 
# Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in 
# place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.
# 
# Check Content: 
# To check if the Bluetooth Remote Wake setting is disabled, run the following two commands as the primary user:
# 
# /usr/bin/defaults -currentHost read com.apple.Bluetooth RemoteWakeEnabled
# 
# /usr/bin/defaults read /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | cut -c22-57`.plist RemoteWakeEnabled
# 
# If there is an error or nothing is returned, or the return value is "1" for either command, this is a finding.
# 
# Fix Text: Manually change this control on the computer by opening System Preferences >> Bluetooth.
# 
# Click "Advanced" and ensure the "Allow Bluetooth devices to wake this computer" is not checked. 
# This control is not necessary if Bluetooth has been completely disabled.
# 
# The following can be run from the command line to disable "Remote Wake" for the current user:
# 
# /usr/bin/defaults write /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57`.plist RemoteWakeEnabled 0  
# 
# CCI: CCI-000366
#
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
# Verify organizational score
AOSX_13_000955="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000955)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000955" = "1" ]; then
	AOSX_13_000955_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableBluetooth = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000955_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000955 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000955 -bool false; else
		/bin/echo "* AOSX_13_000955 The macOS system must be configured so that Bluetooth devices are not allowed to wake the computer. The macOS system must be configured with Bluetooth turned off via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000955 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81675
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96389r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000965
# Rule Title: The macOS system must be configured with Bluetooth Sharing disabled.
# Most effectively managed by disabling Bluetooth.
# 
# Vulnerability Discussion: Bluetooth sharing allows users to wirelessly transmit files between the macOS host and Bluetooth-enabled devices, 
# including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files. 
# Disabling Bluetooth Sharing mitigates this risk.
# 
# Check Content: 
# To check if Bluetooth Sharing is enabled, open System Preferences >> Sharing and verify that "Bluetooth Sharing" is not checked "ON".
# 
# If it is "ON", this is a finding.
# 
# The following command can be run from the command line:
# 
# /usr/bin/defaults read /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | cut -c22-57`.plist PrefKeyServicesEnabled
# 
# If there is an error or nothing is returned, or the return value is "1", this is a finding.
# 
# Fix Text: To disable Bluetooth Sharing, open System Preferences >> Sharing and uncheck the box next to "Bluetooth Sharing". 
# This control is not necessary if Bluetooth has been completely disabled.
# 
# The following can be run from the command line to disable "Bluetooth Sharing" for the current user:
# 
# /usr/bin/defaults write /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57`.plist PrefKeyServicesEnabled 0  
# 
# CCI: CCI-000366
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
# Verify organizational score
AOSX_13_000965="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000965)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000965" = "1" ]; then
	AOSX_13_000965_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableBluetooth = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_000965_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000965 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000965 -bool false; else
		/bin/echo "* AOSX_13_000965 The macOS system must be configured with Bluetooth Sharing disabled. The macOS system must be configured with Bluetooth turned off via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000965 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81677
# Group Title: SRG-OS-000096-GPOS-00050
# Rule ID: SV-96391r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000975
# Rule Title: The macOS system must be configured to disable Remote Apple Events.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding 
# requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, 
# provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration 
# software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# Remote Apple Events must be disabled.
# 
# Check Content: 
# To check if Remote Apple Events is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.AEServer
# 
# If the results do not show the following, this is a finding.
# 
# "com.apple.AEServer" => true
# 
# Fix Text: To disable Remote Apple Events, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.AEServer
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000382
# 
# Verify organizational score
AOSX_13_000975="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000975)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000975" = "1" ]; then
	AOSX_13_000975_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.AEServer)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000975_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000975 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000975 -bool false; else
		/bin/echo "* AOSX_13_000975 The macOS system must be configured to disable Remote Apple Events." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000975 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81679
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96393r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000995
# Rule Title: The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.
# 
# Vulnerability Discussion: The "sudo" command must be configured to prompt for the administrator's password at least once 
# in each newly opened Terminal window or remote logon session, as this prevents a malicious user from taking advantage 
# of an unlocked computer or an abandoned logon session to bypass the normal password prompt requirement.
# 
# Without the "tty_tickets" option, all open local and remote logon sessions would be authenticated to use sudo without 
# a password for the duration of the configured password timeout window.
# 
# Check Content: 
# To check if the "tty_tickets" option is set for "/usr/bin/sudo", run the following command:
# 
# /usr/bin/sudo /usr/bin/grep tty_tickets /etc/sudoers
# 
# If there is no result, this is a finding.
# 
# Fix Text: Edit the "/etc/sudoers" file to contain the line:
# 
# Defaults tty_tickets
# 
# This line can be placed in the defaults section or at the end of the file.  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_13_000995="$(/usr/bin/defaults read "$plistlocation" AOSX_13_000995)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_000995" = "1" ]; then
	AOSX_13_000995_Audit="$(/usr/bin/grep tty_tickets /etc/sudoers)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_000995_Audit != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_000995 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_000995 -bool false; else
		/bin/echo "* AOSX_13_000995 The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_000995 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81681
# Group Title: SRG-OS-000480-GPOS-00232
# Rule ID: SV-96395r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001080
# Rule Title: The macOS Application Firewall must be enabled.
# 
# Vulnerability Discussion: The Application Firewall is the built-in firewall that comes with macOS and must be enabled. 
# Firewalls protect computers from network attacks by blocking or limiting access to open network ports. 
# Application firewalls limit which applications are allowed to communicate over the network.
# 
# Check Content: 
# If an approved HBSS solution is installed, this is not applicable.
# 
# To check if the macOS firewall has been enabled, run the following command:
# 
# /usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
# 
# If the result is "disabled", this is a finding.
# 
# Fix Text: To enable the firewall, run the following command:
# 
# /usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001080="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001080)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001080" = "1" ]; then
	AOSX_13_001080_Audit="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001080_Audit" = *"Firewall is enabled"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001080 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001080 -bool false; else
		/bin/echo "* AOSX_13_001080 The macOS Application Firewall must be enabled. If HBSS is used, this is not applicable. The recommended system is the McAfee HBSS." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001080 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81683
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96397r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001110
# Rule Title: The macOS system must be configured with all public directories owned by root or an application account.
# 
# Vulnerability Discussion: All public directories must be owned by "root", the local admin user, or an application account. 
# Directory owners have permission to delete any files contained in that directory, even if the files are owned by other user accounts. 
# By setting the owner to an administrator or application account, regular users will not be permitted to delete each other's files.
# 
# Check Content: 
# To display all directories that are writable by all and not owned by "root", run the following command:
# 
# /usr/bin/sudo find / -type d -perm +o+w -not -uid 0
# The find command includes /Volumes. This may cause problems with other mounted volumes. "-x" excludes mounted volumes.
# Excluding SIP Cache and tmp directories speeds the process.
# /usr/bin/sudo /usr/bin/find -x / -type d -perm +o+w -not \( -uid 0 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null
#
# If anything is returned, and those directories are not owned by root or application account, this is a finding.
# 
# Fix Text: To change the ownership of any finding, run the following command:
# 
# /usr/bin/sudo find / -type d -perm +o+w -not -uid 0 -exec chown root {} \;  
# The find command includes /Volumes. This may cause problems with other mounted volumes. "-x" excludes mounted volumes.
# Excluding SIP, Cache, and tmp directories speeds the process.
# /usr/bin/find -x / -type d -perm +o+w -not \( -uid 0 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null -exec chown root {} \;
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001110="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001110)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001110" = "1" ]; then
	AOSX_13_001110_Audit="$(/usr/bin/find -x / -type d -perm +o+w -not \( -uid 0 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001110_Audit" = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001110 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001110 -bool false; else
		/bin/echo "* AOSX_13_001110 The macOS system must be configured with all public directories owned by root or an application account." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001110 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81685
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96399r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001115
# Rule Title: The macOS system must be configured with the finger service disabled.
# 
# Vulnerability Discussion: The "finger" service has had several security vulnerabilities in the past and is not a necessary service. 
# It is disabled by default; enabling it would increase the attack surface of the system.
# 
# Check Content: 
# To check if the "finger" service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.fingerd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.fingerd" => true
# 
# Fix Text: To disable the "finger" service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.fingerd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_13_001115="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001115)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001115" = "1" ]; then
	AOSX_13_001115_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.fingerd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_001115_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001115 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001115 -bool false; else
		/bin/echo "* AOSX_13_001115 The macOS system must be configured with the finger service disabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001115 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81687
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96401r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001120
# Rule Title: The macOS system must be configured with the sticky bit set on all public directories.
# 
# Vulnerability Discussion: The sticky bit must be set on all public directories, as it prevents users with write access to the 
# directory from deleting or renaming files that belong to other users inside it.
# 
# Check Content: 
# Run the following command to view all world-writable directories that do not have the "sticky bit" set:
# 
# /usr/bin/sudo /usr/bin/find    / -type d \( -perm -0002 -a ! -perm -1000 \)
# The find command includes /Volumes. This may cause problems with other mounted volumes. "-x" excludes mounted volumes.
# Excluding Cache and tmp directories speeds the process.
# /usr/bin/sudo /usr/bin/find -x / -type d -perm -0002 -a -not \( -perm -1000 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null
# 
# If anything is returned, this is a finding.
# 
# Fix Text: Run the following command to set the "sticky bit" on all world-writable directories:
# 
# /usr/bin/sudo /usr/bin/find / -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} \;  
# The find command includes /Volumes. This may cause problems with other mounted volumes. "-x" excludes mounted volumes.
# Excluding Cache and tmp directories speeds the process.
# /usr/bin/sudo /usr/bin/find -x / -type d -perm -0002 -a -not \( -perm -1000 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null -exec chmod +t {} \;   

# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001120="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001120)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001120" = "1" ]; then
	AOSX_13_001120_Audit="$(/usr/bin/find -x / -type d -perm -0002 -a -not \( -perm -1000 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001120_Audit" = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001120 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001120 -bool false; else
		/bin/echo "* AOSX_13_001120 The macOS system must be configured with the sticky bit set on all public directories." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001120 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81689
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96403r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001125
# Rule Title: The macOS system must be configured with the prompt for Apple ID and iCloud disabled.
# 
# Vulnerability Discussion: The prompt for Apple ID and iCloud must be disabled, as it might mislead new users into creating 
# unwanted Apple IDs and iCloud storage accounts upon their first logon.
# 
# Check Content: 
# To check if the system is configured to skip cloud setup, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipCloudSetup
# 
# If “SkipCloudSetup" is not set to "1", this is a finding.
# 
# To check if the prompt for "Apple ID" and "iCloud" are disabled for new users, run the following command:
# 
# /usr/bin/sudo /usr/bin/defaults read /System/Library/User\ Template/English.lproj/Library/Preferences/com.apple.SetupAssistant
# 
# If there is no result, if it prints out that the domain "does not exist", or the results do not include 
# "DidSeeCloudSetup = 1 AND LastSeenCloudProductVersion = 10.12", this is a finding.
# 
# Fix Text: This setting is enforced using the “Login Window Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Login Window payload > Options > Disable Apple ID setup during login (checked)
# Verify organizational score
AOSX_13_001125="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001125)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001125" = "1" ]; then
	AOSX_13_001125_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipCloudSetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001125_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001125 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001125 -bool false; else
		/bin/echo "* AOSX_13_001125 The macOS system must be configured with the prompt for Apple ID and iCloud disabled via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001125 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81691
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96405r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001130
# Rule Title: The macOS system must be configured so that users do not have Apple IDs signed into iCloud.
# 
# Vulnerability Discussion: Users should not sign into iCloud, as this leads to the possibility that sensitive data could be saved to 
# iCloud storage or that users could inadvertently introduce viruses or malware previously saved to iCloud from other systems.
# 
# Check Content: 
# To see if any user account has configured an Apple ID for iCloud usage, run the following command:
# 
# /usr/bin/sudo find /Users/ -name 'MobileMeAccounts.plist' -exec /usr/bin/defaults read '{}' \;
# 
# If the results show any accounts listed, this is a finding.
# 
# Fix Text: This must be resolved manually.
# 
# With the affected user logged on, open System Preferences >> iCloud.
# 
# Choose "Sign Out".  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001130="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001130)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001130" = "1" ]; then
	over500=$( /usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 { print $1 }' )
	for EachUser in $over500 ;
	do
		UserHomeDirectory=$(/usr/bin/dscl . -read /Users/$EachUser NFSHomeDirectory | /usr/bin/awk '{print $2}')
		CheckForiCloudAccount="$(/usr/bin/defaults read "$UserHomeDirectory/Library/Preferences/MobileMeAccounts" Accounts  2>/dev/null | /usr/bin/grep -c 'AccountDescription = iCloud')"
		# If client fails, then note category in audit file
		if [[ "$CheckForiCloudAccount" > "0" ]] ; then
			/bin/echo "* AOSX_13_001130 $EachUser has an Apple ID signed into iCloud. Sign $EachUser out of the iCloud System Preference." >> "$auditfilelocation"
			/bin/echo $(date -u) "AOSX_13_001130 fix $EachUser iCloud account" | tee -a "$logFile"; else
			/bin/echo $(/bin/date -u) "AOSX_13_001130 passed" | /usr/bin/tee -a "$logFile"
		fi
	done
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81693
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96407r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_001140
# Rule Title: The macOS system must be configured with iTunes Music Sharing disabled.
# 
# Vulnerability Discussion: When iTunes Music Sharing is enabled, the computer starts a network listening service that shares the contents of the 
# user's music collection with other users in the same subnet. Unnecessary network services should always be disabled because they increase 
# the attack surface of the system. Disabling iTunes Music Sharing mitigates this risk.
# 
# Check Content: 
# To check if iTunes Music Sharing is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep disableSharedMusic
# 
# If the return is null or does not contain “disableSharedMusic = 1” this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Custom payload > com.apple.itunes > disableSharedMusic=true
# Verify organizational score
AOSX_13_001140="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001140)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001140" = "1" ]; then
	AOSX_13_001140_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'disableSharedMusic = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001140_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001140 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001140 -bool false; else
		/bin/echo "* AOSX_13_001140 The macOS system must be configured with iTunes Music Sharing disabled via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001140 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81695
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96409r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001145
# Rule Title: All setuid executables on the macOS system must be documented.
# 
# Vulnerability Discussion: Very few of the executables that come preinstalled on the macOS host have the "setuid" bit set, and administrators 
# should never add the "setuid" bit to any executable that does not already have it set by the vendor. Executables with the "setuid" bit set allow 
# anyone that executes them to be temporarily assigned the UID of the file owner. In practice, this almost always is the root account. 
# While some vendors depend on this file attribute for proper operation, security problems can result if "setuid" is assigned to programs 
# allowing reading and writing of files, or shell escapes, as this could lead to unprivileged users gaining privileged access to files and directories on the system.
# 
# Check Content: 
# If available, provide a list of "setuids" provided by a vendor. To list all of the files with the "setuid" bit set, run the following 
# command to send all results to a file named "suidfilelist":
# 
# /usr/bin/sudo find / -perm -4000 -exec /bin/ls -ldb {} \; > suidfilelist
# The find command includes /Volumes. This may cause problems with other mounted volumes. "-x" excludes mounted volumes.
# Excluding Cache and tmp directories speeds the process.
# /bin/echo "$LogStamp" > "$LogDir"/STIG_suidfilelist
# /usr/bin/sudo /usr/bin/find -x / -perm -4000 -not \( -path '/System/*' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null -exec /bin/ls -ldb {} \; > "$LogDir"/STIG_suidfilelist
# 
# If any of the files listed are not documented as needing to have the "setuid" bit set by the vendor, this is a finding.
# 
# Fix Text: Document all of the files with the "setuid" bit set.
# 
# Remove any undocumented files.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001145="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001145)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001145" = "1" ]; then
	/usr/bin/find -x / -perm -4000 -not \( -path '/System/*' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null -exec /bin/ls -ldb {} \; > "$LogDir"/STIG_suidfilelist
	/bin/echo $(/bin/date -u) "AOSX_13_001145 passed" | /usr/bin/tee -a "$logFile"
	/usr/bin/defaults write "$plistlocation" AOSX_13_001145 -bool false
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81697
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96411r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001195
# Rule Title: The macOS system must not accept source-routed IPv4 packets.
# 
# Vulnerability Discussion: A source-routed packet attempts to specify the network path the packet should take. If the system is not configured to 
# block the incoming source-routed packets, an attacker can redirect the system's network traffic. Configuring the system to drop incoming source-routed IPv4 packets mitigates this risk.
# 
# Check Content: 
# To check if the system is configured to accept "source-routed" packets, run the following command:
# 
# sysctl net.inet.ip.accept_sourceroute
# 
# If the value is not "0", this is a finding.
# 
# Fix Text: To configure the system to not accept "source-routed" packets, add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet.ip.accept_sourceroute=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001195="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001195)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001195" = "1" ]; then
	AOSX_13_001195_Audit="$(/usr/sbin/sysctl net.inet.ip.accept_sourceroute)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001195_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001195 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001195 -bool false; else
		/bin/echo "* AOSX_13_001195 The macOS system must not accept source-routed IPv4 packets." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001195 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81699
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96413r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001200
# Rule Title: The macOS system must ignore IPv4 ICMP redirect messages.
# 
# Vulnerability Discussion: ICMP redirects are broadcast to reshape network traffic. A malicious user could craft fake redirect packets and 
# try to force all network traffic to pass through a network sniffer. If the system is not configured to ignore these packets, it could be susceptible to this kind of attack.
# 
# Check Content: 
# To check if the system is configured to ignore "ICMP redirect" messages, run the following command:
# 
# sysctl net.inet.icmp.drop_redirect
# 
# If the value is not "1", this is a finding.
# 
# Fix Text: To configure the system to ignore "ICMP redirect" messages, add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet.icmp.drop_redirect=1  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001200="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001200)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001200" = "1" ]; then
	AOSX_13_001200_Audit="$(/usr/sbin/sysctl net.inet.icmp.drop_redirect)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001200_Audit" = *"1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001200 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001200 -bool false; else
		/bin/echo "* AOSX_13_001200 The macOS system must ignore IPv4 ICMP redirect messages." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001200 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81701
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96415r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001205
# Rule Title: The macOS system must not have IP forwarding for IPv4 enabled.
# 
# Vulnerability Discussion: IP forwarding for IPv4 must not be enabled, as only authorized systems should be permitted to operate as routers.
# 
# Check Content: 
# To check if "IP forwarding" is enabled, run the following command:
# 
# sysctl net.inet.ip.forwarding
# 
# If the values are not "0", this is a finding.
# 
# Fix Text: To configure the system to disable "IP forwarding", add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet.ip.forwarding=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001205="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001205)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001205" = "1" ]; then
	AOSX_13_001205_Audit="$(/usr/sbin/sysctl net.inet.ip.forwarding)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001205_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001205 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001205 -bool false; else
		/bin/echo "* AOSX_13_001205 The macOS system must not have IP forwarding for IPv4 enabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001205 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81703
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96417r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001206
# Rule Title: The macOS system must not have IP forwarding for IPv6 enabled.
# 
# Vulnerability Discussion: IP forwarding for IPv6 must not be enabled, as only authorized systems should be permitted to operate as routers.
# 
# Check Content: 
# To check if "IP forwarding" is enabled, run the following command:
# 
# sysctl net.inet6.ip6.forwarding
# 
# If the values are not "0", this is a finding.
# 
# Fix Text: To configure the system to disable "IP forwarding", add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet6.ip6.forwarding=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001206="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001206)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001206" = "1" ]; then
	AOSX_13_001206_Audit="$(/usr/sbin/sysctl net.inet6.ip6.forwarding)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001206_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001206 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001206 -bool false; else
		/bin/echo "* AOSX_13_001206 The macOS system must not have IP forwarding for IPv6 enabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001206 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81705
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96419r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001210
# Rule Title: The macOS system must not send IPv4 ICMP redirects by default.
# 
# Vulnerability Discussion: ICMP redirects are broadcast to reshape network traffic. A malicious user could use the system to send fake 
# redirect packets and try to force all network traffic to pass through a network sniffer. Disabling ICMP redirect broadcasts mitigates this risk.
# 
# Check Content: 
# To check if the system is configured to send ICMP redirects, run the following command:
# 
# sysctl net.inet.ip.redirect
# 
# If the values are not set to "0", this is a finding.
# 
# Fix Text: To configure the system to not send ICMP redirects, add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet.ip.redirect=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001210="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001210)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001210" = "1" ]; then
	AOSX_13_001210_Audit="$(/usr/sbin/sysctl net.inet.ip.redirect)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001210_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001210 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001210 -bool false; else
		/bin/echo "* AOSX_13_001210 The macOS system must not send IPv4 ICMP redirects by default." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001210 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81707
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96421r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001211
# Rule Title: The macOS system must not send IPv6 ICMP redirects by default.
# 
# Vulnerability Discussion: ICMP redirects are broadcast to reshape network traffic. A malicious user could use the system to send fake 
# redirect packets and try to force all network traffic to pass through a network sniffer. Disabling ICMP redirect broadcasts mitigates this risk.
# 
# Check Content: 
# To check if the system is configured to send ICMP redirects, run the following command:
# 
# sysctl net.inet6.ip6.redirect
# 
# If the values are not set to "0", this is a finding.
# 
# Fix Text: To configure the system to not send ICMP redirects, add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet6.ip6.redirect=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001211="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001211)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001211" = "1" ]; then
	AOSX_13_001211_Audit="$(/usr/sbin/sysctl net.inet6.ip6.redirect)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001211_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001211 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001211 -bool false; else
		/bin/echo "* AOSX_13_001211 The macOS system must not send IPv6 ICMP redirects by default." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001211 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81711
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96425r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001215
# Rule Title: The macOS system must prevent local applications from generating source-routed packets.
# 
# Vulnerability Discussion: A source-routed packet attempts to specify the network path that the system should take. 
# If the system is not configured to block the sending of source-routed packets, an attacker can redirect the system's network traffic.
# 
# Check Content: 
# To check if the system is configured to forward source-routed packets, run the following command:
# 
# sysctl net.inet.ip.sourceroute
# 
# If the value is not set to "0", this is a finding.
# 
# Fix Text: To configure the system to not forward source-routed packets, add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet.ip.sourceroute=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001215="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001215)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001215" = "1" ]; then
	AOSX_13_001215_Audit="$(/usr/sbin/sysctl net.inet.ip.sourceroute)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001215_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001215 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001215 -bool false; else
		/bin/echo "* AOSX_13_001215 The macOS system must prevent local applications from generating source-routed packets." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001215 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81713
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96427r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001220
# Rule Title: The macOS system must not process Internet Control Message Protocol [ICMP] timestamp requests.
# 
# Vulnerability Discussion: ICMP timestamp requests reveal information about the system and can be used to determine which operating system is installed. 
# Precise time data can also be used to launch time-based attacks against the system. Configuring the system to drop incoming ICMPv4 timestamp requests mitigates these risks.
# 
# Check Content: 
# To check if the system is configured to process ICMP timestamp requests, run the following command:
# 
# sysctl net.inet.icmp.timestamp
# 
# If the value is not set to "0", this is a finding.
# 
# Fix Text: To disable ICMP timestamp responses, add the following line to "/etc/sysctl.conf", creating the file if necessary:
# 
# net.inet.icmp.timestamp=0  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001220="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001220)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001220" = "1" ]; then
	AOSX_13_001220_Audit="$(/usr/sbin/sysctl net.inet.icmp.timestamp)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001220_Audit" = *"0"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001220 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001220 -bool false; else
		/bin/echo "* AOSX_13_001220 The macOS system must not process Internet Control Message Protocol [ICMP] timestamp requests." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001220 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81715
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96429r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001235
# Rule Title: The macOS system must have unused network devices disabled.
# 
# Vulnerability Discussion: If an unused network device is left enabled, a user might be able to activate it at a later time. Unused network devices should be disabled.
# 
# Check Content: 
# To list the network devices that are enabled on the system, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices
# 
# A disabled device will have an asterisk in front of its name.
# 
# If any listed device that is not in use is missing this asterisk, this is a finding.
# 
# Fix Text: To disable a network device, run the following command, substituting the name of the device in place of "'<networkservice>'":
# 
# /usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled '<networkservice>' off  
# 
# CCI: CCI-000366
#
#
# Verify organizational score
AOSX_13_001235="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001235)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001235" = "1" ]; then
	/bin/echo "AOSX_13_001235 NULL"
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81717
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96431r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001270
# Rule Title: The macOS system must be configured to disable Internet Sharing.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by 
# default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple 
# services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality of life issues.
# 
# Internet Sharing must be disabled.
# 
# Check Content: 
# To check if Internet Sharing is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.NetworkSharing
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.NetworkSharing" => true
# 
# Fix Text: To disable Internet Sharing, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.NetworkSharing
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_13_001270="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001270)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001270" = "1" ]; then
	AOSX_13_001270_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.NetworkSharing)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_001270_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001270 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001270 -bool false; else
		/bin/echo "* AOSX_13_001270 The macOS system must be configured to disable Internet Sharing." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001270 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################


#####################################################################################################
#
# Group ID (Vulid): V-81719
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96433r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001275
# Rule Title: The macOS system must be configured to disable Web Sharing.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and 
# logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default 
# may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services 
# from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality of life issues.
# 
# Web Sharing is non-essential and must be disabled.
# 
# Check Content: 
# To check if Web Sharing is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep org.apache.httpd
# 
# If the results do not show the following, this is a finding:
# 
# "org.apache.httpd" => true
# 
# Fix Text: To disable Web Sharing, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/org.apache.httpd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_13_001275="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001275)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001275" = "1" ]; then
	AOSX_13_001275_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep org.apache.httpd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_13_001275_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001275 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001275 -bool false; else
		/bin/echo "* AOSX_13_001275 The macOS system must be configured to disable Web Sharing." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001275 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81721
# Group Title: SRG-OS-000329-GPOS-00128
# Rule ID: SV-96435r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001324
# Rule Title: The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.
# 
# Vulnerability Discussion: Setting a lockout time period of 15 minutes is an effective deterrent against brute forcing that also makes 
# allowances for legitimate mistakes by users. When three invalid logon attempts are made, the account will be locked.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, 
# run the following command to check if the system has the correct setting for the logon reset timer:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minutesUntilFailedLoginReset
# 
# If the return is null or not “minutesUntilFailedLoginReset = 15”, this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, the variable names may vary depending on how the policy was set. 
# To check if the password policy is configured to disable an account for 15 minutes after 3 unsuccessful logon attempts, 
# run the following command to output the password policy to the screen:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryAuthentication</key>".
# 
# If this does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# In the array that follows, there should be one or more <dict> sections that describe policy checks. One should contain a <string> that allows 
# users to log on if "policyAttributeFailedAuthentications" is less than "policyAttributeMaximumFailedAuthentications". Under policyParameters, 
# "policyAttributeMaximumFailedAuthentications" should be set to "3".
# 
# If "policyAttributeMaximumFailedAuthentications" is not set to "3", this is a finding.
# 
# In the same check or in another <dict> section, there should be a <string> that allows users to log on if the "policyAttributeCurrentTime" is 
# greater than the result of adding "15" minutes (900 seconds) to "policyAttributeLastFailedAuthenticationTime". 
# The check might use a variable defined in its "policyParameters" section.
# 
# If the check does not exist or if the check adds too great an amount of time, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# The following two lines within the configuration enforce lockout expiration to "15" minutes:
# 
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor and ensure it contains the following text after the opening <dict> tag and before the closing </dict> tag.
# 
# Replace <dict/> first with <dict></dict> if necessary.
# 
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryAuthentication</key>" already exists, the following text should be used instead and inserted after the first <array> tag that follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change 
# and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-002238
#
# Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15
# Verify organizational score
AOSX_13_001324="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001324)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001324" = "1" ]; then
	AOSX_13_001324_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'minutesUntilFailedLoginReset = 15')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001324_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001324 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001324 -bool false; else
		/bin/echo "* AOSX_13_001324 The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001324 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81723
# Group Title: SRG-OS-000021-GPOS-00005
# Rule ID: SV-96437r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001325
# Rule Title: The macOS system must enforce account lockout after the limit of three consecutive invalid logon attempts by a user.
# 
# Vulnerability Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, 
# otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the 
# following command to check if the system has the correct setting for the number of permitted failed logon attempts:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxFailedAttempts
# 
# If the return is null, or not, “maxFailedAttempts = 3”, this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, the variable names may vary depending on how the policy was set. To check if the password 
# policy is configured to disable an account for 15 minutes after 3 unsuccessful logon attempts, run the following command to output the password policy to the screen:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryAuthentication</key>".
# 
# If this does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# In the array that follows, there should be one or more <dict> sections that describe policy checks. One should contain a <string> that allows 
# users to log on if "policyAttributeFailedAuthentications" is less than "policyAttributeMaximumFailedAuthentications". Under policyParameters, "policyAttributeMaximumFailedAuthentications" should be set to "3".
# 
# If "policyAttributeMaximumFailedAuthentications" is not set to "3", this is a finding.
# 
# In the same check or in another <dict> section, there should be a <string> that allows users to log on if the "policyAttributeCurrentTime" 
# is greater than the result of adding "15" minutes (900 seconds) to "policyAttributeLastFailedAuthenticationTime". The check might use a variable defined in its policyParameters section.
# 
# If the check does not exist or if the check adds too great an amount of time, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor and ensure it contains the following text after the opening <dict> tag and before the closing </dict> tag. Replace <dict/> first with <dict></dict> if necessary.
# 
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryAuthentication</key>" already exists, the following text should be used instead and inserted after the first <array> tag that follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# </array>
# 
# If the line <key>policyCategoryAuthentication</key> already exists, the following text should be used instead and inserted after the first <array> tag that follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration or bugs in OS X may 
# block password change and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-000044
#
# Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
# Verify organizational score
AOSX_13_001325="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001325)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001325" = "1" ]; then
	AOSX_13_001325_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'maxFailedAttempts = 3')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001325_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001325 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001325 -bool false; else
		/bin/echo "* AOSX_13_001325 The macOS system must enforce account lockout after the limit of three consecutive invalid logon attempts by a user via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001325 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81725
# Group Title: SRG-OS-000329-GPOS-00128
# Rule ID: SV-96439r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001327
# Rule Title: The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.
# 
# Vulnerability Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, 
# otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. Setting a lockout expiration of 15 minutes is an 
# effective deterrent against brute forcing that also makes allowances for legitimate mistakes by users.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, 
# run the following command to check if the system has the correct setting for the number of permitted failed logon attempts and the logon reset timer:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep 'maxFailedAttempts\|minutesUntilFailedLoginReset'
# 
# If "maxFailedAttempts" is not set to "3" and "minutesUntilFailedLoginReset" is not set to "15", this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, the variable names may vary depending on how the policy was set. 
# To check if the password policy is configured to disable an account for 15 minutes after 3 unsuccessful logon attempts, 
# run the following command to output the password policy to the screen:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryAuthentication</key>".
# 
# If this does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# In the array that follows, there should be one or more <dict> sections that describe policy checks. One should contain a <string> 
# that allows users to log on if "policyAttributeFailedAuthentications" is less than "policyAttributeMaximumFailedAuthentications". 
# Under policyParameters, "policyAttributeMaximumFailedAuthentications" should be set to "3".
# 
# If "policyAttributeMaximumFailedAuthentications" is not set to "3", this is a finding.
# 
# In the same check or in another <dict> section, there should be a <string> that allows users to log on if the "policyAttributeCurrentTime" 
# is greater than the result of adding "15" minutes (900 seconds) to "policyAttributeLastFailedAuthenticationTime". 
# The check might use a variable defined in its "policyParameters" section.
# 
# If the check does not exist or if the check adds too great an amount of time, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor and ensure it contains the following text after the opening <dict> tag and before the closing </dict> tag.
# 
# Replace <dict/> first with <dict></dict> if necessary.
# 
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryAuthentication</key>" already exists, the following text should be used instead and inserted after the first <array> tag that follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration or bugs in OS X 
# may block password change and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-002238
#
# Verify organizational score
AOSX_13_001327="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001327)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001327" = "1" ]; then
	/bin/echo "AOSX_13_001327 NULL - redundant to AOSX_13_001324 and AOSX_13_001325"
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81727
# Group Title: SRG-OS-000047-GPOS-00023
# Rule ID: SV-96441r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001355
# Rule Title: The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).
# 
# Vulnerability Discussion: The audit service should shut down the computer if it is unable to audit system events. 
# Once audit failure occurs, user and system activity is no longer recorded and malicious activity could go undetected. 
# Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, 
# and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.
# 
# When availability is an overriding concern, other approved actions in response to an audit failure are as follows:
# 
# (i) If the failure was caused by the lack of audit record storage capacity, the operating system must continue 
# generating audit records if possible (automatically restarting the audit service if necessary), 
# overwriting the oldest audit records in a first-in-first-out manner.
# 
# (ii) If audit records are sent to a centralized collection server and communication with this server is lost or the 
# server fails, the operating system must queue audit records locally until communication is restored or until the audit 
# records are retrieved manually. Upon restoration of the connection to the centralized collection server, 
# action should be taken to synchronize the local audit data with the collection server.
# 
# Check Content: 
# To view the setting for the audit control system, run the following command:
# 
# sudo /usr/bin/grep ^policy /etc/security/audit_control | /usr/bin/grep ahlt
# 
# If there is no result, this is a finding.
# 
# Fix Text: Edit the "/etc/security/audit_control file" and change the value for policy to include the setting "ahlt". 
# To do this programmatically, run the following command:
# 
# sudo /usr/bin/sed -i.bak '/^policy/ s/$/,ahlt/' /etc/security/audit_control; sudo /usr/sbin/audit -s  
# 
# CCI: CCI-000140
#
# Verify organizational score
AOSX_13_001355="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001355)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001355" = "1" ]; then
	AOSX_13_001355_Audit="$(/usr/bin/grep ^policy /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_001355_Audit" = *"ahlt"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_001355 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001355 -bool false; else
		/bin/echo "* AOSX_13_001355 The macOS system must shut down by default upon audit failure (unless availability is an overriding concern)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001355 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81729
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96443r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_001465
# Rule Title: The macOS system must use a DoD antivirus program.
# 
# Vulnerability Discussion: An approved antivirus product must be installed and configured to run.
# 
# Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of 
# software will aid in elimination of the software from the operating system.
# 
# Check Content: 
# Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved antivirus solution is loaded on the system. 
# The antivirus solution may be bundled with an approved host-based security solution.
# 
# If there is no local antivirus solution installed on the system, this is a finding.
# 
# Fix Text: Install an approved antivirus solution onto the system.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_001465="$(/usr/bin/defaults read "$plistlocation" AOSX_13_001465)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_001465" = "1" ]; then
	# If client fails, then note category in audit file
	if [[ -f "/Library/McAfee/agent/bin/cmdagent" ]]; then # Check for the McAfee cmdagent
		/bin/echo $(/bin/date -u) "AOSX_13_001465 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_001465 -bool false; else
		/bin/echo "* AOSX_13_001465 The macOS system must use a DoD antivirus program – Managed by McAfee EPO. Install McAfee EPO Agent." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_001465 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81731
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-96445r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_002050
# Rule Title: The macOS system must be configured to disable AirDrop.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling 
# (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default 
# may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services 
# from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, 
# providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, 
# and approved to conduct official business or to address authorized quality of life issues.
# 
# AirDrop must be disabled.
# 
# Check Content: 
# To check if AirDrop has been disabled, run the following command:
# 
# sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAirDrop
# 
# If the result is not "DisableAirDrop = 1", this is a finding.
# 
# Fix Text: Disabling AirDrop is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Restrictions payload > Media > Allow AirDrop (unchecked)
# Verify organizational score
AOSX_13_002050="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002050)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002050" = "1" ]; then
	AOSX_13_002050_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'disableSharedMusic = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_002050_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_002050 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_002050 -bool false; else
		/bin/echo "* AOSX_13_002050 The macOS system must be configured to disable AirDrop via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_002050 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81733
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-96447r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_002060
# Rule Title: The macOS system must be integrated into a directory services infrastructure.
# 
# Vulnerability Discussion: Distinct user account databases on each separate system cause problems with username and password policy enforcement. 
# Most approved directory services infrastructure solutions allow centralized management of users and passwords.
# 
# Check Content: 
# To determine if the system is integrated to a directory service, ask the System Administrator (SA) or 
# Information System Security Officer (ISSO) or run the following command:
# 
# /usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)'
# 
# If nothing is returned, or if the system is not integrated into a directory service infrastructure, this is a finding.
# 
# Fix Text: Integrate the system into an existing directory services infrastructure.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_13_002060="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002060)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002060" = "1" ]; then
	AOSX_13_002060_Audit1="$(/usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)')"
	AOSX_13_002060_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'adRealm =')"
	AOSX_13_002060_Audit3="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'syncLocalPassword = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_002060_Audit1" = *"Active Directory"* ]] || [[ "$AOSX_13_002060_Audit1" = *"CentrifyDC"* ]] || [[ "$AOSX_13_002060_Audit2" > "0" ]] || [[ "$AOSX_13_002060_Audit3" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_002060 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_002060 -bool false; else
		/bin/echo "* AOSX_13_002060 The macOS system must be integrated into a directory services infrastructure." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_002060 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81735
# Group Title: SRG-OS-000076-GPOS-00044
# Rule ID: SV-96449r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002085
# Rule Title: The macOS system must enforce a 60-day maximum password lifetime restriction.
# 
# Vulnerability Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, 
# passwords need to be changed periodically.
# 
# One method of minimizing this risk is to use complex passwords and periodically change them. 
# If the operating system does not limit the lifetime of passwords and force users to change their passwords, 
# there is the risk that the operating system passwords could be compromised.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a 
# configuration profile, run the following command to check if the system is configured to require users to 
# change their passwords every 60 days:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxPINAgeInDays
# If the return is null, or is not “maxPINAgeInDays = 60” or set to a smaller value, this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, run the following command instead:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line <key>policyCategoryPasswordChange</key>.
# 
# If it does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# Otherwise, in the array section that follows it, there should be a <dict> section that contains a check <string> that 
# compares the variable "policyAttributeLastPasswordChangeTime" to the variable "policyAttributeCurrentTime". 
# It may contain additional variables defined in the "policyParameters" section that follows it. All comparisons are done in seconds.
# 
# If this check allows users to log in with passwords older than "60" days, or if no such check exists, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current 
# "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor.
# 
# If the file does not yet contain any policy settings, replace <dict/> with <dict></dict>.
# 
# If there already is a policy block that refers to password expiration, ensure it is set to "60" days.
# 
# If the line "<key>policyCategoryPasswordChange</key>" is not present in the file, add the following text immediately 
# after the opening <dict> tag in the file:
# 
# <key>policyCategoryPasswordChange</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
# <key>policyIdentifier</key>
# <string>Password Change Interval</string>
# <key>policyParameters</key>
# <dict>
# <key>policyAttributeExpiresEveryNDays</key>
# <integer>60</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryPasswordChange</key>" is already present in the file, the following text should be added 
# just after the opening <array> tag that follows the line instead:
# 
# <dict>
# <key>policyContent</key>
# <string>policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
# <key>policyIdentifier</key>
# <string>Password Change Interval</string>
# <key>policyParameters</key>
# <dict>
# <key>policyAttributeExpiresEveryNDays</key>
# <integer>60</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block 
# password change and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-000199
#
# Configuration Profile - Passcode payload > MAXIMUM PASSCODE AGE 60
# Verify organizational score
AOSX_13_002085="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002085)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002085" = "1" ]; then
	AOSX_13_002085_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'maxPINAgeInDays = 60')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_002085_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_002085 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_002085 -bool false; else
		/bin/echo "* AOSX_13_002085 The macOS system must enforce a 60-day maximum password lifetime restriction via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_002085 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81737
# Group Title: SRG-OS-000077-GPOS-00045
# Rule ID: SV-96451r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002090
# Rule Title: The macOS system must prohibit password reuse for a minimum of five generations.
# 
# Vulnerability Discussion: Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and 
# brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has 
# exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.
# 
# Check Content: 
# Password policy can be set with the "Password Policy" configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, 
# run the following command to check if the system is configured to require that users cannot reuse one of their five previously used passwords:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep pinHistory
# 
# If the return in null or not “pinHistory = 5” or greater, this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, run the following command instead:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryPasswordContent</key>".
# 
# If it does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# Otherwise, in the array section that follows it, there should be a <dict> section that contains a check <string> such as "<string>none policyAttributePasswordHashes 
# in policyAttributePasswordHistory</string>". This searches for the hash of the user-entered password in the list of previous password hashes. 
# In the "policyParameters" section that follows it, "policyAttributePasswordHistoryDepth" must be set to "5" or greater.
# 
# If this parameter is not set to "5" or greater, or if no such check exists, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor. If the file does not yet contain any policy settings, replace <dict/> with <dict></dict>. 
# If there already is a policy block that refers to password history, ensure it is set to "5". If the line "<key>policyCategoryPasswordContent</key>" 
# is not present in the file, add the following text immediately after the opening <dict> tag in the file:
# 
# <key>policyCategoryPasswordContent</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
# <key>policyIdentifier</key>
# <string>Password History</string>
# <key>policyParameters</key>
# <dict>
# <key>policyAttributePasswordHistoryDepth</key>
# <integer>5</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryPasswordContent</key>" is already present in the file, the following text should be 
# added just after the opening <array> tag that follows the line instead:
# 
# <dict>
# <key>policyContent</key>
# <string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
# <key>policyIdentifier</key>
# <string>Password History</string>
# <key>policyParameters</key>
# <dict>
# <key>policyAttributePasswordHistoryDepth</key>
# <integer>5</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may 
# block password change and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-000200
#
# Configuration Profile - Passcode payload > PASSCODE HISTORY 5
# Verify organizational score
AOSX_13_002090="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002090)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002090" = "1" ]; then
	AOSX_13_002090_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'pinHistory = 5')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_002090_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_002090 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_002090 -bool false; else
		/bin/echo "* AOSX_13_002090 The macOS system must prohibit password reuse for a minimum of five generations via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_002090 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81739
# Group Title: SRG-OS-000206-GPOS-00084
# Rule ID: SV-96453r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002105
# Rule Title: The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.
# 
# Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain 
# sensitive information that could be used by an attacker. Setting the correct owner mitigates this risk.
# 
# Check Content: 
# Log files are controlled by "newsyslog" and "aslmanager".
# 
# These commands check for log files that exist on the system and print out the log with corresponding ownership. 
# Run them from inside "/var/log":
# 
# /usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
# /usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
# 
# If there are any system log files that are not owned by "root" and group-owned by "wheel" or admin, this is a finding.
# 
# Service logs may be owned by the service user account or group.
# 
# Fix Text: For any log file that returns an incorrect owner or group value, run the following command:
# 
# /usr/bin/sudo chown root:wheel [log file]
# 
# [log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line 
# in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and ensure that the owner:group column is set to 
# "root:wheel" or the appropriate service user account and group.
# 
# If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" 
# and ensure that "uid" and "gid" options are either not present or are set to a service user account and group respectively.  
# 
# CCI: CCI-001314
#
# Verify organizational score
AOSX_13_002105="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002105)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002105" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
			if [[ "$(/usr/bin/stat -f '%Su:%Sg:%N' $i)" = *"root:wheel"*  ]] || [[ "$(/usr/bin/stat -f '%Su:%Sg:%N' $i)" = *"root:admin"* ]] ; then
				#/bin/echo "Ownership is correct for $i"
				:
			else
				/bin/echo "* AOSX_13_002105 The macOS system must be configured with system log files owned by root and group-owned by wheel or admin. $i" >> "$auditfilelocation"
				/bin/echo $(/bin/date -u) "AOSX_13_002105 fix ownership for $i" | /usr/bin/tee -a "$logFile"
			fi
		fi
	done
fi
# 
#####################################################################################################


#####################################################################################################
#
# Group ID (Vulid): V-81741
# Group Title: SRG-OS-000206-GPOS-00084
# Rule ID: SV-96455r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002106
# Rule Title: The macOS system must be configured with system log files set to mode 640 or less permissive.
# 
# Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain sensitive 
# information that could be used by an attacker. Setting the correct permissions mitigates this risk.
# 
# Check Content: 
# These commands check for log files that exist on the system and print out the log with corresponding permissions. 
# Run them from inside "/var/log":
# 
# /usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
# /usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
# 
# The correct permissions on log files should be "640" or less permissive for system logs.
# 
# Any file with more permissive settings is a finding.
# 
# Fix Text: For any log file that returns an incorrect permission value, run the following command:
# 
# /usr/bin/sudo chmod 640 [log file]
# 
# [log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line 
# in the directory "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and edit the mode column to be "640" or less permissive.
# 
# If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" 
# and add or edit the mode option to be "mode=0640" or less permissive.  
# 
# CCI: CCI-001314
#
# Verify organizational score
AOSX_13_002106="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002106)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002106" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
			if [[ "$(/usr/bin/stat -f '%A:%N' $i)" = *"640"* ]]; then
				#/bin/echo "Permission are correct for $i"
				:
			else
				/bin/echo "* AOSX_13_002106 The macOS system must be configured with system log files set to mode 640 or less permissive. $i" >> "$auditfilelocation"
				/bin/echo $(/bin/date -u) "AOSX_13_002106 fix permissions for $i" | /usr/bin/tee -a "$logFile"
			fi
		fi
	done
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81743
# Group Title: SRG-OS-000206-GPOS-00084
# Rule ID: SV-96457r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002107
# Rule Title: The macOS system must be configured with access control lists (ACLs) for system log files to be set correctly.
# 
# Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain 
# sensitive information that could be used by an attacker. Setting the correct ACLs mitigates this risk.
# 
# Check Content: 
# These commands check for log files that exist on the system and print out the list of ACLs if there are any.
# 
# /usr/bin/sudo ls -ld@ $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
# /usr/bin/sudo ls -ld@ $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
# 
# ACLs will be listed under any file that may contain them (i.e., "0: group:admin allow list,readattr,reaadextattr,readsecurity").
# 
# If any system log file contains this information, this is a finding.
# 
# Fix Text: For any log file that returns an ACL, run the following command:
# 
# /usr/bin/sudo chmod -N [log file]
# 
# [log file] is the full path to the log file in question.  
# 
# CCI: CCI-001314
#
# Verify organizational score
AOSX_13_002107="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002107)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002107" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
			if [[ "$(/bin/ls -lde $i)" != *","* ]]; then
				#/bin/echo "ACLs are correct for $i"
				:
			else
				/bin/echo "* AOSX_13_002107 The macOS system must be configured with access control lists (ACLs) for system log files to be set correctly. $i" >> "$auditfilelocation"
				/bin/echo $(/bin/date -u) "AOSX_13_002107 fix ACLs for $i" | /usr/bin/tee -a "$logFile"
			fi
		fi
	done
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81745
# Group Title: SRG-OS-000365-GPOS-00152
# Rule ID: SV-96459r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002110
# Rule Title: The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.
# 
# Vulnerability Discussion: By auditing access restriction enforcement, changes to application and OS configuration files can be 
# audited. Without auditing the enforcement of access restrictions, it will be difficult to identify attempted attacks and an 
# audit trail will not be available for forensic investigation.
# 
# Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement 
# action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). 
# Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.
# 
# Satisfies: SRG-OS-000365-GPOS-00152, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000463-GPOS-00207, 
# SRG-OS-000465-GPOS-00209, SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00211, SRG-OS-000468-GPOS-00212, SRG-OS-000474-GPOS-00219
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Enforcement actions are logged by way of the "fm" flag, which audits permission changes, and "-fr" and "-fw", 
# which denote failed attempts to read or write to a file.
# 
# If "fm", "-fr", and "-fw" are not listed in the result of the check, this is a finding.
# 
# Fix Text: To set the audit flags to the recommended setting, run the following command to add the flags "fm", "-fr", and "-fw" all at once:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000172
# CCI: CCI-001814
#
# Verify organizational score
AOSX_13_002110="$(/usr/bin/defaults read "$plistlocation" AOSX_13_002110)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_002110" = "1" ]; then
	AOSX_13_002110_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_002110_Audit" = *"fm"* ]] && [[ "$AOSX_13_002110_Audit" = *"-fr"* ]] && [[ "$AOSX_13_002110_Audit" = *"-fw"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_002110 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_002110 -bool false; else
		/bin/echo "* AOSX_13_002110 The macOS system must audit the enforcement actions used to restrict access associated with changes to the system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_002110 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81747
# Group Title: SRG-OS-000030-GPOS-00011
# Rule ID: SV-96461r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_030014
# Rule Title: The macOS system must be configured to lock the user session when a smart token is removed.
# 
# Vulnerability Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate 
# physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
# 
# The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period 
# of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke 
# a session lock so users may secure their session should they need to temporarily vacate the immediate physical vicinity.
# 
# Check Content: 
# To check if support for session locking with removal of a token is enabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "tokenRemovalAction = 1;"
# 
# If there is no result, this is a finding.
# 
# Fix Text: This is now in the smartcard payload.
# <key>tokenRemovalAction</key>
# <integer>1</integer>  
# 
# CCI: CCI-000058
#
# Configuration Profile - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
# Verify organizational score
AOSX_13_030014="$(/usr/bin/defaults read "$plistlocation" AOSX_13_030014)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_030014" = "1" ]; then
	AOSX_13_030014_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'tokenRemovalAction = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_030014_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_030014 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_030014 -bool false; else
		/bin/echo "* AOSX_13_030014 The macOS system must be configured to lock the user session when a smart token is removed via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_030014 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81749
# Group Title: SRG-OS-000067-GPOS-00035
# Rule ID: SV-96463r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_067035
# Rule Title: The macOS system must enable certificate for smartcards.
# 
# Vulnerability Discussion: To prevent untrusted certificates the certificates on a smartcard card must be valid in these ways: 
# its issuer is system-trusted, the certificate is not expired, its "valid-after" date is in the past, and it passes CRL and OCSP checking.
# 
# Check Content: 
# To view the setting for the smartcard certification configuration, run the following command:
# 
# sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep checkCertificateTrust
# 
# If the output is null or not "checkCertificateTrust = 1;" this is a finding.
# 
# Fix Text: This setting is enforced using the "Smartcard" configuration profile.  
# 
# CCI: CCI-000186
#
# Configuration Profile - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)
# Verify organizational score
AOSX_13_067035="$(/usr/bin/defaults read "$plistlocation" AOSX_13_067035)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_067035" = "1" ]; then
	AOSX_13_067035_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'checkCertificateTrust = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_067035_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_067035 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_067035 -bool false; else
		/bin/echo "* AOSX_13_067035 The macOS system must enable certificate for smartcards via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_067035 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-81751
# Group Title: SRG-OS-000362-GPOS-00149
# Rule ID: SV-96465r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_362149
# Rule Title: The macOS system must prohibit user installation of software without explicit privileged status.
# 
# Vulnerability Discussion: Allowing regular users to install software, without explicit privileges, creates the risk that 
# untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative 
# privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.
# 
# Operating system functionality will vary, and while users are not permitted to install unapproved software, there may be 
# instances where the organization allows the user to install approved software packages, such as from an approved software 
# repository.
# 
# The operating system or software configuration management utility must enforce control of software installation by users 
# based upon what types of software installations are permitted (e.g., updates and security patches to existing software) 
# and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious 
# is unknown or suspect) by the organization.
# 
# Check Content: 
# To check if the system is configured to prohibit user installation of software, first check to ensure the Parental 
# Controls are enabled with the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep “/Users"
# 
# If the result is null, or does not contain “/Users/“, this is a finding
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-001812
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Users/"
# Verify organizational score
AOSX_13_362149="$(/usr/bin/defaults read "$plistlocation" AOSX_13_362149)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_13_362149" = "1" ]; then
	AOSX_13_362149_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep '/Users')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_13_362149_Audit" = *"/Users/"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_13_362149 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_13_362149 -bool false; else
		/bin/echo "* AOSX_13_362149 The macOS system must prohibit user installation of software without explicit privileged status via configuration profile." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_13_362149 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

/bin/echo $(/bin/date -u) "Audit complete" | /usr/bin/tee -a "$logFile"
/bin/echo "Run 3_STIG_Remediation (if it has not already run)"

exit 0
