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
# 2019-08-12	1.1		Erin McDonald Jamf		added variable for AOSX_13_000330B time server
#####################################################################################################
#
# VARIABLES:
#
ntpServer="" # enter time server for AOSX_13_000330B (i.e. time.apple.com)
#
#####################################################################################################
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

# Append to existing logFile
/bin/echo "$(date -u)" "Beginning remediation" >> "$logFile"
# Create new logFile
# /bin/echo "$(date -u)" "Beginning remediation" > "$logFile"	

if [[ ! -e $plistlocation ]]; then
	/bin/echo "No scoring file present"
	exit 0
fi

#####################################################################################################
# AOSX_13_000005 A default screen saver must be configured for all users via configuration profile.
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
#####################################################################################################

#####################################################################################################
# AOSX_13_000006 The macOS system must be configured to disable hot corners via configuration profile.
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0
#####################################################################################################

#####################################################################################################
# AOSX_13_000007 The macOS system must be configured to prevent Apple Watch from terminating a session lock via configuration profile.
# Configuration Profile - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000010 A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity via configuration profile. 
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
#####################################################################################################

#####################################################################################################
# AOSX_13_000020 Users must be prompted to enter their passwords when unlocking the screen saver via configuration profile.
# Configuration Profile - Security & Privacy Payload > General > Require password after sleep or screen saver begins (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000025 The macOS system must initiate the session lock no more than five seconds after a screen saver is started via configuration profile.
# Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time)
#####################################################################################################

#####################################################################################################
# AOSX_13_000030 Ensure the appropriate flags are enabled for /etc/security/audit_control - lo.
# Verify organizational score
AOSX_13_000030="$(defaults read "$plistlocation" AOSX_13_000030)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000030" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_000030 remediated" | /usr/bin/tee -a "$logFile"
fi
#
#####################################################################################################

#####################################################################################################
# AOSX_13_000035 Enable remote access through SSH.
# Verify organizational score
AOSX_13_000035="$(defaults read "$plistlocation" AOSX_13_000035)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000035" = "1" ]; then
	/bin/launchctl enable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin on
	/bin/echo $(date -u) "AOSX_13_000035 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000035off Disable remote access through SSH.
# Verify organizational score
AOSX_13_000035off="$(defaults read "$plistlocation" AOSX_13_000035off)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000035off" = "1" ]; then
	/bin/launchctl disable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin off
	/bin/echo $(date -u) "AOSX_13_000035off remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000050 The macOS system must be configured to disable rshd service.
# Verify organizational score
AOSX_13_000050="$(defaults read "$plistlocation" AOSX_13_000050)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000050" = "1" ]; then
	/bin/launchctl disable system/com.apple.rshd
	/bin/echo $(date -u) "AOSX_13_000050 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000055 The macOS system must enforce requirements for remote connections to the information system. Disable Screen Sharing service.
# Verify organizational score
AOSX_13_000055="$(defaults read "$plistlocation" AOSX_13_000055)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000055" = "1" ]; then
	/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
	/bin/launchctl disable system/com.apple.screensharing
	/bin/echo $(date -u) "AOSX_13_000055 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000065 The macOS system must be configured with Bluetooth turned off via configuration profile.
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
#####################################################################################################

#####################################################################################################
# AOSX_13_000070 The macOS system must be configured with Wi-Fi support software disabled.
# Verify organizational score
AOSX_13_000070="$(defaults read "$plistlocation" AOSX_13_000070)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000070" = "1" ]; then
	/usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off
	/bin/echo $(date -u) "AOSX_13_000070 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000075 The macOS system must be configured with Infrared [IR] support disabled.
# Verify organizational score
AOSX_13_000075="$(defaults read "$plistlocation" AOSX_13_000075)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000075" = "1" ]; then
	/usr/bin/defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool FALSE  
	/bin/echo $(date -u) "AOSX_13_000075 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000085 The macOS system must be configured with automatic actions disabled for blank CDs via configuration profile.
# Configuration Profile - Custom payload > com.apple.digihub.blank.cd.appeared > action=1
#####################################################################################################

#####################################################################################################
# AOSX_13_000090 The macOS system must be configured with automatic actions disabled for blank DVDs via configuration profile.
# Configuration Profile - Custom payload > com.apple.digihub.blank.dvd.appeared > action=1
#####################################################################################################

#####################################################################################################
# AOSX_13_000095 The macOS system must be configured with automatic actions disabled for music CDs via configuration profile.
# Configuration Profile - Custom payload > com.apple.digihub.cd.music.appeared > action=1
#####################################################################################################

#####################################################################################################
# AOSX_13_000100 The macOS system must be configured with automatic actions disabled for picture CDs via configuration profile.
# Configuration Profile - Custom payload > com.apple.digihub.cd.picture.appeared > action=1
#####################################################################################################

#####################################################################################################
# AOSX_13_000105 The macOS system must be configured with automatic actions disabled for video DVDs via configuration profile.
# Configuration Profile - Custom payload > com.apple.digihub.dvd.video.appeared > action=1
#####################################################################################################

#####################################################################################################
# AOSX_13_000110 The macOS system must automatically remove or disable temporary user accounts after 72 hours. Ensure the system is integrated into a directory services infrastructure.
# Managed by a directory server (AD).
#####################################################################################################

#####################################################################################################
# AOSX_13_000115 The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours. Ensure the system is integrated into a directory services infrastructure.
# Managed by a directory server (AD).
#####################################################################################################

#####################################################################################################
# AOSX_13_000120 Ensure the appropriate flags are enabled for /etc/security/audit_control - ad.
# Verify organizational score
AOSX_13_000120="$(defaults read "$plistlocation" AOSX_13_000120)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000120" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_000120 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000139 The macOS system must be configured to disable SMB File Sharing unless it is required.
# Verify organizational score
AOSX_13_000139="$(defaults read "$plistlocation" AOSX_13_000139)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000139" = "1" ]; then
	/bin/launchctl disable system/com.apple.smbd
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000139 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000140 The macOS system must be configured to disable Apple File (AFP) Sharing.
# Verify organizational score
AOSX_13_000140="$(defaults read "$plistlocation" AOSX_13_000140)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000140" = "1" ]; then
	/bin/launchctl disable system/com.apple.AppleFileServer
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000140 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000141 The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.
# Verify organizational score
AOSX_13_000141="$(defaults read "$plistlocation" AOSX_13_000141)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000141" = "1" ]; then
	/bin/launchctl disable system/com.apple.nfsd
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.nfsd.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000141 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000142 The macOS system must be configured to disable the Network File System (NFS) lock daemon unless it is required.
# Verify organizational score
AOSX_13_000142="$(defaults read "$plistlocation" AOSX_13_000142)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000142" = "1" ]; then
	/bin/launchctl disable system/com.apple.lockd
	#/bin/launchctl unload -wF /System/Library/LaunchDaemons/com.apple.lockd.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000142 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000143 The macOS system must be configured to disable the Network File System (NFS) stat daemon unless it is required.
# Verify organizational score
AOSX_13_000143="$(defaults read "$plistlocation" AOSX_13_000143)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000143" = "1" ]; then
	/bin/launchctl disable system/com.apple.statd.notify
	#/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.statd.notify.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000143 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000155 The macOS system firewall must be configured with a default-deny policy – Managed by McAfee EPO. Install McAfee EPO Agent.
# The recommended system is the McAfee HBSS.
#####################################################################################################

#####################################################################################################
# AOSX_13_000186 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system.
BannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
# Verify organizational score
AOSX_13_000186="$(defaults read "$plistlocation" AOSX_13_000186)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000186" = "1" ]; then
	/bin/echo "$BannerText" > "/etc/banner"
	/bin/chmod 755 "/etc/banner" 
	# create a symbolic link for Message of the Day (motd) – This appears when a new terminal window or session is opened.
	/bin/ln -s /etc/banner /etc/motd
	/bin/chmod 755 "/etc/motd" 
	#
	/bin/echo $(date -u) "AOSX_13_000186 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000187 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
# Verify organizational score
AOSX_13_000187="$(defaults read "$plistlocation" AOSX_13_000187)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000187" = "1" ]; then
	/usr/bin/sed -i.bak 's/^[\#]*#Banner\ none.*/Banner \/etc\/banner/' /etc/ssh/sshd_config
	/bin/echo $(date -u) "AOSX_13_000187 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000195 The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.
PolicyBannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
# Verify organizational score
AOSX_13_000195="$(defaults read "$plistlocation" AOSX_13_000195)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000195" = "1" ]; then
	/bin/echo "$PolicyBannerText" > "/Library/Security/PolicyBanner.txt"
	/bin/chmod 755 "/Library/Security/PolicyBanner."* 
	#
	/bin/echo $(date -u) "AOSX_13_000195 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000200 Ensure the appropriate flags are enabled for /etc/security/audit_control - aa.
# Verify organizational score
AOSX_13_000200="$(defaults read "$plistlocation" AOSX_13_000200)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000200" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_000200 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000230 The macOS system must initiate session audits at system startup.
# Verify organizational score
AOSX_13_000230="$(defaults read "$plistlocation" AOSX_13_000230)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000230" = "1" ]; then
	/bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
	/bin/echo $(date -u) "AOSX_13_000230 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000240 The macOS system must enable System Integrity Protection. To reenable System Integrity Protection, 
# boot the affected system into Recovery mode, launch Terminal from the Utilities menu, and run the following command: 
# "/usr/bin/csrutil enable" or zap the PRAM (reboot then hold down command option p r)
#####################################################################################################

#####################################################################################################
# AOSX_13_000295 Change the value for /etc/security/audit_control - expire-after to 7d.
# Verify organizational score
AOSX_13_000295="$(defaults read "$plistlocation" AOSX_13_000295)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000295" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_000295 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000305 Change the value for /etc/security/audit_control - minfree to 25.
# Verify organizational score
AOSX_13_000305="$(defaults read "$plistlocation" AOSX_13_000305)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000305" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_000305 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000310 Change the value for /etc/security/audit_control - logger to -s.
# Verify organizational score
AOSX_13_000310="$(defaults read "$plistlocation" AOSX_13_000310)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000310" = "1" ]; then
	/usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_000310 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# ADDITIONAL/ALTERNATE - 10.14 uses timed not ntpd. This check works for 10.14 and 10.13.
# AOSX_13_000330A The macOS system must compare internal information system clocks at least every 24 with an NTP server. Set usingnetworktime to on.
# Verify organizational score
AOSX_13_000330A="$(defaults read "$plistlocation" AOSX_13_000330A)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000330A" = "1" ]; then
	/usr/sbin/systemsetup -setusingnetworktime on
	/bin/echo $(date -u) "AOSX_13_000330A remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000330B The macOS system must compare internal information system clocks at least every 24 with an NTP server. Ensure an authorized NTP server is configured.
# Verify organizational score
AOSX_13_000330B="$(defaults read "$plistlocation" AOSX_13_000330B)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000330B" = "1" ]; then
	/usr/sbin/systemsetup -setnetworktimeserver "$ntpServer"
	/bin/echo $(date -u) "AOSX_13_000330B remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000331 The macOS system must be configured with audit log files owned by root.
# Verify organizational score
AOSX_13_000331="$(defaults read "$plistlocation" AOSX_13_000331)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000331" = "1" ]; then
	/usr/sbin/chown root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(date -u) "AOSX_13_000331 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000332 The macOS system must be configured with audit log folders owned by root.
# Verify organizational score
AOSX_13_000332="$(defaults read "$plistlocation" AOSX_13_000332)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000332" = "1" ]; then
	/usr/sbin/chown root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(date -u) "AOSX_13_000332 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000333 The macOS system must be configured with audit log files group-owned by wheel.
# Verify organizational score
AOSX_13_000333="$(defaults read "$plistlocation" AOSX_13_000333)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000333" = "1" ]; then
	/usr/bin/chgrp wheel $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(date -u) "AOSX_13_000333 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000334 The macOS system must be configured with audit log folders group-owned by wheel.
# Verify organizational score
AOSX_13_000334="$(defaults read "$plistlocation" AOSX_13_000334)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000334" = "1" ]; then
	/usr/bin/chgrp wheel $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(date -u) "AOSX_13_000334 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000335 The macOS system must be configured with audit log files set to mode 440 or less permissive.
# Verify organizational score
AOSX_13_000335="$(defaults read "$plistlocation" AOSX_13_000335)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000335" = "1" ]; then
	/bin/chmod 440 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(date -u) "AOSX_13_000335 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000336 The macOS system must be configured with audit log folders set to mode 700 or less permissive.
# Verify organizational score
AOSX_13_000336="$(defaults read "$plistlocation" AOSX_13_000336)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000336" = "1" ]; then
	/bin/chmod 700 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(date -u) "AOSX_13_000336 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000337 The macOS system must be configured so that log files must not contain access control lists (ACLs).
# Verify organizational score
AOSX_13_000337="$(defaults read "$plistlocation" AOSX_13_000337)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000337" = "1" ]; then
	/bin/chmod -N $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(date -u) "AOSX_13_000337 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000338 The macOS system must be configured so that log folders must not contain access control lists (ACLs).
# Verify organizational score
AOSX_13_000338="$(defaults read "$plistlocation" AOSX_13_000338)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000338" = "1" ]; then
	/bin/chmod -N $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(date -u) "AOSX_13_000338 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000430 The macOS system must have the security assessment policy subsystem enabled.
# Verify organizational score
AOSX_13_000430="$(defaults read "$plistlocation" AOSX_13_000430)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000430" = "1" ]; then
	/usr/sbin/spctl --master-enable
	/bin/echo $(date -u) "AOSX_13_000430 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000475 The macOS system must be configured to disable the application FaceTime via configuration profile.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app/"
#####################################################################################################

#####################################################################################################
# AOSX_13_000490 The macOS system must be configured to disable the application Messages via configuration profile.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Messages.app/"
#####################################################################################################

#####################################################################################################
# AOSX_13_000505 The macOS system must be configured to disable the iCloud Calendar services via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000507 The macOS system must be configured to disable the iCloud Reminders services via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000510 The macOS system must be configured to disable iCloud Address Book services via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000515 The macOS system must be configured to disable the iCloud Mail services via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000517 The macOS system must be configured to disable the iCloud Notes services via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000518 The macOS system must be configured to disable the camera via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow use of Camera (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000520 The macOS system must be configured to disable the system preference pane for iCloud via configuration profile.
# Configuration Profile - Restrictions payload > Preferences > disable selected items "iCloud"
#####################################################################################################

#####################################################################################################
# AOSX_13_000521 The macOS system must be configured to disable the system preference pane for Internet Accounts via configuration profile.
# Configuration Profile - Restrictions payload > Preferences > disable selected items "Internet Accounts"
#####################################################################################################

#####################################################################################################
# AOSX_13_000522 The macOS system must be configured to disable the system preference pane for Siri via configuration profile.
# Configuration Profile - Restrictions payload > Preferences > disable selected items "Dictation & Speech"
#####################################################################################################

#####################################################################################################
# AOSX_13_000523 The macOS system must be configured to disable Siri and dictation via configuration profile.
# Configuration Profile - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
# Configuration Profile - Custom payload > com.apple.assistant.support > allowAssistant=false
#####################################################################################################

#####################################################################################################
# AOSX_13_000530 The macOS system must be configured to disable sending diagnostic and usage data to Apple via configuration profile.
# Configuration Profile - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000531 The macOS system must be configured to disable the iCloud Find My Mac service via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Find My Mac (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000535 The macOS system must be configured to disable Location Services via configuration profile.
# Configuration Profile - Custom payload > com.apple.MCX > DisableLocationServices=true
#####################################################################################################

#####################################################################################################
# AOSX_13_000545 The macOS system must be configured to disable Bonjour multicast advertising.
# Verify organizational score
AOSX_13_000545="$(defaults read "$plistlocation" AOSX_13_000545)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000545" = "1" ]; then
	/usr/bin/defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true
	/bin/echo $(date -u) "AOSX_13_000545 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000550 The macOS system must be configured to disable the UUCP service.
# Verify organizational score
AOSX_13_000550="$(defaults read "$plistlocation" AOSX_13_000550)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000550" = "1" ]; then
	/bin/launchctl disable system/com.apple.uucp
	/bin/launchctl unload -wF /System/Library/LaunchDaemons/com.apple.uucp.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000550 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000551 The macOS system must disable the Touch ID feature via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow Touch ID to unlock device (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000552 The macOS system must obtain updates from a DoD-approved update server. Apple is considered a DoD-approved source.
# Verify organizational score
AOSX_13_000552="$(defaults read "$plistlocation" AOSX_13_000552)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000552" = "1" ]; then
	/usr/bin/defaults delete /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL
	/bin/echo $(date -u) "AOSX_13_000552 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000553 The macOS system must not have a root account. Disable root manually using the command: dsenableroot -d
# The dsenableroot command is interactive and requires password entry. It is not ideal for a script.
# Optionally (not STIG approved) – /usr/bin/dscl . -create /Users/root UserShell /usr/bin/false
#####################################################################################################

#####################################################################################################
# AOSX_13_000554 The macOS system must not have a guest account via configuration profile.
# Configuration Profile - Login Window payload > Options > Allow Guest User (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000555 The macOS system must unload tftpd.
# Verify organizational score
AOSX_13_000555="$(defaults read "$plistlocation" AOSX_13_000555)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000555" = "1" ]; then
	/bin/launchctl disable system/com.apple.tftp
	/bin/launchctl unload -w /System/Library/LaunchDaemons/tftp.plist # legacy command
	/bin/echo $(date -u) "AOSX_13_000555 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000556 The macOS system must disable Siri pop-ups via configuration profile.
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000557 The macOS system must disable iCloud Back to My Mac feature via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Back to My Mac (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000558 The macOS system must disable iCloud Keychain synchronization via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000559 The macOS system must disable iCloud document synchronization via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000560 The macOS system must disable iCloud bookmark synchronization via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000561 The macOS system must disable iCloud Photo Library via configuration profile.
# Configuration Profile - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
#####################################################################################################

#####################################################################################################
# AOSX_13_000561 The macOS system must disable iCloud Desktop And Documents via configuration profile.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive > Desktop & Documents (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000565 The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
# Verify organizational score
AOSX_13_000565="$(defaults read "$plistlocation" AOSX_13_000565)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000565" = "1" ]; then
	/usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
	/bin/echo $(date -u) "AOSX_13_000565 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000570 The macOS system must implement NSA-approved cryptography to protect classified information...
# Verify organizational score
AOSX_13_000570="$(defaults read "$plistlocation" AOSX_13_000570)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000570" = "1" ]; then
	# /usr/bin/sed -i.bak 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config # This command only works if "#Protocol" exists in the sshd_config.
	/bin/echo "Protocol 2" >> /etc/ssh/sshd_config
	/bin/echo $(date -u) "AOSX_13_000570 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000585 The macOS system must enforce password complexity by requiring that at least one numeric character be used via configuration profile.
# Configuration Profile - Passcode payload > Require alphanumeric value (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000587 The macOS system must enforce password complexity by requiring that at least one special character be used via configuration profile.
# Configuration Profile - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
# Configuration Profile - Passcode payload > Allow simple value (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000590 The macOS system must enforce a minimum 15-character password length via configuration profile.
# Configuration Profile - Passcode payload > MINIMUM PASSCODE LENGTH 15
#####################################################################################################

#####################################################################################################
# AOSX_13_000605 The macOS system must not use telnet.
# Verify organizational score
AOSX_13_000605="$(defaults read "$plistlocation" AOSX_13_000605)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000605" = "1" ]; then
	/bin/launchctl disable system/com.apple.telnetd
	/bin/echo $(date -u) "AOSX_13_000605 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000606 The macOS system must not use unencrypted FTP.
# Verify organizational score
AOSX_13_000606="$(defaults read "$plistlocation" AOSX_13_000606)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000606" = "1" ]; then
	/bin/launchctl disable system/com.apple.ftpd
	/bin/echo $(date -u) "AOSX_13_000606 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000710 The macOS system must allow only applications downloaded from the App Store to run via configuration profile.
# Configuration Profile - Security & Privacy payload > General > Mac App Store and identified developers (selected)
#####################################################################################################

#####################################################################################################
# AOSX_13_000711 The macOS system must be configured so that end users cannot override Gatekeeper settings via configuration profile.
# Configuration Profile - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000720 The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.
# Verify organizational score
AOSX_13_000720="$(defaults read "$plistlocation" AOSX_13_000720)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000720" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config
	/bin/echo $(date -u) "AOSX_13_000720 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000721 The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.
# Verify organizational score
AOSX_13_000721="$(defaults read "$plistlocation" AOSX_13_000721)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000721" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
	/bin/echo $(date -u) "AOSX_13_000721 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000722 The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.
# Verify organizational score
AOSX_13_000722="$(defaults read "$plistlocation" AOSX_13_000722)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000722" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
	/bin/echo $(date -u) "AOSX_13_000722 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000750 The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider via configuration profile.
# Configuration Profile - Certificate payload
#####################################################################################################

#####################################################################################################
# AOSX_13_000780 The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest – Enable FileVault.
#####################################################################################################

#####################################################################################################
# AOSX_13_000835 The macOS system must employ automated mechanisms to determine the state of system components with regard to flaw remediation – Managed by McAfee EPO. Install McAfee EPO Agent.
# The recommended system is the McAfee HBSS.
#####################################################################################################

#####################################################################################################
# AOSX_13_000850 The macOS system must restrict the ability of individuals to use USB storage devices via configuration profile.
# Configuration Profile - Restrictions payload > Media > EXTERNAL DISKS: Allow (unchecked) 
#####################################################################################################

#####################################################################################################
# AOSX_13_000862 The macOS system must be configured to not allow iTunes file sharing via configuration profile.
# Configuration Profile - Custom payload > com.apple.applicationaccess > allowiTunesFileSharing=false
#####################################################################################################

#####################################################################################################
# AOSX_13_000925 The macOS system must not allow an unattended or automatic logon to the system via configuration profile.
# Configuration Profile - Login Window payload > Options > Disable automatic login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000930 The macOS system logon window must be configured to prompt for username and password, rather than show a list of users via configuration profile.
# Configuration Profile - Login Window payload > Window > Name and password text fields (selected)
#####################################################################################################

#####################################################################################################
# AOSX_13_000950 The macOS firewall must have logging enabled. If HBSS is used, this is not applicable. The recommended system is the McAfee HBSS.
# Verify organizational score
AOSX_13_000950="$(defaults read "$plistlocation" AOSX_13_000950)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000950" = "1" ]; then
	/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
	/bin/echo $(date -u) "AOSX_13_000950 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000955 The macOS system must be configured so that Bluetooth devices are not allowed to wake the computer. The macOS system must be configured with Bluetooth turned off via configuration profile.
# Most effectively managed by disabling Bluetooth.
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
#####################################################################################################

#####################################################################################################
# AOSX_13_000965 The macOS system must be configured with Bluetooth Sharing disabled. The macOS system must be configured with Bluetooth turned off via configuration profile.
# Most effectively managed by disabling Bluetooth.
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
#####################################################################################################

#####################################################################################################
# AOSX_13_000975 The macOS system must be configured to disable Remote Apple Events.
# Verify organizational score
AOSX_13_000975="$(defaults read "$plistlocation" AOSX_13_000975)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000975" = "1" ]; then
	/bin/launchctl disable system/com.apple.AEServer
	/bin/echo $(date -u) "AOSX_13_000975 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_000995 The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.
# Verify organizational score
AOSX_13_000995="$(defaults read "$plistlocation" AOSX_13_000995)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_000995" = "1" ]; then
	/bin/echo "Defaults tty_tickets" >> /etc/sudoers
	/bin/echo $(date -u) "AOSX_13_000995 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001080 The macOS Application Firewall must be enabled. If HBSS is used, this is not applicable. The recommended system is the McAfee HBSS.
# Verify organizational score
AOSX_13_001080="$(defaults read "$plistlocation" AOSX_13_001080)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001080" = "1" ]; then
	/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
	/bin/echo $(date -u) "AOSX_13_001080 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001110 The macOS system must be configured with all public directories owned by root or an application account.
# Verify organizational score
AOSX_13_001110="$(defaults read "$plistlocation" AOSX_13_001110)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001110" = "1" ]; then
	/usr/bin/find -x / -type d -perm +o+w -not \( -uid 0 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null -exec chown root {} \;
	/bin/echo $(date -u) "AOSX_13_001110 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001115 The macOS system must be configured with the finger service disabled.
# Verify organizational score
AOSX_13_001115="$(defaults read "$plistlocation" AOSX_13_001115)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001115" = "1" ]; then
	/bin/launchctl disable system/com.apple.fingerd
	/bin/echo $(date -u) "AOSX_13_001115 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001120 The macOS system must be configured with the sticky bit set on all public directories.
# Verify organizational score
AOSX_13_001120="$(defaults read "$plistlocation" AOSX_13_001120)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001120" = "1" ]; then
	/usr/bin/find -x / -type d -perm -0002 -a -not \( -perm -1000 -o -path '/System/' -o -path '/System/Library/' -o -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' -o -path '/private/var/db/*' -o -path '/private/var/folders/*' -o -path '*/Caches/*' -o -path '*/tmp/*' \) 2>/dev/null -exec chmod +t {} \;
	/bin/echo $(date -u) "AOSX_13_001120 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001125 The macOS system must be configured with the prompt for Apple ID and iCloud disabled via configuration profile.
# Configuration Profile - Login Window payload > Options > Disable Apple ID setup during login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_001130 The macOS system must be configured so that users do not have Apple IDs signed into iCloud.
# This must be resolved manually. With the affected user logged on, open System Preferences >> iCloud. Choose "Sign Out".  
#####################################################################################################

#####################################################################################################
# AOSX_13_001140 The macOS system must be configured with iTunes Music Sharing disabled via configuration profile.
# Configuration Profile - Custom payload > com.apple.itunes > disableSharedMusic=true
#####################################################################################################

#####################################################################################################
# AOSX_13_001145 All setuid executables on the macOS system must be documented.
#####################################################################################################

#####################################################################################################
# AOSX_13_001195 The macOS system must not accept source-routed IPv4 packets.
# Verify organizational score
AOSX_13_001195="$(defaults read "$plistlocation" AOSX_13_001195)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001195" = "1" ]; then
	/usr/sbin/sysctl net.inet.ip.accept_sourceroute=0
	/bin/echo $(date -u) "AOSX_13_001195 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001200 The macOS system must ignore IPv4 ICMP redirect messages.
# Verify organizational score
AOSX_13_001200="$(defaults read "$plistlocation" AOSX_13_001200)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001200" = "1" ]; then
	/usr/sbin/sysctl net.inet.icmp.drop_redirect=1
	/bin/echo $(date -u) "AOSX_13_001200 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001205 The macOS system must not have IP forwarding for IPv4 enabled.
# Verify organizational score
AOSX_13_001205="$(defaults read "$plistlocation" AOSX_13_001205)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001205" = "1" ]; then
	/usr/sbin/sysctl net.inet.ip.forwarding=0
	/bin/echo $(date -u) "AOSX_13_001205 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001206 The macOS system must not have IP forwarding for IPv6 enabled.
# Verify organizational score
AOSX_13_001206="$(defaults read "$plistlocation" AOSX_13_001206)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001206" = "1" ]; then
	/usr/sbin/sysctl net.inet6.ip6.forwarding=0
	/bin/echo $(date -u) "AOSX_13_001206 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001210 The macOS system must not send IPv4 ICMP redirects by default.
# Verify organizational score
AOSX_13_001210="$(defaults read "$plistlocation" AOSX_13_001210)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001210" = "1" ]; then
	/usr/sbin/sysctl net.inet.ip.redirect=0
	/bin/echo $(date -u) "AOSX_13_001210 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001211 The macOS system must not send IPv6 ICMP redirects by default.
# Verify organizational score
AOSX_13_001211="$(defaults read "$plistlocation" AOSX_13_001211)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001211" = "1" ]; then
	/usr/sbin/sysctl net.inet6.ip6.redirect=0
	/bin/echo $(date -u) "AOSX_13_001211 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001215 The macOS system must prevent local applications from generating source-routed packets.
# Verify organizational score
AOSX_13_001215="$(defaults read "$plistlocation" AOSX_13_001215)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001215" = "1" ]; then
	/usr/sbin/sysctl net.inet.ip.sourceroute=0
	/bin/echo $(date -u) "AOSX_13_001215 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001220 The macOS system must not process Internet Control Message Protocol [ICMP] timestamp requests.
# Verify organizational score
AOSX_13_001220="$(defaults read "$plistlocation" AOSX_13_001220)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001220" = "1" ]; then
	/usr/sbin/sysctl net.inet.icmp.timestamp=0 
	/bin/echo $(date -u) "AOSX_13_001220 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001270 The macOS system must be configured to disable Internet Sharing.
# Verify organizational score
AOSX_13_001270="$(defaults read "$plistlocation" AOSX_13_001270)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001270" = "1" ]; then
	/bin/launchctl disable system/com.apple.NetworkSharing
	/bin/echo $(date -u) "AOSX_13_001270 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001275 The macOS system must be configured to disable Web Sharing.
# Verify organizational score
AOSX_13_001275="$(defaults read "$plistlocation" AOSX_13_001275)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001275" = "1" ]; then
	/bin/launchctl disable system/org.apache.httpd
	/bin/echo $(date -u) "AOSX_13_001275 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001324 The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts via configuration profile.
# Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15
#####################################################################################################

#####################################################################################################
# AOSX_13_001325 The macOS system must enforce account lockout after the limit of three consecutive invalid logon attempts by a user via configuration profile.
# Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
#####################################################################################################

#####################################################################################################
# AOSX_13_001327 The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked via configuration profile.
# NULL - redundant to AOSX_13_001324 and AOSX_13_001325
#####################################################################################################

#####################################################################################################
# AOSX_13_001355 The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).
# Verify organizational score
AOSX_13_001355="$(defaults read "$plistlocation" AOSX_13_001355)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_001355" = "1" ]; then
	/usr/bin/sed -i.bak '/^policy/ s/$/,ahlt/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_001355 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_001465 The macOS system must use a DoD antivirus program – Managed by McAfee EPO. Install McAfee EPO Agent.
# The recommended system is the McAfee HBSS.
#####################################################################################################

#####################################################################################################
# AOSX_13_002050 The macOS system must be configured to disable AirDrop via configuration profile.
# Configuration Profile - Restrictions payload > Media > Allow AirDrop (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_002060 The macOS system must be integrated into a directory services infrastructure.
# Managed by a directory server (AD).
#####################################################################################################

#####################################################################################################
# AOSX_13_002085 The macOS system must enforce a 60-day maximum password lifetime restriction via configuration profile.
# Configuration Profile - Passcode payload > MAXIMUM PASSCODE AGE 60
#####################################################################################################

#####################################################################################################
# AOSX_13_002090 The macOS system must prohibit password reuse for a minimum of five generations.
# Configuration Profile - Passcode payload > PASSCODE HISTORY 5
#####################################################################################################

#####################################################################################################
# AOSX_13_002105 The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.
# Verify organizational score
AOSX_13_002105="$(defaults read "$plistlocation" AOSX_13_002105)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_002105" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
		/usr/sbin/chown root:admin $i
		#/bin/ls -al $i
		fi
	done
	/bin/echo $(date -u) "AOSX_13_002105 remediated" | /usr/bin/tee -a "$logFile"
	/usr/bin/defaults write "$plistlocation" AOSX_13_002105 -bool false
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_002106 The macOS system must be configured with system log files set to mode 640 or less permissive.
# Verify organizational score
AOSX_13_002106="$(defaults read "$plistlocation" AOSX_13_002106)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_002106" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
		/bin/chmod 640 $i
		#/bin/ls -al $i
		fi
	done
	/bin/echo $(date -u) "AOSX_13_002106 remediated" | /usr/bin/tee -a "$logFile"
	/usr/bin/defaults write "$plistlocation" AOSX_13_002106 -bool false
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_002107 The macOS system must be configured with access control lists (ACLs) for system log files to be set correctly.
# Verify organizational score
AOSX_13_002107="$(defaults read "$plistlocation" AOSX_13_002107)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_002107" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
		/bin/chmod -N $i
		#/bin/ls -lde $i
		fi
	done
	/bin/echo $(date -u) "AOSX_13_002107 remediated" | /usr/bin/tee -a "$logFile"
	/usr/bin/defaults write "$plistlocation" AOSX_13_002107 -bool false
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_002110 The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.
# Verify organizational score
AOSX_13_002110="$(defaults read "$plistlocation" AOSX_13_002110)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_13_002110" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(date -u) "AOSX_13_002110 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_13_030014 The macOS system must be configured to lock the user session when a smart token is removed via configuration profile.
# Configuration Profile - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
#####################################################################################################

#####################################################################################################
# AOSX_13_067035 The macOS system must enable certificate for smartcards via configuration profile.
# Configuration Profile - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)
#####################################################################################################

#####################################################################################################
# AOSX_13_362149 The macOS system must prohibit user installation of software without explicit privileged status via configuration profile.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Users/"
#####################################################################################################

/bin/echo $(date -u) "Remediation complete" | /usr/bin/tee -a "$logFile"
/bin/echo "Re-run 2_STIG_Audit_Compliance"
exit 0
