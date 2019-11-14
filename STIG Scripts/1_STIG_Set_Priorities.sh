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
# Admins set organizational compliance for each listed item, which gets written to plist.
# Values default to "true," and must be commented to "false" to disregard as an organizational priority.
# Writes to /Library/Application Support/SecurityScoring/STIG_security_score.plist by default.

# Create the Scoring file destination directory if it does not already exist
LogDir="/Library/Application Support/SecurityScoring"

if [[ ! -e "$LogDir" ]]; then
    /bin/mkdir "$LogDir"
fi
plistlocation="$LogDir/STIG_security_score.plist"

###################################################################
############### ADMINS DESIGNATE STIG VALUES BELOW ################
###################################################################

### EXAMPLE ###
# Severity: CAT X
# Rule Version (STIG-ID): AOSX_13_00000X
# Rule Title: Description
# Configuration Profile - Payload > X > Y > Z (selected)
# AOSX_13_00000X="true"
# AOSX_13_00000X="false"
### EXAMPLE ###

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000005
# Rule Title: The macOS system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.
# A default screen saver must be configured for all users.
## Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
AOSX_13_000005="true"
# AOSX_13_000005="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000006
# Rule Title: The macOS system must be configured to disable hot corners.
## Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0
AOSX_13_000006="true"
# AOSX_13_000006="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000007
# Rule Title: The macOS system must be configured to prevent Apple Watch from terminating a session lock.
## Configuration Profile - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (un-checked)
AOSX_13_000007="true"
# AOSX_13_000007="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000010
# Rule Title: The macOS system must initiate a session lock after a 15-minute period of inactivity.
# A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity. 
## Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
AOSX_13_000010="true"
# AOSX_13_000010="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000020
# Rule Title: The macOS system must retain the session lock until the user reestablishes access using established identification and authentication procedures.
# Users must be prompted to enter their passwords when unlocking the screen saver. 
## Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (checked)
AOSX_13_000020="true"
# AOSX_13_000020="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000025
# Rule Title: The macOS system must initiate the session lock no more than five seconds after a screen saver is started.
## Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time)
AOSX_13_000025="true"
# AOSX_13_000025="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000030
# Rule Title: The macOS system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.
AOSX_13_000030="true"
# AOSX_13_000030="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000035
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote 
# access sessions including transmitted data and data during preparation for transmission – Enable remote access through SSH.
AOSX_13_000035="true"
# AOSX_13_000035="false"
#
# If AOSX_13_000035 is not enforced then SSH should be off.
if [ "$AOSX_13_000035" = "false" ]; then
	AOSX_13_000035off="true"; else
	AOSX_13_000035off="false"
fi

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000050
# Rule Title: The macOS system must be configured to disable rshd service.
AOSX_13_000050="true"
# AOSX_13_000050="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000055
# Rule Title: The macOS system must enforce requirements for remote connections to the information system.
# Check if the Screen Sharing service is disabled.
AOSX_13_000055="true"
# AOSX_13_000055="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000065
# Rule Title: The macOS system must be configured with Bluetooth turned off unless approved by the organization.
## Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
AOSX_13_000065="true"
# AOSX_13_000065="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000070
# Rule Title: The macOS system must be configured with Wi-Fi support software disabled.
AOSX_13_000070="true"
# AOSX_13_000070="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000075
# Rule Title: The macOS system must be configured with Infrared [IR] support disabled.
AOSX_13_000075="true"
# AOSX_13_000075="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000085
# Rule Title: The macOS system must be configured with automatic actions disabled for blank CDs.
## Configuration Profile - Custom payload > com.apple.digihub.blank.cd.appeared > action=1
AOSX_13_000085="true"
# AOSX_13_000085="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000090
# Rule Title: The macOS system must be configured with automatic actions disabled for blank DVDs.
## Configuration Profile - Custom payload > com.apple.digihub.blank.dvd.appeared > action=1
AOSX_13_000090="true"
# AOSX_13_000090="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000095
# Rule Title: The macOS system must be configured with automatic actions disabled for music CDs.
## Configuration Profile - Custom payload > com.apple.digihub.cd.music.appeared > action=1
AOSX_13_000095="true"
# AOSX_13_000095="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000100
# Rule Title: The macOS system must be configured with automatic actions disabled for picture CDs.
## Configuration Profile - Custom payload > com.apple.digihub.cd.picture.appeared > action=1
AOSX_13_000100="true"
# AOSX_13_000100="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000105
# Rule Title: The macOS system must be configured with automatic actions disabled for video DVDs.
## Configuration Profile - Custom payload > com.apple.digihub.dvd.video.appeared > action=1
AOSX_13_000105="true"
# AOSX_13_000105="false"

# NULL – Managed by a directory server (AD).
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000110
# Rule Title: The macOS system must automatically remove or disable temporary user accounts after 72 hours.
# AOSX_13_000110="true"
AOSX_13_000110="false"

# NULL – Managed by a directory server (AD).
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000115
# Rule Title: The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
# AOSX_13_000115="true"
AOSX_13_000115="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000120
# Rule Title: The macOS system must generate audit records for all account creations, modifications, disabling, and termination events; 
# privileged activities or other system-level access; all kernel module load, unload, and restart actions; all program initiations; 
# and organizationally defined events for all non-local maintenance and diagnostic sessions.
AOSX_13_000120="true"
# AOSX_13_000120="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000139
# Rule Title: The macOS system must be configured to disable SMB File Sharing unless it is required.
AOSX_13_000139="true"
# AOSX_13_000139="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000140
# Rule Title: The macOS system must be configured to disable Apple File (AFP) Sharing.
AOSX_13_000140="true"
# AOSX_13_000140="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000141
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.
AOSX_13_000141="true"
# AOSX_13_000141="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000142
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) lock daemon unless it is required.
# UPDATE FOR 10.14 – No longer required
# AOSX_13_000142="true"
AOSX_13_000142="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000143
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) stat daemon unless it is required.
# UPDATE FOR 10.14 – No longer required
# AOSX_13_000143="true"
AOSX_13_000143="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000155
# Rule Title: The macOS system firewall must be configured with a default-deny policy.
# The recommended system is the McAfee HBSS. 
# Managed by McAfee EPO.
AOSX_13_000155="true"
# AOSX_13_000155="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000186
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system.
AOSX_13_000186="true"
# AOSX_13_000186="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000187
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
AOSX_13_000187="true"
# AOSX_13_000187="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000195
# Rule Title: The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.
AOSX_13_000195="true"
# AOSX_13_000195="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000200
# Rule Title: The macOS system must generate audit records for DoD-defined events such as successful/unsuccessful logon attempts, successful/unsuccessful 
# direct access attempts, starting and ending time for user access, and concurrent logons to the same account from different sources.
AOSX_13_000200="true"
# AOSX_13_000200="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000230
# Rule Title: The macOS system must initiate session audits at system startup.
AOSX_13_000230="true"
# AOSX_13_000230="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000240
# Rule Title: The macOS system must enable System Integrity Protection.
AOSX_13_000240="true"
# AOSX_13_000240="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000295
# Rule Title: The macOS system must allocate audit record storage capacity to store at least one weeks worth of audit records when audit 
# records are not immediately sent to a central audit record storage facility.
AOSX_13_000295="true"
# AOSX_13_000295="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000305
# Rule Title: The macOS system must provide an immediate warning to the System Administrator (SA) and Information System Security Officer 
# (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.
AOSX_13_000305="true"
# AOSX_13_000305="false"

# Rule Version (STIG-ID): AOSX_13_000310
# Rule Title: The macOS system must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, of all audit failure events requiring real-time alerts.
# Severity: CAT II
AOSX_13_000310="true"
# AOSX_13_000310="false"

# UPDATE FOR 10.14
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000330
# Rule Title: The macOS system must, for networked systems, compare internal information system clocks at least every 24 hours with a server 
# that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the 
# appropriate DoD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).
# AOSX_13_000330A - Ensure the NTP service is running.
# AOSX_13_000330B - Ensure an authorized NTP server is configured.
AOSX_13_000330="true"
# AOSX_13_000330="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000331
# Rule Title: The macOS system must be configured with audit log files owned by root.
AOSX_13_000331="true"
# AOSX_13_000331="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000332
# Rule Title: The macOS system must be configured with audit log folders owned by root.
AOSX_13_000332="true"
# AOSX_13_000332="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000333
# Rule Title: The macOS system must be configured with audit log files group-owned by wheel.
AOSX_13_000333="true"
# AOSX_13_000333="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000334
# Rule Title: The macOS system must be configured with audit log folders group-owned by wheel.
AOSX_13_000334="true"
# AOSX_13_000334="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000335
# Rule Title: The macOS system must be configured with audit log files set to mode 440 or less permissive.
AOSX_13_000335="true"
# AOSX_13_000335="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000336
# Rule Title: The macOS system must be configured with audit log folders set to mode 700 or less permissive.
AOSX_13_000336="true"
# AOSX_13_000336="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000337
# Rule Title: The macOS system must be configured so that log files must not contain access control lists (ACLs).
AOSX_13_000337="true"
# AOSX_13_000337="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000338
# Rule Title: The macOS system must be configured so that log folders must not contain access control lists (ACLs).
AOSX_13_000338="true"
# AOSX_13_000338="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000430
# Rule Title: The macOS system must have the security assessment policy subsystem enabled.
AOSX_13_000430="true"
# AOSX_13_000430="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000475
# Rule Title: The macOS system must be configured to disable the application FaceTime.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app/"
AOSX_13_000475="true"
# AOSX_13_000475="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000490
# Rule Title: The macOS system must be configured to disable the application Messages.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Messages.app/"
AOSX_13_000490="true"
# AOSX_13_000490="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000505
# Rule Title: The macOS system must be configured to disable the iCloud Calendar services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
AOSX_13_000505="true"
# AOSX_13_000505="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000507
# Rule Title: The macOS system must be configured to disable the iCloud Reminders services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
AOSX_13_000507="true"
# AOSX_13_000507="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000510
# Rule Title: The macOS system must be configured to disable iCloud Address Book services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
AOSX_13_000510="true"
# AOSX_13_000510="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000515
# Rule Title: The macOS system must be configured to disable the iCloud Mail services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
AOSX_13_000515="true"
# AOSX_13_000515="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_000517
# Rule Title: The macOS system must be configured to disable the iCloud Notes services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
AOSX_13_000517="true"
# AOSX_13_000517="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000518
# Rule Title: The macOS system must be configured to disable the camera.
## Configuration Profile - Restrictions payload > Functionality > Allow use of Camera (unchecked)
AOSX_13_000518="true"
# AOSX_13_000518="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000520
# Rule Title: The macOS system must be configured to disable the system preference pane for iCloud.
## Configuration Profile - Restrictions payload > Preferences > disable selected items "iCloud"
AOSX_13_000520="true"
# AOSX_13_000520="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000521
# Rule Title: The macOS system must be configured to disable the system preference pane for Internet Accounts.
## Configuration Profile - Restrictions payload > Preferences > disable selected items "Internet Accounts"
AOSX_13_000521="true"
# AOSX_13_000521="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000522
# Rule Title: The macOS system must be configured to disable the system preference pane for Siri.
# AOSX_13_000522 The macOS system must be configured to disable the system preference pane for Siri via configuration profile.
## Configuration Profile - Restrictions payload > Preferences > disable selected items "Dictation & Speech"
AOSX_13_000522="true"
# AOSX_13_000522="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000523
# Rule Title: The macOS system must be configured to disable Siri and dictation.
## Configuration Profile - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
## Configuration Profile - Custom payload > com.apple.assistant.support > allowAssistant=false
AOSX_13_000523="true"
# AOSX_13_000523="false"

# Severity: CAT II
# Rule Version (STIG-ID):  AOSX_13_000530
# Rule Title: The macOS system must be configured to disable sending diagnostic and usage data to Apple.
## Configuration Profile - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
AOSX_13_000530="true"
# AOSX_13_000530="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000531
# Rule Title: The macOS system must be configured to disable the iCloud Find My Mac service.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Find My Mac (unchecked)
AOSX_13_000531="true"
# AOSX_13_000531="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000535
# Rule Title: The macOS system must be configured to disable Location Services.
# This is not recommended by Apple Professional Service.
## Configuration Profile - Custom payload > com.apple.MCX > DisableLocationServices=true
AOSX_13_000535="true"
# AOSX_13_000535="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000545
# Rule Title: The macOS system must be configured to disable Bonjour multicast advertising.
AOSX_13_000545="true"
# AOSX_13_000545="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000550
# Rule Title: The macOS system must be configured to disable the UUCP service.
AOSX_13_000550="true"
# AOSX_13_000550="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000551
# Rule Title: The macOS system must disable the Touch ID feature.
## Configuration Profile - Restrictions payload > Functionality > Allow Touch ID to unlock device (unchecked)
AOSX_13_000551="true"
# AOSX_13_000551="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000552
# Rule Title: The macOS system must obtain updates from a DoD-approved update server.
AOSX_13_000552="true"
# AOSX_13_000552="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000553
# Rule Title: The macOS system must not have a root account.
AOSX_13_000553="true"
# AOSX_13_000553="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000554
# Rule Title: The macOS system must not have a guest account.
## Configuration Profile - Login Window payload > Options > Allow Guest User (unchecked)
AOSX_13_000554="true"
# AOSX_13_000554="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000555
# Rule Title: The macOS system must unload tftpd.
AOSX_13_000555="true"
# AOSX_13_000555="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000556
# Rule Title: The macOS system must disable Siri pop-ups.
## Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
AOSX_13_000556="true"
# AOSX_13_000556="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000557
# Rule Title: The macOS system must disable iCloud Back to My Mac feature.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Back to My Mac (unchecked)
AOSX_13_000557="true"
# AOSX_13_000557="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000558
# Rule Title: The macOS system must disable iCloud Keychain synchronization.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
AOSX_13_000558="true"
# AOSX_13_000558="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000559
# Rule Title: The macOS system must disable iCloud document synchronization.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
AOSX_13_000559="true"
# AOSX_13_000559="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000560
# Rule Title: The macOS system must disable iCloud bookmark synchronization.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
AOSX_13_000560="true"
# AOSX_13_000560="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000561
# Rule Title: The macOS system must disable iCloud Photo Library.
## Configuration Profile - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
AOSX_13_000561="true"
# AOSX_13_000561="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000562
# Rule Title: The macOS system must disable iCloud Desktop And Documents.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive > Desktop & Documents (unchecked)
AOSX_13_000562="true"
# AOSX_13_000562="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000565
# Rule Title: The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
AOSX_13_000565="true"
# AOSX_13_000565="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000570
# Rule Title: The macOS system must implement NSA-approved cryptography to protect classified information in accordance with applicable 
# federal laws, Executive Orders, directives, policies, regulations, and standards.
AOSX_13_000570="true"
# AOSX_13_000570="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000585
# Rule Title: The macOS system must enforce password complexity by requiring that at least one numeric character be used.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > Require alphanumeric value (checked)
# AOSX_13_000585="true"
AOSX_13_000585="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000587
# Rule Title: The macOS system must enforce password complexity by requiring that at least one special character be used.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
## Configuration Profile - Passcode payload > Allow simple value (unchecked)
# AOSX_13_000587="true"
AOSX_13_000587="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000590
# Rule Title: The macOS system must enforce a minimum 15-character password length.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > MINIMUM PASSCODE LENGTH 15
# AOSX_13_000590="true"
AOSX_13_000590="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000605
# Rule Title: The macOS system must not use telnet.
AOSX_13_000605="true"
# AOSX_13_000605="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000606
# Rule Title: The macOS system must not use unencrypted FTP.
AOSX_13_000606="true"
# AOSX_13_000606="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000710
# Rule Title: The macOS system must allow only applications downloaded from the App Store to run.
## Configuration Profile - Security & Privacy payload > General > Mac App Store and identified developers (selected)
AOSX_13_000710="true"
# AOSX_13_000710="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000711
# Rule Title: The macOS system must be configured so that end users cannot override Gatekeeper settings.
## Configuration Profile - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
AOSX_13_000711="true"
# AOSX_13_000711="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000720
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.
AOSX_13_000720="true"
# AOSX_13_000720="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000721
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.
AOSX_13_000721="true"
# AOSX_13_000721="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000722
# Rule Title: The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.
AOSX_13_000722="true"
# AOSX_13_000722="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000750
# Rule Title: The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider.
## Configuration Profile - Certificate payload
AOSX_13_000750="true"
# AOSX_13_000750="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000780
# Rule Title: The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest – FileVault.
AOSX_13_000780="true"
# AOSX_13_000780="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000835
# Rule Title: The macOS system must employ automated mechanisms to determine the state of system components with regard to 
# flaw remediation using the following frequency: continuously where HBSS is used; 30 days for any additional internal network 
# scans not covered by HBSS; and annually for external scans by Computer Network Defense Service Provider (CNDSP).
# The recommended system is the McAfee HBSS.
# Managed by McAfee EPO.
AOSX_13_000835="true"
# AOSX_13_000835="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000850
# Rule Title: The macOS system must restrict the ability of individuals to use USB storage devices.
## Configuration Profile - Restrictions payload > Media > EXTERNAL DISKS: Allow (unchecked) 
AOSX_13_000850="true"
# AOSX_13_000850="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000862
# Rule Title: The macOS system must be configured to not allow iTunes file sharing.
## Configuration Profile - Custom payload > com.apple.applicationaccess > allowiTunesFileSharing=false
AOSX_13_000862="true"
# AOSX_13_000862="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000925
# Rule Title: The macOS system must not allow an unattended or automatic logon to the system.
## Configuration Profile - Login Window payload > Options > Disable automatic login (checked)
AOSX_13_000925="true"
# AOSX_13_000925="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000930
# Rule Title: The macOS system logon window must be configured to prompt for username and password, rather than show a list of users.
## Configuration Profile - Login Window payload > Window > Name and password text fields (selected)
AOSX_13_000930="true"
# AOSX_13_000930="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000950
# Rule Title: The macOS firewall must have logging enabled.
# If HBSS is used, this is not applicable. The recommended system is the McAfee HBSS.
AOSX_13_000950="true"
# AOSX_13_000950="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000955
# Rule Title: The macOS system must be configured so that Bluetooth devices are not allowed to wake the computer.
# Most effectively managed by disabling Bluetooth.
## Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
AOSX_13_000955="true"
# AOSX_13_000955="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000965
# Rule Title: The macOS system must be configured with Bluetooth Sharing disabled.
# Most effectively managed by disabling Bluetooth.
## Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
AOSX_13_000965="true"
# AOSX_13_000965="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_000975
# Rule Title: The macOS system must be configured to disable Remote Apple Events.
AOSX_13_000975="true"
# AOSX_13_000975="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_000995
# Rule Title: The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.
AOSX_13_000995="true"
# AOSX_13_000995="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001080
# Rule Title: The macOS Application Firewall must be enabled.
# If HBSS is used, this is not applicable. The recommended system is the McAfee HBSS.
AOSX_13_001080="true"
# AOSX_13_001080="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001110
# Rule Title: The macOS system must be configured with all public directories owned by root or an application account.
AOSX_13_001110="true"
# AOSX_13_001110="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001115
# Rule Title: The macOS system must be configured with the finger service disabled.
AOSX_13_001115="true"
# AOSX_13_001115="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001120
# Rule Title: The macOS system must be configured with the sticky bit set on all public directories.
AOSX_13_001120="true"
# AOSX_13_001120="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001125
# Rule Title: The macOS system must be configured with the prompt for Apple ID and iCloud disabled.
## Configuration Profile - Login Window payload > Options > Disable Apple ID setup during login (checked)
AOSX_13_001125="true"
# AOSX_13_001125="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001130
# Rule Title: The macOS system must be configured so that users do not have Apple IDs signed into iCloud.
AOSX_13_001130="true"
# AOSX_13_001130="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_001140
# Rule Title: The macOS system must be configured with iTunes Music Sharing disabled.
## Configuration Profile - Custom payload > com.apple.itunes > disableSharedMusic=true
AOSX_13_001140="true"
# AOSX_13_001140="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001145
# Rule Title: All setuid executables on the macOS system must be documented.
AOSX_13_001145="true"
# AOSX_13_001145="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001195
# Rule Title: The macOS system must not accept source-routed IPv4 packets.
AOSX_13_001195="true"
# AOSX_13_001195="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001200
# Rule Title: The macOS system must ignore IPv4 ICMP redirect messages.
AOSX_13_001200="true"
# AOSX_13_001200="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001205
# Rule Title: The macOS system must not have IP forwarding for IPv4 enabled.
AOSX_13_001205="true"
# AOSX_13_001205="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001206
# Rule Title: The macOS system must not have IP forwarding for IPv6 enabled.
AOSX_13_001206="true"
# AOSX_13_001206="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001210
# Rule Title: The macOS system must not send IPv4 ICMP redirects by default.
AOSX_13_001210="true"
# AOSX_13_001210="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001211
# Rule Title: The macOS system must not send IPv6 ICMP redirects by default.
AOSX_13_001211="true"
# AOSX_13_001211="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001215
# Rule Title: The macOS system must prevent local applications from generating source-routed packets.
AOSX_13_001215="true"
# AOSX_13_001215="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001220
# Rule Title: The macOS system must not process Internet Control Message Protocol [ICMP] timestamp requests.
AOSX_13_001220="true"
# AOSX_13_001220="false"

# NULL - There is no way to automate this.
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001235
# Rule Title: The macOS system must have unused network devices disabled.
# AOSX_13_001235="true"
AOSX_13_001235="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001270
# Rule Title: The macOS system must be configured to disable Internet Sharing.
AOSX_13_001270="true"
# AOSX_13_001270="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001275
# Rule Title: The macOS system must be configured to disable Web Sharing.
AOSX_13_001275="true"
# AOSX_13_001275="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001324
# Rule Title: The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15
# AOSX_13_001324="true"
AOSX_13_001324="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001325
# Rule Title: The macOS system must enforce account lockout after the limit of three consecutive invalid logon attempts by a user.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
# AOSX_13_001325="true"
AOSX_13_001325="false"

# NULL - redundant to AOSX_13_001324 and AOSX_13_001325
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001327
# Rule Title: The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
# AOSX_13_001327="true"
AOSX_13_001327="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_001355
# Rule Title: The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).
AOSX_13_001355="true"
# AOSX_13_001355="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_001465
# Rule Title: The macOS system must use a DoD antivirus program.
AOSX_13_001465="true"
# AOSX_13_001465="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_13_002050
# Rule Title: The macOS system must be configured to disable AirDrop.
## Configuration Profile - Restrictions payload > Media > Allow AirDrop (unchecked)
AOSX_13_002050="true"
# AOSX_13_002050="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_13_002060
# Rule Title: The macOS system must be integrated into a directory services infrastructure.
AOSX_13_002060="true"
# AOSX_13_002060="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002085
# Rule Title: The macOS system must enforce a 60-day maximum password lifetime restriction.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > MAXIMUM PASSCODE AGE 60
# AOSX_13_002085="true"
AOSX_13_002085="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002090
# Rule Title: The macOS system must prohibit password reuse for a minimum of five generations.
# DO NOT ENFORCE if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) will lead to unexpected results.
## Configuration Profile - Passcode payload > PASSCODE HISTORY 5
# AOSX_13_002090="true"
AOSX_13_002090="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002105
# Rule Title: The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.
AOSX_13_002105="true"
# AOSX_13_002105="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002106
# Rule Title: The macOS system must be configured with system log files set to mode 640 or less permissive.
AOSX_13_002106="true"
# AOSX_13_002106="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002107
# Rule Title: The macOS system must be configured with access control lists (ACLs) for system log files to be set correctly.
AOSX_13_002107="true"
# AOSX_13_002107="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_002110
# Rule Title: The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.
AOSX_13_002110="true"
# AOSX_13_002110="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_030014
# Rule Title: The macOS system must be configured to lock the user session when a smart token is removed.
## Configuration Profile - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
AOSX_13_030014="true"
# AOSX_13_030014="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_067035
# Rule Title: The macOS system must enable certificate for smartcards.
## Configuration Profile - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)
AOSX_13_067035="true"
# AOSX_13_067035="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_13_362149
# Rule Title: The macOS system must prohibit user installation of software without explicit privileged status.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Users/"
AOSX_13_362149="true"
# AOSX_13_362149="false"

##################################################################
############# DO NOT MODIFY ANYTHING BELOW THIS LINE #############
##################################################################
# Write org_security_score values to local plist

/bin/cat << EOF > "$plistlocation"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>		
		<key>AOSX_13_000005</key>
		<${AOSX_13_000005}/>
		<key>AOSX_13_000006</key>
		<${AOSX_13_000006}/>
		<key>AOSX_13_000007</key>
		<${AOSX_13_000007}/>
		<key>AOSX_13_000010</key>
		<${AOSX_13_000010}/>
		<key>AOSX_13_000020</key>
		<${AOSX_13_000020}/>
		<key>AOSX_13_000025</key>
		<${AOSX_13_000025}/>
		<key>AOSX_13_000030</key>
		<${AOSX_13_000030}/>
		<key>AOSX_13_000035</key>
		<${AOSX_13_000035}/>
		<key>AOSX_13_000035off</key>
		<${AOSX_13_000035off}/>
		<key>AOSX_13_000050</key>
		<${AOSX_13_000050}/>
		<key>AOSX_13_000055</key>
		<${AOSX_13_000055}/>
		<key>AOSX_13_000065</key>
		<${AOSX_13_000065}/>
		<key>AOSX_13_000070</key>
		<${AOSX_13_000070}/>
		<key>AOSX_13_000075</key>
		<${AOSX_13_000075}/>
		<key>AOSX_13_000085</key>
		<${AOSX_13_000085}/>
		<key>AOSX_13_000090</key>
		<${AOSX_13_000090}/>
		<key>AOSX_13_000095</key>
		<${AOSX_13_000095}/>
		<key>AOSX_13_000100</key>
		<${AOSX_13_000100}/>
		<key>AOSX_13_000105</key>
		<${AOSX_13_000105}/>
		<key>AOSX_13_000110</key>
		<${AOSX_13_000110}/>
		<key>AOSX_13_000115</key>
		<${AOSX_13_000115}/>
		<key>AOSX_13_000120</key>
		<${AOSX_13_000120}/>
		<key>AOSX_13_000139</key>
		<${AOSX_13_000139}/>
		<key>AOSX_13_000140</key>
		<${AOSX_13_000140}/>
		<key>AOSX_13_000141</key>
		<${AOSX_13_000141}/>
		<key>AOSX_13_000142</key>
		<${AOSX_13_000142}/>
		<key>AOSX_13_000143</key>
		<${AOSX_13_000143}/>
		<key>AOSX_13_000155</key>
		<${AOSX_13_000155}/>
		<key>AOSX_13_000186</key>
		<${AOSX_13_000186}/>
		<key>AOSX_13_000187</key>
		<${AOSX_13_000187}/>
		<key>AOSX_13_000195</key>
		<${AOSX_13_000195}/>
		<key>AOSX_13_000200</key>
		<${AOSX_13_000200}/>
		<key>AOSX_13_000230</key>
		<${AOSX_13_000230}/>
		<key>AOSX_13_000240</key>
		<${AOSX_13_000240}/>
		<key>AOSX_13_000295</key>
		<${AOSX_13_000295}/>
		<key>AOSX_13_000305</key>
		<${AOSX_13_000305}/>
		<key>AOSX_13_000310</key>
		<${AOSX_13_000310}/>
		<key>AOSX_13_000330A</key>
		<${AOSX_13_000330}/>
		<key>AOSX_13_000330B</key>
		<${AOSX_13_000330}/>
		<key>AOSX_13_000331</key>
		<${AOSX_13_000331}/>
		<key>AOSX_13_000332</key>
		<${AOSX_13_000332}/>
		<key>AOSX_13_000333</key>
		<${AOSX_13_000333}/>
		<key>AOSX_13_000334</key>
		<${AOSX_13_000334}/>
		<key>AOSX_13_000335</key>
		<${AOSX_13_000335}/>
		<key>AOSX_13_000336</key>
		<${AOSX_13_000336}/>
		<key>AOSX_13_000337</key>
		<${AOSX_13_000337}/>
		<key>AOSX_13_000338</key>
		<${AOSX_13_000338}/>
		<key>AOSX_13_000430</key>
		<${AOSX_13_000430}/>
		<key>AOSX_13_000475</key>
		<${AOSX_13_000475}/>
		<key>AOSX_13_000490</key>
		<${AOSX_13_000490}/>
		<key>AOSX_13_000505</key>
		<${AOSX_13_000505}/>
		<key>AOSX_13_000507</key>
		<${AOSX_13_000507}/>
		<key>AOSX_13_000510</key>
		<${AOSX_13_000510}/>
		<key>AOSX_13_000515</key>
		<${AOSX_13_000515}/>
		<key>AOSX_13_000517</key>
		<${AOSX_13_000517}/>
		<key>AOSX_13_000518</key>
		<${AOSX_13_000518}/>
		<key>AOSX_13_000520</key>
		<${AOSX_13_000520}/>
		<key>AOSX_13_000521</key>
		<${AOSX_13_000521}/>
		<key>AOSX_13_000522</key>
		<${AOSX_13_000522}/>
		<key>AOSX_13_000523</key>
		<${AOSX_13_000523}/>
		<key>AOSX_13_000530</key>
		<${AOSX_13_000530}/>
		<key>AOSX_13_000531</key>
		<${AOSX_13_000531}/>
		<key>AOSX_13_000535</key>
		<${AOSX_13_000535}/>
		<key>AOSX_13_000545</key>
		<${AOSX_13_000545}/>
		<key>AOSX_13_000550</key>
		<${AOSX_13_000550}/>
		<key>AOSX_13_000551</key>
		<${AOSX_13_000551}/>
		<key>AOSX_13_000552</key>
		<${AOSX_13_000552}/>
		<key>AOSX_13_000553</key>
		<${AOSX_13_000553}/>
		<key>AOSX_13_000554</key>
		<${AOSX_13_000554}/>
		<key>AOSX_13_000555</key>
		<${AOSX_13_000555}/>
		<key>AOSX_13_000556</key>
		<${AOSX_13_000556}/>
		<key>AOSX_13_000557</key>
		<${AOSX_13_000557}/>
		<key>AOSX_13_000558</key>
		<${AOSX_13_000558}/>
		<key>AOSX_13_000559</key>
		<${AOSX_13_000559}/>
		<key>AOSX_13_000560</key>
		<${AOSX_13_000560}/>
		<key>AOSX_13_000561</key>
		<${AOSX_13_000561}/>
		<key>AOSX_13_000562</key>
		<${AOSX_13_000562}/>
		<key>AOSX_13_000565</key>
		<${AOSX_13_000565}/>
		<key>AOSX_13_000570</key>
		<${AOSX_13_000570}/>
		<key>AOSX_13_000585</key>
		<${AOSX_13_000585}/>
		<key>AOSX_13_000587</key>
		<${AOSX_13_000587}/>
		<key>AOSX_13_000590</key>
		<${AOSX_13_000590}/>
		<key>AOSX_13_000605</key>
		<${AOSX_13_000605}/>
		<key>AOSX_13_000606</key>
		<${AOSX_13_000606}/>
		<key>AOSX_13_000710</key>
		<${AOSX_13_000710}/>
		<key>AOSX_13_000711</key>
		<${AOSX_13_000711}/>
		<key>AOSX_13_000720</key>
		<${AOSX_13_000720}/>
		<key>AOSX_13_000721</key>
		<${AOSX_13_000721}/>
		<key>AOSX_13_000722</key>
		<${AOSX_13_000722}/>
		<key>AOSX_13_000750</key>
		<${AOSX_13_000750}/>
		<key>AOSX_13_000780</key>
		<${AOSX_13_000780}/>
		<key>AOSX_13_000835</key>
		<${AOSX_13_000835}/>
		<key>AOSX_13_000850</key>
		<${AOSX_13_000850}/>
		<key>AOSX_13_000862</key>
		<${AOSX_13_000862}/>
		<key>AOSX_13_000925</key>
		<${AOSX_13_000925}/>
		<key>AOSX_13_000930</key>
		<${AOSX_13_000930}/>
		<key>AOSX_13_000950</key>
		<${AOSX_13_000950}/>
		<key>AOSX_13_000955</key>
		<${AOSX_13_000955}/>
		<key>AOSX_13_000965</key>
		<${AOSX_13_000965}/>
		<key>AOSX_13_000975</key>
		<${AOSX_13_000975}/>
		<key>AOSX_13_000995</key>
		<${AOSX_13_000995}/>
		<key>AOSX_13_001080</key>
		<${AOSX_13_001080}/>
		<key>AOSX_13_001110</key>
		<${AOSX_13_001110}/>
		<key>AOSX_13_001115</key>
		<${AOSX_13_001115}/>
		<key>AOSX_13_001120</key>
		<${AOSX_13_001120}/>
		<key>AOSX_13_001125</key>
		<${AOSX_13_001125}/>
		<key>AOSX_13_001130</key>
		<${AOSX_13_001130}/>
		<key>AOSX_13_001140</key>
		<${AOSX_13_001140}/>
		<key>AOSX_13_001145</key>
		<${AOSX_13_001145}/>
		<key>AOSX_13_001195</key>
		<${AOSX_13_001195}/>
		<key>AOSX_13_001200</key>
		<${AOSX_13_001200}/>
		<key>AOSX_13_001205</key>
		<${AOSX_13_001205}/>
		<key>AOSX_13_001206</key>
		<${AOSX_13_001206}/>
		<key>AOSX_13_001210</key>
		<${AOSX_13_001210}/>
		<key>AOSX_13_001211</key>
		<${AOSX_13_001211}/>
		<key>AOSX_13_001215</key>
		<${AOSX_13_001215}/>
		<key>AOSX_13_001220</key>
		<${AOSX_13_001220}/>
		<key>AOSX_13_001235</key>
		<${AOSX_13_001235}/>
		<key>AOSX_13_001270</key>
		<${AOSX_13_001270}/>
		<key>AOSX_13_001275</key>
		<${AOSX_13_001275}/>
		<key>AOSX_13_001324</key>
		<${AOSX_13_001324}/>
		<key>AOSX_13_001325</key>
		<${AOSX_13_001325}/>
		<key>AOSX_13_001327</key>
		<${AOSX_13_001327}/>
		<key>AOSX_13_001355</key>
		<${AOSX_13_001355}/>
		<key>AOSX_13_001465</key>
		<${AOSX_13_001465}/>
		<key>AOSX_13_002050</key>
		<${AOSX_13_002050}/>
		<key>AOSX_13_002060</key>
		<${AOSX_13_002060}/>
		<key>AOSX_13_002085</key>
		<${AOSX_13_002085}/>
		<key>AOSX_13_002090</key>
		<${AOSX_13_002090}/>
		<key>AOSX_13_002105</key>
		<${AOSX_13_002105}/>
		<key>AOSX_13_002106</key>
		<${AOSX_13_002106}/>
		<key>AOSX_13_002107</key>
		<${AOSX_13_002107}/>
		<key>AOSX_13_002110</key>
		<${AOSX_13_002110}/>
		<key>AOSX_13_030014</key>
		<${AOSX_13_030014}/>
		<key>AOSX_13_067035</key>
		<${AOSX_13_067035}/>
		<key>AOSX_13_362149</key>
		<${AOSX_13_362149}/>
</dict>
</plist>
EOF

/bin/echo "Run 2_STIG_Audit_Compliance"
exit 0
