#!/bin/bash

# STIG Security Reporting - Set UID File List

auditfile=/Library/Application\ Support/SecurityScoring/STIG_suidfilelist
echo "<result>$(cat "$auditfile")</result>"