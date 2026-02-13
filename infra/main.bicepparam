// Bicep parameters file for PrivilegeGuard deployment
using 'main.bicep'

param projectName = 'privguard'
param pythonVersion = '3.11'
param backupJobSchedule = '0 55 1 * * *'
param backupJobDurationMinutes = 35
