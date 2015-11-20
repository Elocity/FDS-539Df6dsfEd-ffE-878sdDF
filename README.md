# FDS-539Df6dsfEd-ffE-878sdDF
SBS

[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 30
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 5
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 60
ForceLogoffWhenHourExpire = 1
ClearTextPassword = 1
LSAAnonymousNameLookup = 0
EnableAdminAccount = 1
EnableGuestAccount = 0
[System Log]
RestrictGuestAccess = 1
[Security Log]
MaximumLogSize = 99968
RestrictGuestAccess = 1
[Application Log]
RestrictGuestAccess = 1
[Event Audit]
AuditSystemEvents = 1
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 1
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3
[Registry Values]
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,2
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,COMCFG
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,1
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,4
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,1
MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,Enforced by Troy InSecT.,Silas and Brandon
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"Enforced by Troy InSecT."
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,1
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"0"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,"1"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,"1"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeNetworkLogonRight = *S-1-5-32-544
SeTcbPrivilege =
SeMachineAccountPrivilege = *S-1-5-32-544
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeRemoteInteractiveLogonRight =
SeSystemtimePrivilege = *S-1-5-32-544
SeTimeZonePrivilege = *S-1-5-32-544
SeDebugPrivilege =
SeCreatePermanentPrivilege =
SeDenyNetworkLogonRight = *S-1-5-7,Built-in Administrator,*S-1-5-32-546,*S-1-5-32-555,Support_388945a0
SeDenyBatchLogonRight = *S-1-5-32-555,*S-1-5-32-545
SeDenyServiceLogonRight = *S-1-5-32-546,*S-1-5-32-555,*S-1-5-32-545
SeDenyInteractiveLogonRight = *S-1-5-32-546,*S-1-5-32-555
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-32-555,*S-1-5-32-545
SeEnableDelegationPrivilege =
SeRemoteShutdownPrivilege =
SeAuditPrivilege =
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-6
SeIncreaseWorkingSetPrivilege =
SeIncreaseBasePriorityPrivilege =
SeLoadDriverPrivilege =
SeLockMemoryPrivilege = *S-1-5-32-544
SeBatchLogonRight =
SeServiceLogonRight =
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeSyncAgentPrivilege =
SeTakeOwnershipPrivilege = *S-1-5-32-544
[Service General Setting]
"ALG",4,""
"AxInstSV",4,""
"AppMgmt",4,""
"BDESVC",2,"D:AR(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
"EventSystem",4,""
"Dhcp",4,""
"DFServ",4,""
"TrkWks",4,""
"MSDTC",4,""
"Fax",4,""
"HomeGroupProvider",4,""
"SharedAccess",4,""
"iphlpsvc",4,""
"Microsoft SharePoint Workspace Audit Service",4,""
"NetMsmqActivator",4,""
"NetPipeActivator",4,""
"NetTcpActivator",4,""
"NetTcpPortSharing",4,""
"PlugPlay",4,""
"Spooler",4,""
"ProtectedStorage",2,""
"RasAuto",4,""
"RasMan",4,""
"SessionEnv",4,""
"TermService",4,""
"UmRdpService",4,""
"RpcLocator",4,""
"RemoteRegistry",4,""
"RemoteAccess",4,""
"seclogon",4,""
"SstpSvc",4,""
"ShellHWDetection",4,""
"SCardSvr",4,""
"SNMPTRAP",4,""
"SSDPSRV",4,""
"TabletInputService",4,""
"lmhosts",4,""
"upnphost",4,""
"TapiSrv",4,""
"TBS",4,""
"vds",4,""
"VSS",4,""
"WebClient",4,""
"SDRSVC",2,""
"WinDefend",2,""
"wudfsvc",4,""
"MpsSvc",2,""
"ehRecvr",4,""
"ehSched",4,""
"WMPNetworkSvc",4,""
"WinRM",4,""
"WinHttpAutoProxySvc",4,""
"wuauserv",2,""
[Version]
signature="$CHICAGO$"
Revision=1
[Profile Description]
Description=Windows SecTemp© Silas Shen and Brandon Shin2015 
