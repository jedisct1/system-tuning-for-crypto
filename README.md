System tuning recommendations for running cryptographic applications
====================================================================

Generic recommendations
=======================

Disable swap partitions
-----------------------

#### Windows

1. Navigate to the `Control Panel` and click `System`
2. Select `Advanced System Settings`
3. In the `Advanced` tab under the `Performance` section, click `Settings`
4. In the `Advanced` Tab under `Virtual Memory` section, click `Change`
5. Untick `Automatically manage paging file size for all drives` 
6. Select each drive listed and select the `No paging file` radio button for each.

Disable core dumps
------------------

Disable kernel crash dumps
--------------------------

#### Windows

1. Navigate to the `Control Panel` and click `System`
2. Select `Advanced System Settings`
3. In the `Advanced` tab under the `Startup and Recovery` section, click `Settings`
4. Under the `System Failure` section, change the `Write debugging information` drop down to `(none)`

Disable hibernation/suspend-to-RAM
----------------------------------

#### Windows

1. Open a `Command Prompt` with Administrator privileges.
2. Type `powercfg -h off` and hit enter.

Run on bare metal
-----------------

Disable hyperthreading
----------------------

Linux-specific recommendations
==============================

Disable ptrace(2) capability
----------------------------

```bash
# lcap CAP_SYS_PTRACE
```

Use CPU affinity
----------------

Use grsec
---------

FreeBSD-specific recommendations
================================

Disable ptrace(2), procfs(5), ktrace(2), hwpmc(4) and other debugging primitives.
-----------------

```bash
# sysctl -w security.bsd.unprivileged_proc_debug=0
```

Windows specific recommendations
================================

Disable sending data to Microsoft
---------------------------------

All registry entries are `DWORD` and under the `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\` key.

Location | Name | Value
:--- | :--- | :--- | :---
PCHealth\ErrorReporting\ | DoReport | 0
SQMClient\Windows\ | CEIPEnable | 0
Windows Defender\Spynet\ | SpyNetReporting | 0
Windows\AppCompat\ | DisableInventory | 1
Windows\AppCompat\ | DisablePcaUI | 0
Windows\ScriptedDiagnosticsProvider\Policy\ | EnableQueryRemoteServer | 0
Windows\System\ | EnableSmartScreen | 0
Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ | ScenarioExecutionEnabled | 0
Windows\Windows Error Reporting\ | AutoApproveOSDumps | 0
Windows\Windows Error Reporting\ | Disabled | 1
Windows\Windows Error Reporting\ | DontSendAdditionalData | 1
