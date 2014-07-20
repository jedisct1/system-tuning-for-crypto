System tuning recommendations for running cryptographic applications
====================================================================

Generic recommendations
=======================

Disable swap partitions
-----------------------

Disable core dumps
------------------

Disable kernel crash dumps
--------------------------

Disable hibernation/suspend-to-RAM
----------------------------------

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

