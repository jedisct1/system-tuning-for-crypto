
# Hardening your infrastructure to mitigate leaks of sensitive data

Using encryption, choosing strong passwords, and properly generating secret keys is often perceived as all it takes to ensure that sensitive data remain confidential.

However, the operating system can still be leaking these data. Let's review some common sources of leaks that are frequently overlooked, even by security professionals.

# In-memory data

Even if there is currently a lot of research to mitigate this, sensitive data typically has to be stored unencrypted in memory in order to be processed.

Is credit card information safe if it only resides in RAM?

As demonstrated by point-of-sale malware such as Dexter and Alina, it is certainly not. These malware do not attempt to inspect the network traffic, where the information is encrypted. Instead, they constantly scrape the memory of compromised systems in order to find and exfiltrate the data after they have been decrypted by the system.

Accessing the memory doesn't even require a machine to be compromised by a piece malware. By design, the Firewire and Thunderbolt interfaces found on many modern laptops and workstations provide direct access to the main memory.

Tools such as [Winlockpwn](http://www.breaknenter.org/tag/winlockpwn/) and more recently [Inception](http://www.breaknenter.org/projects/inception/) make it trivial for anyone to dump the memory of a live system using these interfaces. And the attack will likely go unnoticed.

Therefore, sensitive data should be present in memory for the shortest possible amount of time. In particular, plaintext passwords stored in memory should be overwriten with garbage right after having been hashed for storage or verification. The same recommendation applies to web applications processing user-submitted forms.

While this shrinks the time window in which data can be exfiltrated, it is not a silver bullet and has to be done at application-level.

## OS-level mitigation

The Inception web site mentions a few way to stay safe against Firewire/Thunderbolt DMA attacks:
* Windows: [block the SBP-2 driver](http://support.microsoft.com/kb/2516445) and remove the Firewire drivers if they are not required
* OSX: [set a firmware password](http://ilostmynotes.blogspot.com/2012/01/os-x-open-firmware-settings-use-nvram.html)
* Linux: [remove the 1394 drivers](http://www.hermann-uwe.de/blog/physical-memory-attacks-via-firewire-dma-part-1-overview-and-mitigation)

## In-memory data persistence

Operating systems usually do not clear the memory pages used by an application after it exits. They just mark them as "available for reuse" and erase the previous content only when they actually have to be reused by a different application.

As a result, passwords used to encrypt files, passwords used for certificate requests, passwords used to connect to file servers or to get an interactive shell on a remote machine, can remain accessible in memory way after the action was done.

If a system gets compromised, live data can be recorded. But what is often overlooked is that sensitive data used in the past may also be present and get exfiltrated.

Does your system have a 2+ years uptime? Congratulations. But can you remember everything you did on this system for the past 2 years?

## OS-level mitigation

[Grsecurity](https://grsecurity.net/) is an extensive security enhancement to the Linux kernel that defends against a wide range of security threats.

In particular, Grsecurity can wipe all the memory pages used by a process as soon as the process exits. In order to do so, the [PAX_MEMORY_SANITIZE](http://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#Sanitize_all_freed_memory) option has to be enabled.

## Data swapped out to disk

Linux swap partitions (or files), Windows paging files and OSX paging files are used to optimize the amount of available physical memory by temporarily storing less-used memory pages to disk, and copying them back to RAM as needed.

For this reason, an unsuspected copy of a top-secret document that was carefully only stored to a USB stick can be present, and remain accessible for a very long time. Web browsers, password managers, file encryption apps, VPN clients, can all be susceptible to having a copy
of the in-memory data they use stored to disk. And quitting these apps doesn't have any effect on what is stored in the paging files.

Modern systems also provide the ability to hibernate ("suspend-to-disk"): before powering off the computer, a copy of the memory is stored to disk. When the computer is powered on again, the system can be brought back to the exact state it was before being powered off.

This incredibly useful feature also means that sensitive data present in memory will be stored to disk, and will remain accessible until the system goes to hibernation mode again.

Swap and hibernation files/partitions can be encrypted. However, this doesn't help against attacks on a live system, since the encryption keys are in memory.

Other unexpected copies of the memory are also commonly written to disk. In particular, when a process crashes on a UNIX system, a “core" file can be automatically created by the system for post-mortem analysis.

This file includes a copy of all the in-memory data used by the process before the crash.

Some operating systems provide ways for applications to avoid this behavior for memory pages containing sensitive data.

For example, the Linux kernel introduced the `MADV_DONTDUMP` advice for the `madvise()` system call. However, one cannot reasonably expect all the applications to properly use this mechanism, and for this mechanism to be available at all.

System crashes also happen. And in order to help developers and vendors diagnose and fix the root cause of the crashes, it is common for kernels to dump a full copy of the memory to disk before rebooting. As expected, these dumps can contain sensitive data, and the files can
remain available forever if not manually deleted.

The [Volatility](https://code.google.com/p/volatility/wiki/VolatilityIntroduction?tm=6) framework makes it easy to analyze most of these dumps, and malware can take advantage of these dumps the same way.

## OS-level mitigations

### OSX

Hibernation and paging files are encrypted by default since OSX Lion (10.7).

This can be checked by entering the command:

    sysctl -n vm.swapusage

Paging can also be totally disabled by removing or renaming the `/System/Library/LaunchDaemons/com.apple.dynamic_pager.plist` file.

### Windows

* Encrypt paging files
  1) Open a `Command Prompt` with Administrator privileges
  2) Type: `fsutil behavior set encryptpagingfile 1`
  3) Reboot the system.

* ...or disable paging files
  1) Navigate to the `Control Panel` and click `System`
  2) Select `Advanced System Settings`
  3) In the `Advanced` tab under the `Performance` section, click `Settings`
  4) In the `Advanced Tab` under `Virtual Memory` section, click `Change`
  5) Untick `Automatically manage paging file size for all drives`
  6) Select each drive listed and select the `No paging file` radio button
for each.

* Disable kernel crash dumps
  1) Navigate to the `Control Panel` and click `System`
  2) Select `Advanced System Settings`
  3) In the `Advanced` tab under the `Startup and Recovery` section, click `Settings`
  4) Under the `System Failure` section, change the `Write debugging information drop down` to `(none)`.

* Disable hibernation/suspend-to-RAM
  1) Open a `Command Prompt` with Administrator privileges
  2) Type `powercfg -h off` and hit enter.

(thanks to @maxrmp for the Windows recommendations)

## History of shell commands

On UNIX systems, interactive shells are often configured to store all the commands that have been typed into files named `~/.zsh_history` (zsh), `~/.bash_history` (bash) or `~/.sh_history` (ksh).

Do these commands include confidential data? Then definitely can, especially since applications accepting passwords on the command-line are fairly common. The OpenSSL command-line tool, the `ssh-keygen` command and the MySQL client are some common examples of tools
where important passwords can be given on the command-line.
And a copy of these passwords eventually get recorded into the history shell commands.

Some shells such as Zsh allow fine-grained control over what should be recorded. Most shells will not record a command stating with a space character. However, on a production system, there is usually no reason to persist the shell history to disk.

## OS-Level mitigations

Replace the `~/.zsh_history`, `~/.bash_history` and `~/.sh_history` files with a symbolic link to `/dev/null`.

Alternatively, set the `SAVEHIST` environment variable to `0`.

# Side-channel information leakage

Side-channels attacks extract sensitive data from information leaked by implementations processing them.

Perhaps the most common side-channel is caused by non-constant time comparisons of passwords and secret keys:

```python
    if user_entered_password == stored_password:
        allow_access()
    else:
        disallow_access()
```

This is how Python actually performs the strings comparison:

```c
    if (Py_SIZE(a) == Py_SIZE(b) &&
        a->ob_sval[0] == b->ob_sval[0] &&
        memcmp(a->ob_sval, b->ob_sval, Py_SIZE(a)) == 0) {
        result = Py_True;
    } else {
        result = Py_False;
    }
```

If the strings do not have the same length, the function directly returns `False` without any further processing.

The first character is compared next. If it is not the same in both strings, the function doesn't perform any further comparisons and returns `False`.

Eventually, the memcmp() function is called in order to compare the the entire string.

Here is an implementation of this function (OpenBSD/amd64):

```c
    int memcmp(const void *s1, const void *s2, size_t n)
    {
        if (n != 0) {
            const unsigned char *p1 = s1, *p2 = s2;
            do {
                if (*p1++ != *p2++)
                    return (*--p1 - *--p2);
            } while (--n != 0);
        }
        return (0);
    }
```

Bytes are compared one by one, and the function returns as soon as one
difference is found.

As a result:
- Timing differences can be observed when comparing two strings of the same length (no matter what their content is) and when comparing strings of different lengths.
- No matter what the `memcmp()` implementation is, timing differences can be observed when the first character of two strings is identical and when it is not.
- Timing differences can be observed according to the longest common prefix shared by two strings being compared.

These timing differences can be used to extract sensitive data such as private keys, locally and remotely.

While timing differences are particularily visible in Python and Java, all programming languages behave in a similar way, for obvious performance purposes.

A common misconception is that these timing differences are not exploitable due to jitter introduced by the network and by other system activities.
However, it has been demonstrated that with enough samples and by calculating the difference between peaks combined with a percentile range filter, very small differences could still be exploited regardless of the noise.

Timing attacks have been successfully used in many scenarios such as extracting private keys from HTTP servers and [unlocking the XBOX 360](http://beta.ivc.no/wiki/index.php/Xbox_360_Timing_Attack).

As we are shifting from dedicated servers to virtualized environments, side-channel attacks should be taken more and more seriously.

In particular, CPUs are usually shared by all the processes no matter which container or virtual machine they run in.

Branch prediction and shared caches can be abused by a process to learn about what kind of operations another process is performing.
In 2005, Percival published a concerning paper on how the "Hyper-Threading" feature of modern Intel CPUs and shared L1 caches can be used to steal secret keys from
another another process.
This attack is still relevant today, even when the processes are running in different containers.

More recently, Apecechea, Inci, Eisenbarth and Sunar demonstrated that [cross-VM attacks are possible](http://eprint.iacr.org/2014/248.pdf).
Their clever attack was conducted on VMWare, as well as the Xen hypervisor used by many virtual machines providers such as Amazon (EC2).

And [In a previous study](http://cseweb.ucsd.edu/~hovav/dist/cloudsec.pdf), Ristenpart, Tromer, Shacham and Savage showed that with little effort and money, an attacker can get an instance assigned to the same physical machine as the target.

These attacks remain fairly difficult to conduct, but considering the level of sophistication of some targeted cyber espionage operations we have seen in the past, they should definitely not be ignored.

## Mitigating side-channel information leakage

Although it is not the only side channel that can be exploited, we focused on timing attacks because these are the most practical attacks without physical access.

Resisting side-channel attacks is hard. Ideally, applications should never access specific memory locations or do conditional jumps based on sensitive data.

Even cryptographic libraries are not completely immune to side-channel attacks. Numerous timing side channels have been found in major TLS implementations, such as in the recent [Lucky 13](http://www.isg.rhul.ac.uk/tls/Lucky13.html) attack by Paterson and Al Fardan.

For applications processing sensitive data:
* Favor bare-metal, dedicated servers over shared virtual machines.
* Disable Hyper Threading.
* Use Hardware Security Modules. This is even an option on Amazon EC2.
* Do not write your own crypto and make sure that the libraries you are using are always up-to-date.

