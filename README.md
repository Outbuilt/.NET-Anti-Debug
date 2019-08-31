# .NET-Anti-Debug
Anti-Debugger to stop multiple malicious tools and hooks on your software.

- Anti Fiddler / Requests / All other web debuggers
- Anti Folder Changes View / Grabbers
- Anti Debug 1 - Checks for known tools and custom tools to bypass and/or tamper with application
- Anti Debug 2 - Checks for attached & remote debuggers & dll's from kernel
- Anti Emulation 
- Anti Sandboxie
- Anti Virtual Machine & VPS
- Anti Dump - Clears headers and some secret magic ontop
- Checks for system modifications that allow tampering.
- Checks for Admin privelages being manipulated or revoked.
- Checks for application hash and DLL hash if anything is cloned

Update 08/13/19

- Anti-Debug threading changed (more faster)
- Added more anti-debug features
- Plenty of new security checks
- Fixed FreezeMouse out of memory
- Patched some other self-found bugs.

Update 08/14/19

- Fixed anti-debug not starting
- Now checks for malicious handles, hooks and dll's
- Checks parent and modules so it can't be ran through other programs.

Update 08/30/19

- Open-Sourced
- Added anti-proxy

Credits:

1 year ago, https://github.com/MauriceHuber sent me the code for detecting multiple process names.
It has been drastically modified and new features have been added.
