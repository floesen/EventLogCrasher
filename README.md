# EventLogCrasher
Proof of concept for a bug, that allows any user to crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain. The crash occurs in `wevtsvc!VerifyUnicodeString` when an attacker sends a malformed `UNICODE_STRING` object to the `ElfrRegisterEventSourceW` method exposed by the RPC-based EventLog Remoting Protocol.

# Demo
![](https://github.com/floesen/EventLogCrasher/blob/main/demo.gif)

