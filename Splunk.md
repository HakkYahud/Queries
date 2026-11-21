## Type of sourcetype
| tstats count where index=* by index, sourcetype

Know the field per sourcetype, in this example what are the fields in stream:http
index=botsv1 sourcetype=stream:http | fieldsummary | table field count distinct_count values

## DNS logs 
index=botsv1 sourcetype=stream:dns src_ip="192.168.250.100"
| rename "query{}" as query
| search query="*.*" NOT query IN ( "*.arpa", "*.local", "wpad*", "isatap*", "teredo*", "_ldap._tcp*", "_kerberos*", "*.microsoft.com", "microsoft.com", "*.windowsupdate.com", "*.windows.com", "*.msftncsi.com", "*.msftconnecttest.com", "*.live.com", "*.bing.com", "ocsp.*", "crl.*", "*.digicert.com", "*.verisign.com", "*.mozilla.org", "*.mozilla.net", "*.gstatic.com", "*.doubleclick.net")
| stats count dc(src_ip) as hosts values(src_ip) as src earliest(_time) as first latest(_time) as last by query
| convert ctime(first) ctime(last)
| sort - count


## Process Tree

### On suspicious path
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image IN ("*\\Temp\\*", "*\\AppData\\*", "*\\Users\\Public\\*", "*\\ProgramData\\*")
| join type=left ParentProcessGuid
    [ search index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
      | rename ProcessGuid as ParentProcessGuid, ParentImage as GrandParentImage, ParentProcessId as GrandParentId
      | fields ParentProcessGuid GrandParentImage GrandParentId]
| eval gp=mvindex(split(GrandParentImage,"\\"),-1),
       p=mvindex(split(ParentImage,"\\"),-1),
       c=mvindex(split(Image,"\\"),-1)
| eval chain=coalesce(gp,"?")." → ".p." → ".c
| stats count values(CommandLine) as cmdlines by host chain, GrandParentId, ParentProcessId, ProcessId
| sort count

### Using different index and sourcetype as an example
### General One
index=case-windows-logs sourcetype=system_logs event.code=1
| rename process.entity_id as guid, process.parent.entity_id as pguid,
         process.parent.executable as ParentImage, process.parent.pid as ParentPid,
         process.command_line as CommandLine, process.name as Child, process.pid as Pid
| join type=left pguid
    [ search index=case-windows-logs sourcetype=system_logs event.code=1
    | rename process.entity_id as pguid,
             process.parent.executable as GrandParentImage, process.parent.pid as GrandParentPid
    | fields pguid GrandParentImage GrandParentPid ]
| eval gp=mvindex(split(GrandParentImage,"\\"),-1),
       p=mvindex(split(ParentImage,"\\"),-1)
| eval chain=coalesce(gp,"?")." → ".coalesce(p,"?")." → ".coalesce(Child,"?")
| search chain="*node.exe*"
| fillnull value="-" GrandParentPid ParentPid CommandLine
| stats count earliest(_time) as first values(CommandLine) as cmdlines
    by host.hostname, user.name, chain, GrandParentPid, ParentPid, Pid
| convert ctime(first)
| sort first

## Authentication RDP from 
index=case-windows-logs host.name="qqqisVDC4*" source.ip="10.85.47.70"
    event.code=4624 winlog.event_data.LogonType=10
| table _time, user.name, source.ip, winlog.event_data.LogonType
| sort _time

