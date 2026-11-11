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

