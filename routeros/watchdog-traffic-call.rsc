# The scheduler never evaluates disk-supplied text or an unchecked script.
# This one installer-built helper is pinned inside the scheduler binary body.
:local imageTraffic do={
    :local row [/system/script/find where name="tikray-watchdog-traffic" or comment="tikray:watchdog-traffic"]
    :if (([:len $row]!=1) or ([:len [/system/script/find where name="tikray-watchdog-traffic" and comment="tikray:watchdog-traffic" and !dont-require-permissions]]!=1)) do={:error "image: traffic helper ownership changed"}
    :local id [:pick $row 0]; :local count 0
    :foreach p in=[/system/script/get $id policy] do={:if ([:pick $p 0 1]!="!") do={:if ($p!="read") do={:error "image: traffic helper privileges changed"}; :set count ($count+1)}}
    :if ($count!=1) do={:error "image: traffic helper privileges changed"}
    :local body [/system/script/get $id source]; :local n [:len $body]
    :if (($n=0) or ($n>20000)) do={:error "image: traffic helper content changed"}
    :while (($n>0) and (([:pick $body ($n-1) $n]="\r") or ([:pick $body ($n-1) $n]="\n"))) do={:set n ($n-1)}
    :set body [:pick $body 0 $n]
    :if ([:convert [:convert $body from=raw transform=sha512 to=hex] transform=lc]!="@TIKRAY_TRAFFIC_HASH@") do={:error "image: traffic helper content changed"}
    :local run [:parse $body]
    :return [$run $1 $2 $3 $4 $5 $6 $7]
}
