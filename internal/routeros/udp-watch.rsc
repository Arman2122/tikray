# The packet guard covers route changes between these bounded scans.
:local suspended do={
    :if ([:len [/system/script/find where name="tikray-emergency-state" or name="tikray-uninstall-state" or name="tikray-image-transition"]]>0) do={:return true}
    :if ([:len [/system/script/job/find where script="tikray-emergency-off" or script="tikray-uninstall"]]>0) do={:return true}
    :local locks [/system/script/find where name="tikray-install-lock"]
    :if ([:len $locks]=0) do={:return false}
    :if ([:len $locks]!=1) do={:return true}
    :local label [/system/script/get [:pick $locks 0] comment]
    :local prefix "tikray:install-lock "
    :if ([:pick $label 0 [:len $prefix]]!=$prefix) do={:return true}
    :local lease [:deserialize from=json options=json.no-string-conversion value=[:pick $label [:len $prefix] [:len $label]]]
    :if (($lease->"version")!=1) do={:return true}
    :local id [:toid ($lease->"job")]
    :if ([:typeof $id]!="id") do={:return true}
    :local jobs [/system/script/job/find where .id=$id]
    :return (([:len $jobs]=1) and ([:tostr [/system/script/job/get $id started]]=($lease->"started")))
}
:local currentPath do={
    :local scopes [/ip/route/find where routing-table="tikray-open"]
    :if ([:len $scopes]!=2) do={:return ""}
    :local runner [/ip/route/find where comment="tikray:route-open-runner" and routing-table="tikray-open" and dst-address="0.0.0.0/0" and distance=1 and check-gateway=ping and !disabled and !dynamic and !blackhole]
    :local wan [/ip/route/find where comment="tikray:route-open-fallback" and routing-table="tikray-open" and dst-address="0.0.0.0/0" and distance=2 and !disabled and !dynamic and !blackhole]
    :if (([:len $runner]!=1) or ([:len $wan]!=1)) do={:return ""}
    :local through [/ip/route/get [:pick $runner 0]]
    :local direct [/ip/route/get [:pick $wan 0]]
    :if (([:tostr ($through->"gateway")]!="@RUNNER@") or ([:tostr ($direct->"gateway")]!="@WAN@")) do={:return ""}
    :if ((($through->"active")=true) and (($direct->"active")!=true)) do={:return "tikray-open-wan"}
    :if ((($direct->"active")=true) and (($through->"active")!=true)) do={:return "tikray-open-runner"}
    :return ""
}
# Marks are private only while every writer is an expected native rule.
:local ownsWriters do={
    :foreach mark in={"tikray-open";"tikray-open-udp";"tikray-open-runner";"tikray-open-wan"} do={
        :foreach id in=[/ip/firewall/mangle/find where new-connection-mark=$mark] do={
            :local tag [/ip/firewall/mangle/get $id comment]
            :local matches
            :if (($mark="tikray-open") or ($mark="tikray-open-udp")) do={
                :local suffix ""
                :if ($mark="tikray-open-udp") do={:set suffix "-udp"}
                :local mode
                :if ($tag=("tikray:conn-full-open" . $suffix)) do={:set mode "full"}
                :if ($tag=("tikray:conn-smart-open" . $suffix)) do={:set mode "smart"}
                :if ([:typeof $mode]!="str") do={:return false}
                :local listName ("tikray-src-" . $mode . "-open")
                :set matches [/ip/firewall/mangle/find where comment=$tag and chain="tikray-pre" and action=mark-connection and new-connection-mark=$mark and src-address-list=$listName and !dynamic]
            } else={
                :local side [:pick $mark 12 [:len $mark]]
                :local expected ("tikray:udp-birth-" . $side)
                :if ($tag!=$expected) do={:return false}
                :local iface "!tikray"
                :if ($side="runner") do={:set iface "tikray"}
                :set matches [/ip/firewall/mangle/find where comment=$tag and chain=forward and action=mark-connection and connection-mark="tikray-open-udp" and new-connection-mark=$mark and in-interface-list="@LAN@" and out-interface=$iface and !dynamic]
            }
            :if (([:len $matches]!=1) or ([:pick $matches 0]!=$id)) do={:return false}
        }
    }
    :return true
}
:local identity do={
    :local r $1; :local tuple ""
    :foreach field in={".id";"src-address";"dst-address";"protocol";"src-port";"dst-port";"reply-src-address";"reply-dst-address";"reply-src-port";"reply-dst-port";"connection-mark";"dstnat"} do={
        :set tuple ($tuple . "|" . [:tostr ($r->$field)])
    }
    :return $tuple
}
:do {
    :if (([$suspended]) or (![$ownsWriters])) do={:return true}
    :local stale [$currentPath]
    :if ($stale="") do={:return true}
    :local ids [/ip/firewall/address-list/find where (list="tikray-src-smart-open" or list="tikray-src-full-open") and !dynamic and !disabled]
    :local size [:len $ids]
    :if ($size=0) do={:return true}
    # Netwatch exposes its test counter as text in the script environment.
    :local count [:tonum $"done-tests"]
    :if ([:typeof $count]!="num") do={:return true}
    :local deadline ([:tonsec [/system/resource/get uptime]]+1500000000)
    :local removes 0
    :local start ($count%$size)
    :for n from=0 to=23 do={
        :if (($n>=$size) or ($removes>=8) or ([:tonsec [/system/resource/get uptime]]>$deadline)) do={:return true}
        :local member [:pick $ids (($start+$n)%$size)]
        :local row [/ip/firewall/address-list/get $member]
        :local label ($row->"comment")
        :local listName ($row->"list")
        :local address [:tostr ($row->"address")]
        :if ([:typeof [:find $address "/"]]!="num") do={:set address ($address . "/32")}
        :if ((!($address~"^[0-9.]+/[0-9]+\$")) or ($address~"/0\$") or ($label!=("tikray:" . [:pick $listName 7 [:len $listName]] . ":" . $address))) do={:return true}
        :local toPrefix [:parse (":return " . $address)]
        :local scope [$toPrefix]
        :local flows [/ip/firewall/connection/print detail as-value where src-address in $scope and protocol=udp and (connection-mark=$stale or connection-mark="tikray-open" or connection-mark="tikray-open-udp") and dst-port!=53 and !dstnat]
        :foreach original in=$flows do={
            :if (($removes>=8) or ([:tonsec [/system/resource/get uptime]]>$deadline)) do={:return true}
            :local id ($original->".id")
            :local src ($original->"src-address"); :local dst ($original->"dst-address")
            :local sp ($original->"src-port"); :local dp ($original->"dst-port")
            :local mark ($original->"connection-mark")
            :if (([:typeof $id]="id") and ([:typeof $src]="ip") and ([:typeof $dst]="ip") and ([:typeof $sp]="num") and ([:typeof $dp]="num") and ($src in $scope) and ($dp!=53) and (($mark=$stale) or ($mark="tikray-open") or ($mark="tikray-open-udp"))) do={
                :local candidates [/ip/firewall/connection/find where src-address=$src and dst-address=$dst and protocol=udp and src-port=$sp and dst-port=$dp and connection-mark=$mark and !dstnat]
                :if (([:len $candidates]=1) and ([:pick $candidates 0]=$id) and (![$suspended]) and ([$ownsWriters]) and ([$currentPath]=$stale) and ([:len [/ip/firewall/address-list/find where .id=$member and list=$listName and comment=$label and !disabled and !dynamic]]=1)) do={
                    :local reread [/ip/firewall/connection/print detail as-value where src-address=$src and dst-address=$dst and protocol=udp and src-port=$sp and dst-port=$dp and connection-mark=$mark and !dstnat]
                    :if (([:len $reread]=1) and ([$identity $original]=[$identity [:pick $reread 0]])) do={
                        /ip/firewall/connection/remove $id
                        :set removes ($removes+1)
                    }
                }
            }
        }
    }
} on-error={}
