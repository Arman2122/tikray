# Owner-run binding removal stage. The uninstall caller quiesces both
# containers and the scheduler first, and removes the veths/bridge last.
# Keep learning and unknown-unicast flooding off until those ports are gone.
{
# BEGIN BINDING REMOVAL HELPER
:local removeBindings do={
    :local op $1
    :local ownedLease $2
    :if (($op != "inspect") and ($op != "remove")) do={ :error "tikray: unknown binding removal operation" }
    :local collect do={
        :local quiet $1
        :local lease $2
        :local claims [:toarray ""]
        :local count 0
        :foreach role in={"ctl";"runner"} do={
            :set count ($count + [:len [/ip/arp/find where comment=("tikray:arp-" . $role)]] + [:len [/interface/bridge/host/find where comment=("tikray:fdb-" . $role)]])
        }
        :if (($count = 0) and ([:len [/ip/address/find where comment="tikray:addr"]] = 0)) do={ :return $claims }
        :if ($quiet and ($count > 0)) do={
            :if (([:len [/system/script/job/find where script="tikray-watchdog"]] > 0) or ([:len [/system/scheduler/find where (name="tikray-watchdog" or comment="tikray:watchdog-scheduler") and !disabled]] > 0)) do={ :error "tikray: quiesce the watchdog before removing bindings" }
            :local lock [/system/script/find where name="tikray-install-lock" or comment~"^tikray:install-lock "]
            :if (([:len $lock] > 0) or ([:typeof $lease] = "array")) do={
                :if (([:len $lock] != 1) or ([:typeof $lease] != "array") or ([:len [/system/script/find where name="tikray-uninstall-state" and comment~"^tikray:uninstall-state "]] != 1)) do={ :error "tikray: another installer holds the binding lease" }
                :local lid [:pick $lock 0]
                :if (($lid != ($lease->"id")) or ([/system/script/get $lid comment] != ($lease->"comment")) or ([/system/script/get $lid name] != "tikray-install-lock") or ([:len [/system/script/get $lid source]] != 0) or ([:tostr [/system/script/job/get ($lease->"job") started]] != ($lease->"started"))) do={ :error "tikray: uninstall lease changed" }
            }
        }
        :local bridge [/interface/bridge/find where name="tikray" or comment="tikray:bridge"]
        :local ips [/ip/address/find where interface="tikray" or comment="tikray:addr"]
        :if (([:len $bridge] != 1) or ([:len [/interface/bridge/find where name="tikray" and comment="tikray:bridge"]] != 1) or ([:len $ips] != 1) or ([/ip/address/get $ips comment] != "tikray:addr") or ([:tostr [/ip/address/get $ips interface]] != "tikray")) do={ :error "tikray: shared_reference_refuses; verify the owned private bridge" }
        :local prefix [:tostr [/ip/address/get $ips address]]
        :local gateway [:toip [:pick $prefix 0 [:find $prefix "/"]]]
        :foreach port in=[/interface/bridge/port/find where bridge="tikray"] do={
            :local iface [:tostr [/interface/bridge/port/get $port interface]]
            :local role [/interface/bridge/port/get $port comment]
            :if (!( (($iface = "tikray-ctl") and ($role = "tikray:port-ctl")) or (($iface = "tikray-runner") and ($role = "tikray:port-runner")) )) do={ :error "tikray: shared_reference_refuses; foreign bridge port" }
        }
        :foreach side in={"ctl";"runner"} do={
            :local iface ("tikray-" . $side)
            :local addr ($gateway + 1)
            :local component "tikray"
            :local containerTag "tikray:tikray"
            :if ($side = "runner") do={ :set addr ($gateway + 2); :set component "tikray-runner"; :set containerTag "tikray:runner" }
            :local cs [/container/find where interface=$iface or name=$component or comment=$containerTag]
            :if ([:len $cs] > 0) do={
                :if (([:len $cs] != 1) or ([:len [/container/find where interface=$iface and name=$component and comment=$containerTag]] != 1)) do={ :error "tikray: shared_reference_refuses; container ownership conflict" }
                :if ($quiet and ($count > 0) and ([:len [/container/find where interface=$iface and name=$component and comment=$containerTag and stopped and !start-on-boot]] != 1)) do={ :error "tikray: stop owned containers and disable automatic start before removing bindings" }
            }
            :local vtag ("tikray:veth-" . $side)
            :local v [/interface/veth/find where name=$iface or comment=$vtag]
            :local mac ""
            :if (($count > 0) or ([:len $v] > 0)) do={
                :if (([:len $v] != 1) or ([:len [/interface/veth/find where name=$iface and comment=$vtag]] != 1)) do={ :error "tikray: shared_reference_refuses; verify the owned veth before removing bindings" }
                :set mac [:tostr [/interface/veth/get $v container-mac-address]]
            }
            :local atag ("tikray:arp-" . $side)
            :local ars [/ip/arp/find where comment=$atag or (interface="tikray" and address=$addr)]
            :if ([:len $ars] > 0) do={
                :if (([:len $ars] != 1) or ([:len [/ip/arp/find where comment=$atag and interface="tikray" and address=$addr and mac-address=$mac and !dynamic and !published]] != 1)) do={ :error "tikray: shared_reference_refuses; ARP binding changed" }
                :set ($claims->[:len $claims]) {"menu"="arp";"id"=[:pick $ars 0];"role"=$atag;"iface"=$iface;"ip"=$addr;"mac"=$mac}
            }
            :local ftag ("tikray:fdb-" . $side)
            :local fds [/interface/bridge/host/find where comment=$ftag]
            :if ($mac != "") do={ :set fds [/interface/bridge/host/find where comment=$ftag or (bridge="tikray" and mac-address=$mac)] }
            :if ([:len $fds] > 0) do={
                :if (([:len $fds] != 1) or ([:len [/interface/bridge/host/find where comment=$ftag and bridge="tikray" and interface=$iface and mac-address=$mac and !dynamic and !local]] != 1)) do={ :error "tikray: shared_reference_refuses; forwarding binding changed" }
                :set ($claims->[:len $claims]) {"menu"="host";"id"=[:pick $fds 0];"role"=$ftag;"iface"=$iface;"mac"=$mac}
            }
        }
        :return $claims
    }
    # Never start dismantling one side before verifying both. Re-read IDs
    # and natural keys before each removal following any concurrent edit.
    :local before [$collect ($op = "remove") $ownedLease]
    :if ($op = "inspect") do={ :return true }
    :foreach expected in=$before do={
        :local fresh [$collect true $ownedLease]
        :local matched false
        :foreach live in=$fresh do={ :if ([:tostr $expected] = [:tostr $live]) do={ :set matched true } }
        :if (!$matched) do={ :error "tikray: binding removal drift; verify and retry" }
        :local id ($expected->"id")
        :if (($expected->"menu") = "arp") do={ /ip/arp/remove $id } else={ /interface/bridge/host/remove $id }
    }
    :local remaining [$collect true $ownedLease]
    :if ([:len $remaining] != 0) do={ :error "tikray: verify remaining bindings" }
    :return true
}
# END BINDING REMOVAL HELPER
    :local removed [$removeBindings "remove"]
}
