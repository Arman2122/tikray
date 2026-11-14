# Build the complete plan before touching either peer. Every observation is
# scoped on the router. A lost acknowledgement is recovered by observing again.
:local bindPeers do={
    :local mode $1
    :local scope $2
    :local fence $3
    :local token $4
    :if (($mode != "preflight") and ($mode != "repair") and ($mode != "check")) do={ :error "tikray: unknown peer binding operation" }
    :local observe do={
        :local inspect ($1 = "preflight")
        :local subnet $2
        :local slash [:find $subnet "/"]
        :if ([:typeof $slash] != "num") do={ :error "tikray: missing peer subnet" }
        :local netAddr [:toip [:pick $subnet 0 $slash]]
        :local bits [:tonum [:pick $subnet ($slash+1) [:len $subnet]]]
        :if (([:typeof $netAddr] != "ip") or ([:typeof $bits] != "num") or ($bits > 29) or ($bits < 1)) do={ :error "tikray: invalid peer subnet" }
        :local routerAddr ($netAddr + 1)
        :local plan [:toarray ""]
        :local identity ""
        :local bridge [/interface/bridge/find where name="tikray" or comment="tikray:bridge"]
        :if (([:len $bridge] != 0) or (!$inspect)) do={
            :if (([:len $bridge] != 1) or ([:len [/interface/bridge/find where name="tikray" and comment="tikray:bridge" and protocol-mode=none and !disabled and !vlan-filtering]] != 1)) do={ :error "tikray: private bridge identity conflict" }
            :set identity [:tostr $bridge]
        }
        :local ips [/ip/address/find where interface="tikray" or comment="tikray:addr"]
        :if (([:len $ips] != 0) or (!$inspect)) do={
            :if (([:len $ips] != 1) or ([:len [/ip/address/find where interface="tikray" and comment="tikray:addr" and !disabled and !dynamic]] != 1) or ([:tostr [/ip/address/get $ips address]] != ($routerAddr . "/" . $bits))) do={ :error "tikray: private gateway identity conflict" }
        }
        :foreach entry in=[/interface/bridge/port/find where bridge="tikray"] do={
            :local c [/interface/bridge/port/get $entry comment]
            :if (($c != "tikray:port-ctl") and ($c != "tikray:port-runner")) do={ :error "tikray: shared_reference_refuses; unexpected private bridge port" }
        }
        :local priorMAC ""
        :foreach side in={"ctl";"runner"} do={
            :local dev ("tikray-" . $side)
            :local ip ($routerAddr + 1)
            :if ($side = "runner") do={ :set ip ($routerAddr + 2) }
            :local vtag ("tikray:veth-" . $side)
            :local ptag ("tikray:port-" . $side)
            :local ftag ("tikray:fdb-" . $side)
            :local atag ("tikray:arp-" . $side)
            :local vs [/interface/veth/find where name=$dev or comment=$vtag]
            :local mac ""
            :if (([:len $vs] > 0) or (!$inspect)) do={
                :if (([:len $vs] != 1) or ([:len [/interface/veth/find where name=$dev and comment=$vtag and !disabled]] != 1)) do={ :error "tikray: private veth ownership conflict" }
                :if (([:tostr [/interface/veth/get $vs address]] != ($ip . "/" . $bits)) or ([:tostr [/interface/veth/get $vs gateway]] != [:tostr $routerAddr])) do={ :error "tikray: private veth address conflict" }
                :set mac [:convert [:tostr [/interface/veth/get $vs container-mac-address]] transform=uc]
                :if ($mac = "00:00:00:00:00:00") do={
                    :local hostMac [:convert [:tostr [/interface/veth/get $vs mac-address]] transform=uc]
                    :local lead "02:74:02:"; :local cname "tikray"; :local cr "tikray:tikray"
                    :if ($side = "runner") do={ :set lead "02:74:03:"; :set cname "tikray-runner"; :set cr "tikray:runner" }
                    :local cs [/container/find where interface=$dev or name=$cname or comment=$cr]
                    :if (([:len $hostMac] != 17) or (([:len $cs] > 0) and (([:len $cs] != 1) or ([:len [/container/find where interface=$dev and name=$cname and comment=$cr and stopped]] != 1)))) do={ :error "tikray: stop and inspect the veth before assigning its peer MAC" }
                    :set mac ($lead . [:pick $hostMac 9 17])
                    :if ($mac = $hostMac) do={ :error "tikray: peer MAC collides with veth" }
                    :set ($plan->[:len $plan]) {"op"="peer-mac";"id"=[:pick $vs 0];"mac"=$mac}
                }
                :if (([:len $mac] != 17) or (!($mac ~ "^[0-9A-F][02468ACE]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]\$"))) do={ :error "tikray: invalid container MAC" }
                :if (($mac = "00:00:00:00:00:00") or ($mac = $priorMAC)) do={ :error "tikray: duplicate or zero container MAC" }
                :set priorMAC $mac
                :set identity ($identity . "|" . [:tostr $vs] . "|" . $mac)
            }
            :local ps [/interface/bridge/port/find where interface=$dev or comment=$ptag]
            :if ([:len $ps] > 0) do={
                :if ([:len $ps] != 1) do={ :error "tikray: private port collision" }
                :local id [:pick $ps 0]
                :local pi [/interface/bridge/port/get $id]
                :local observed [:tostr ($pi->"interface")]
                :if ((($pi->"comment") != $ptag) or ([:tostr ($pi->"bridge")] != "tikray") or (($pi->"dynamic") = true) or (($pi->"disabled") = true) or (($observed != $dev) and ([:pick $observed 0 1] != "*"))) do={ :error "tikray: private port ownership conflict" }
                :if (($observed != $dev) or ([:tostr ($pi->"learn")] != "no") or (($pi->"unknown-unicast-flood") != false)) do={ :set ($plan->[:len $plan]) {"op"="set-port";"id"=$id;"dev"=$dev;"role"=$ptag} }
            } else={ :set ($plan->[:len $plan]) {"op"="add-port";"dev"=$dev;"role"=$ptag} }
            # A static MAC-to-port row prevents MAC learning on an attacker
            # from moving an ARP-pinned destination to its own port.
            :local hosts [/interface/bridge/host/find where comment=$ftag]
            :if ($mac != "") do={ :set hosts [/interface/bridge/host/find where comment=$ftag or (bridge="tikray" and mac-address=$mac)] }
            :if ([:len $hosts] > 0) do={
                :if ([:len $hosts] != 1) do={ :error "tikray: shared_reference_refuses; forwarding entry collision" }
                :local id [:pick $hosts 0]
                :local host [/interface/bridge/host/get $id]
                :local observed [:tostr ($host->"interface")]
                :if ((($host->"comment") != $ftag) or ([:tostr ($host->"bridge")] != "tikray") or (($host->"dynamic") = true) or (($host->"local") = true) or (($host->"disabled") = true) or (($observed != $dev) and ([:pick $observed 0 1] != "*")) or (([:len [:tostr ($host->"vid")]] > 0) and ([:tostr ($host->"vid")] != "0"))) do={ :error "tikray: forwarding entry ownership conflict" }
                :if (($mac != "") and (($observed != $dev) or ([:tostr ($host->"mac-address")] != $mac))) do={ :set ($plan->[:len $plan]) {"op"="set-host";"id"=$id;"dev"=$dev;"mac"=$mac;"role"=$ftag} }
            } else={ :if ($mac != "") do={ :set ($plan->[:len $plan]) {"op"="add-host";"dev"=$dev;"mac"=$mac;"role"=$ftag} } }
            :local arps [/ip/arp/find where comment=$atag or (interface="tikray" and address=$ip)]
            :if ([:len $arps] > 0) do={
                :if ([:len $arps] != 1) do={ :error "tikray: shared_reference_refuses; ARP entry collision" }
                :local id [:pick $arps 0]
                :local a [/ip/arp/get $id]
                :if ((($a->"comment") != $atag) or ([:tostr ($a->"interface")] != "tikray") or ([:tostr ($a->"address")] != [:tostr $ip]) or (($a->"dynamic") = true) or (($a->"published") = true) or (($a->"dhcp") = true) or (($a->"disabled") = true)) do={ :error "tikray: ARP entry ownership conflict" }
                :if (($mac != "") and ([:tostr ($a->"mac-address")] != $mac)) do={ :set ($plan->[:len $plan]) {"op"="set-arp";"id"=$id;"ip"=$ip;"mac"=$mac;"role"=$atag} }
            } else={ :if ($mac != "") do={ :set ($plan->[:len $plan]) {"op"="add-arp";"ip"=$ip;"mac"=$mac;"role"=$atag} } }
        }
        :if (([:len $bridge] = 1) and ([:tostr [/interface/bridge/get $bridge arp]] != "reply-only")) do={ :set ($plan->[:len $plan]) {"op"="bridge";"id"=[:pick $bridge 0]} }
        :return {"plan"=$plan;"identity"=$identity}
    }
    :for pass from=0 to=11 do={
        :local a [$observe $mode $scope]
        :local ops ($a->"plan")
        :if (($mode = "preflight") or ([:len $ops] = 0)) do={ :return true }
        :if ($mode != "repair") do={ :error "tikray: peer bindings require repair" }
        :local b [$observe $mode $scope]
        :if ((($a->"identity") != ($b->"identity")) or ([:tostr ($ops->0)] != [:tostr ($b->"plan"->0)])) do={ :error "tikray: peer binding changed; retry" }
        :local action ($ops->0); :local verb ($action->"op"); :local id ($action->"id")
        :local dev ($action->"dev"); :local role ($action->"role"); :local ip ($action->"ip"); :local mac ($action->"mac")
        :if ([:typeof $fence] = "code") do={ $fence $token }
        :if ($verb = "peer-mac") do={ /interface/veth/set $id container-mac-address=$mac }
        :if ($verb = "add-port") do={ /interface/bridge/port/add interface=$dev bridge=tikray learn=no unknown-unicast-flood=no comment=$role }
        :if ($verb = "set-port") do={ /interface/bridge/port/set $id interface=$dev learn=no unknown-unicast-flood=no }
        :if ($verb = "add-host") do={ /interface/bridge/host/add interface=$dev bridge=tikray mac-address=$mac comment=$role }
        :if ($verb = "set-host") do={ /interface/bridge/host/set $id interface=$dev mac-address=$mac }
        :if ($verb = "add-arp") do={ /ip/arp/add interface=tikray address=$ip mac-address=$mac comment=$role }
        :if ($verb = "set-arp") do={ /ip/arp/set $id mac-address=$mac }
        :if ($verb = "bridge") do={ /interface/bridge/set $id arp=reply-only }
    }
    :error "tikray: private bridge bindings did not converge"
}
