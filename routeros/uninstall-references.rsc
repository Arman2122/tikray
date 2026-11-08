:local references do={
    :local objects $1; :local roleOf $2; :local dataPath $3; :local volume $4; :local slot $5; :local normalize $6; :local scope $7
    :local known do={
        :local menu $1; :local id $2; :local roles ($3->$menu)
        :foreach key,ownerID in=$roles do={ :if ($id = $ownerID) do={ :return true } }
        :return false
    }
    :local unique do={
        :local menu $1; :local key $2; :local expected $3; :local tagValue $4; :local owned ($5->$menu->$tagValue)
        :local findName [:parse (":return [" . $menu . "/find where " . $key . "=\$1]")]
        :local refs [$findName $expected]
        :if (([:len $refs] = 0) and ([:typeof $owned] != "id")) do={ :return true }
        :if (([:len $refs] != 1) or ([:typeof $owned] != "id") or ([:pick $refs 0] != $owned)) do={ :error "tikray: shared_reference_refuses; reserved name, tag or interface changed" }
        :return true
    }
    :foreach part in={"ctl";"runner"} do={
        :local dev ("tikray-" . $part); :local component "tikray"; :local ctag "tikray:tikray"
        :if ($part="runner") do={ :set component "tikray-runner"; :set ctag "tikray:runner" }
        :local a [$unique "/container" "name" $component $ctag $objects]
        :local b [$unique "/container" "interface" $dev $ctag $objects]
        :local c [$unique "/interface/veth" "name" $dev ("tikray:veth-" . $part) $objects]
        :local d [$unique "/interface/bridge/port" "interface" $dev ("tikray:port-" . $part) $objects]
    }
    :local a [$unique "/interface/bridge" "name" "tikray" "tikray:bridge" $objects]
    :local b [$unique "/user" "name" "tikray" "tikray:user" $objects]
    :local c [$unique "/user/group" "name" "tikray" "tikray:group" $objects]
    :local d [$unique "/system/scheduler" "name" "tikray-watchdog" "tikray:watchdog-scheduler" $objects]
    :local state [/system/script/find where name="tikray-watchdog-state" or comment~"^tikray:watchdog-state "]
    :if ([:len $state] > 0) do={
        :if (([:len $state] != 1) or ([:len [/system/script/find where name="tikray-watchdog-state" and comment~"^tikray:watchdog-state " and source=""]] != 1)) do={ :error "tikray: shared_reference_refuses; watchdog receipt conflict" }
    }
    :local userID ($objects->"/user"->"tikray:user")
    :if ([:typeof $userID]="id") do={ :if ([/user/get $userID group]!="tikray") do={ :error "tikray: shared_reference_refuses; restricted account changed group" } }
    :local gatewayRows [/ip/address/find where interface="tikray" or comment="tikray:addr"]
    :local routerAddr ""; :local ctlAddr ""; :local runAddr ""
    :if ([:len $gatewayRows] > 0) do={
        :if (([:len $gatewayRows] != 1) or ([:len [/ip/address/find where interface="tikray" and comment="tikray:addr" and !dynamic]]!=1)) do={ :error "tikray: shared_reference_refuses; bridge address changed" }
        :local text [:tostr [/ip/address/get $gatewayRows address]]; :local slash [:find $text "/"]
        :if ([:typeof $slash] != "num") do={ :error "tikray: shared_reference_refuses; invalid gateway address" }
        :set routerAddr [:toip [:pick $text 0 $slash]]
        :if ($scope!="") do={
            :local cut [:find $scope "/"]; :local n [:toip [:pick $scope 0 $cut]]
            :if (($routerAddr!=($n+1)) or ([:pick $scope $cut [:len $scope]]!=[:pick $text $slash [:len $text]])) do={ :error "tikray: shared_reference_refuses; bridge subnet changed" }
        }
        :set ctlAddr ($routerAddr+1); :set runAddr ($routerAddr+2)
    }
    :foreach p in=[/interface/bridge/port/find where comment="tikray:port-ctl" or comment="tikray:port-runner"] do={
        :if ([/interface/bridge/port/get $p bridge]!="tikray") do={ :error "tikray: shared_reference_refuses; tagged port belongs to another bridge" }
    }
    :foreach component in={"watchdog-script";"emergency-off";"emergency-state"} do={
        :local n ("tikray-" . $component); :if ($component="watchdog-script") do={ :set n "tikray-watchdog" }
        :local v [$unique "/system/script" "name" $n ("tikray:" . $component) $objects]
    }
    :foreach cls in={"open";"closed"} do={
        :local tab ("tikray-" . $cls)
        :local v [$unique "/routing/table" "name" $tab ("tikray:table-" . $cls) $objects]
        :if ([:len [/routing/table/find where name=$tab]] = 1) do={
            :foreach j in=[/ip/route/find where routing-table=$tab] do={ :if (![$known "/ip/route" $j $objects]) do={ :error "tikray: shared_reference_refuses; foreign route in an owned table" } }
        }
    }
    :foreach j in=[/user/find where group="tikray"] do={ :if (![$known "/user" $j $objects]) do={ :error "tikray: shared_reference_refuses; foreign user in the owned group" } }
    :if ([:len [/user/find where name="tikray"]] > 0) do={
        :if ([:len [/user/ssh-keys/find where user="tikray"]] > 0) do={ :error "tikray: shared_reference_refuses; owner SSH key references restricted account" }
    }
    :foreach claim in={"interface/bridge/port:bridge";"interface/bridge/host:bridge";"interface/list/member:interface";"interface/vlan:interface";"interface/vrrp:interface";"ip/arp:interface";"ip/address:interface";"ipv6/address:interface";"ip/dhcp-client:interface";"ip/dhcp-server:interface";"ipv6/dhcp-client:interface";"ipv6/dhcp-server:interface"} do={
        :local sep [:find $claim ":"]; :local menu ("/" . [:pick $claim 0 $sep]); :local field [:pick $claim ($sep+1) [:len $claim]]
        {
            :local findRef [:parse (":return [" . $menu . "/find where " . $field . "=\$1]")]
            :foreach dev in={"tikray";"tikray-ctl";"tikray-runner"} do={
                :foreach j in=[$findRef $dev] do={
                    :if (![$known $menu $j $objects]) do={
                        :local auto false
                        :if ($menu="/interface/bridge/host") do={ :set auto ([/interface/bridge/host/get $j dynamic] or [/interface/bridge/host/get $j local]) }
                        :if ($menu="/ipv6/address") do={ :set auto [/ipv6/address/get $j dynamic] }
                        :if (!$auto) do={ :error "tikray: shared_reference_refuses; owner uses the bridge or veth" }
                    }
                }
            }
        }
    }
    :local private do={
        :local value [:tostr $1]; :if ([:pick $value 0 1] = "!") do={ :set value [:pick $value 1 [:len $value]] }
        :if ([:typeof [:find {"tikray";"tikray-ctl";"tikray-runner";"tikray-open";"tikray-closed";"tikray-pre";"tikray-egress";"tikray-ipv6";"tikray-proxied";"tikray-local";"tikray-domestic";"tikray-src-full-open";"tikray-src-full-closed";"tikray-src-smart-open";"tikray-src-smart-closed";"tikray-bridge-fw";"tikray-bridge-in"} $value]] = "num") do={ :return true }
        :return (($value ~ "^tikray-h[0-9a-f]+\$") and ([:len $value]=40))
    }
    :local checkFields do={
        :local menu $1; :local fields $2; :local own $3; :local isOwned $4; :local reserved $5
        :foreach field in=$fields do={
            :local list [:parse (":return [" . $menu . "/find where " . $field . "~\"tikray\"]")]
            :local val [:parse (":return [" . $menu . "/get \$1 " . $field . "]")]
            :foreach j in=[$list] do={
                :if (![$isOwned $menu $j $own]) do={
                    :foreach x in=[$val $j] do={ :if ([$reserved $x]) do={ :error "tikray: shared_reference_refuses; foreign firewall, routing or queue consumer" } }
                }
            }
        }
        :return true
    }
    :foreach menu in={"/ip/firewall/filter";"/ip/firewall/raw";"/ip/firewall/mangle";"/ip/firewall/nat";"/ipv6/firewall/filter";"/ipv6/firewall/mangle";"/ipv6/firewall/raw";"/ipv6/firewall/nat"} do={
        :local v [$checkFields $menu ({"in-interface";"out-interface";"in-bridge-port";"out-bridge-port";"chain";"jump-target";"src-address-list";"dst-address-list";"address-list";"packet-mark";"connection-mark";"routing-mark";"new-packet-mark";"new-connection-mark";"new-routing-mark"}) $objects $known $private]
    }
    :foreach menu in={"/interface/bridge/filter";"/interface/bridge/nat"} do={
        :local v [$checkFields $menu ({"in-interface";"out-interface";"in-bridge";"out-bridge";"chain";"jump-target";"packet-mark";"new-packet-mark"}) $objects $known $private]
    }
    # Both IP families accept interface-only or interface-qualified next
    # hops. Ignore runtime connected routes, and compare exact interface
    # tokens so a similarly named owner route is preserved.
    :foreach menu in={"/ip/route";"/ipv6/route"} do={
        :local lookup [:parse (":return [" . $menu . "/find where !dynamic and gateway~\"tikray\"]")]
        :local hops [:parse (":return [" . $menu . "/get \$1 gateway]")]
        :foreach entry in=[$lookup] do={
            :if (![$known $menu $entry $objects]) do={
                :foreach gw in=[:toarray [$hops $entry]] do={
                    :local dev [:tostr $gw]; :local at [:find $dev "@"]
                    :if ([:typeof $at]="num") do={ :set dev [:pick $dev 0 $at] }
                    :local pct [:find $dev "%"]; :if ([:typeof $pct]="num") do={ :set dev [:pick $dev ($pct+1) [:len $dev]] }
                    :if ([:typeof [:find {"tikray";"tikray-ctl";"tikray-runner"} $dev]]="num") do={ :error "tikray: shared_reference_refuses; static owner route uses private interface" }
                }
            }
        }
    }
    :foreach pair in={"ip/firewall/address-list:list";"ipv6/firewall/address-list:list";"routing/rule:table";"routing/rule:routing-mark";"routing/rule:interface";"queue/tree:packet-mark";"queue/tree:parent";"queue/simple:packet-marks";"interface/bonding:slaves";"interface/bridge/vlan:tagged";"interface/bridge/vlan:untagged";"ip/vrf:interfaces"} do={
        :local pos [:find $pair ":"]; :local menu ("/" . [:pick $pair 0 $pos]); :local field [:pick $pair ($pos+1) [:len $pair]]
        :local v [$checkFields $menu [:toarray $field] $objects $known $private]
    }
    :foreach j in=[/system/scheduler/find where on-event~"tikray-(watchdog|emergency-off)"] do={
        :if (![$known "/system/scheduler" $j $objects]) do={ :error "tikray: shared_reference_refuses; owner scheduler uses owned command" }
    }
    :foreach j in=[/system/script/find where source~"tikray-(watchdog|emergency-off|runner|ctl)"] do={
        :if (![$known "/system/script" $j $objects]) do={ :error "tikray: shared_reference_refuses; owner script uses private resource" }
    }
    :if ([:typeof $routerAddr] = "ip") do={
        :foreach address in={$routerAddr;$ctlAddr;$runAddr} do={
            # Routes in another routing table can still use a private next hop.
            :foreach r in=[/ip/route/find where gateway=$address or gateway=($address . "%tikray")] do={
                :if (![$known "/ip/route" $r $objects]) do={ :error "tikray: shared_reference_refuses; private gateway in owner route" }
            }
            :foreach n in=[/tool/netwatch/find where host=$address] do={ :if (![$known "/tool/netwatch" $n $objects]) do={ :error "tikray: shared_reference_refuses; foreign netwatch targets private peer" } }
            :foreach server in=[/ip/dns/get servers] do={ :if ([:tostr $server]=[:tostr $address]) do={ :error "tikray: shared_reference_refuses; router DNS uses private peer" } }
            :foreach network in=[/ip/dhcp-server/network/find] do={
                :foreach dns in=[/ip/dhcp-server/network/get $network dns-server] do={ :if ([:tostr $dns]=[:tostr $address]) do={ :error "tikray: shared_reference_refuses; owner DHCP advertises private DNS" } }
                :if ([:tostr [/ip/dhcp-server/network/get $network gateway]]=[:tostr $address]) do={ :error "tikray: shared_reference_refuses; owner DHCP advertises private gateway" }
            }
            :foreach n in=[/ip/firewall/nat/find where action=dst-nat or action=netmap] do={
                :if (![$known "/ip/firewall/nat" $n $objects]) do={
                    :local target [:tostr [/ip/firewall/nat/get $n to-addresses]]
                    :if ($target=[:tostr $address]) do={ :error "tikray: shared_reference_refuses; owner NAT targets private peer" }
                    :local separator [:find $target "-"]
                    :if ([:typeof $separator]="num") do={
                        :local lo [:toip [:pick $target 0 $separator]]; :local hi [:toip [:pick $target ($separator+1) [:len $target]]]
                        :if (([:typeof $lo] = "ip") and ([:typeof $hi] = "ip") and ($lo <= $address) and ($address <= $hi)) do={ :error "tikray: shared_reference_refuses; owner NAT targets private peer" }
                    }
                }
            }
        }
    }
    :local sharePath do={
        :local path $1; :local data $2; :local vol $3; :local alias $4; :local norm $5
        :set path ([$norm $path] . "/")
        :if ($path = "/") do={ :return true }
        :if (([:typeof [:find ("/" . $path) "/../"]] = "num") or ([:typeof [:find ("/" . $path) "/./"]] = "num") or ([:typeof [:find $path "//"]] = "num")) do={ :return true }
        :if ([:pick $path 0 ([:len $alias]+1)] = ($alias . "/")) do={ :set path ($vol . "/" . [:pick $path ([:len $alias]+1) [:len $path]]) }
        :local base ([:pick $data 0 ([:len $data]-5)] . "/")
        :return (([:pick $path 0 [:len $base]]=$base) or ([:pick $base 0 [:len $path]]=$path))
    }
    :foreach j in=[/container/mounts/find] do={
        :if (![$known "/container/mounts" $j $objects]) do={
            :local lst [/container/mounts/get $j list]
            :if (($lst="tikray") or ($lst="tikray-runner") or (($dataPath != "") and [$sharePath [/container/mounts/get $j src] $dataPath $volume $slot $normalize])) do={ :error "tikray: shared_reference_refuses; owner mount uses installation" }
        } else={
            :local roleName [/container/mounts/get $j comment]
            :local expected "/data"; :local lst "tikray"; :local origin $dataPath
            :if ($roleName!="tikray:mount-tikray-data") do={
                :local part [:pick $roleName [:len "tikray:mount-runner-"] [:len $roleName]]
                :set expected ("/data/" . $part); :set lst "tikray-runner"; :set origin ($dataPath . "/" . $part)
            }
            :if (([/container/mounts/get $j list]!=$lst) or ([/container/mounts/get $j dst]!=$expected) or ([$normalize [/container/mounts/get $j src]]!=$origin)) do={ :error "tikray: shared_reference_refuses; tagged mount changed identity" }
        }
    }
    :foreach j in=[/container/envs/find where list="tikray" or list="tikray-runner"] do={
        :if (![$known "/container/envs" $j $objects]) do={ :error "tikray: shared_reference_refuses; foreign entry in private env list" }
    }
    :foreach key,j in=($objects->"/container/envs") do={
        :local lst "tikray"; :if ($key="tikray:env-runner-data") do={ :set lst "tikray-runner" }
        :if (([/container/envs/get $j list]!=$lst) or ([/container/envs/get $j key]!="TIKRAY_DATA")) do={ :error "tikray: shared_reference_refuses; tagged environment changed identity" }
    }
    :foreach j in=[/container/find] do={
        :if (![$known "/container" $j $objects]) do={
            :foreach name in=[/container/get $j mountlists] do={ :if (($name="tikray") or ($name="tikray-runner")) do={ :error "tikray: shared_reference_refuses; owner container uses private mount list" } }
            :foreach name in=[/container/get $j envlists] do={ :if (($name="tikray") or ($name="tikray-runner")) do={ :error "tikray: shared_reference_refuses; owner container uses private environment" } }
            :if (($dataPath!="") and [$sharePath [/container/get $j root-dir] $dataPath $volume $slot $normalize]) do={ :error "tikray: shared_reference_refuses; owner container references installation root" }
        } else={
            :local expected "control"; :if ([/container/get $j comment]="tikray:runner") do={ :set expected "runner" }
            :if (($dataPath="") or ([$normalize [/container/get $j root-dir]] != ([:pick $dataPath 0 ([:len $dataPath]-5)] . "/containers/" . $expected))) do={ :error "tikray: shared_reference_refuses; container root is not private" }
        }
    }
    :return true
}
