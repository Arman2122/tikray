# Source template. Package with tikray-installer and the two authenticated image archives.
{
    :global tikrayDisk
    :global tikrayDir
    :global tikraySubnet
    :global tikrayLanList
    :global tikrayWanList
    :global tikrayCore
    :global tikrayOffline
    :global tikrayShowSetup
    :local displaySetup ($tikrayShowSetup = true)
    :set tikrayShowSetup
    :local disk $tikrayDisk
    :local subnet [:tostr $tikraySubnet]
    :local lanList $tikrayLanList
    :local wanList $tikrayWanList
    :local core $tikrayCore
    :local offline $tikrayOffline
    :if ([:typeof $disk] = "nothing") do={ :set disk "disk1" }
    :if ($subnet = "") do={ :set subnet "172.31.255.0/29" }
    :if ([:typeof $lanList] = "nothing") do={ :set lanList "LAN" }
    :if ([:typeof $wanList] = "nothing") do={ :set wanList "WAN" }
    :if ([:typeof $core] = "nothing") do={ :set core "latest" }
    :if ([:typeof $offline] = "nothing") do={ :set offline false }
    :if (!($disk ~ "^[A-Za-z0-9][A-Za-z0-9_-]*\$") or !($lanList ~ "^[A-Za-z0-9_][A-Za-z0-9_.-]*\$") or !($wanList ~ "^[A-Za-z0-9_][A-Za-z0-9_.-]*\$") or ($lanList = $wanList) or ([:typeof $offline] != "bool")) do={ :error "tikray: inspect disk and LAN/WAN list names" }
    :if (($core != "latest") and !($core ~ "^[0-9]+\\.[0-9]+\\.[0-9]+\$")) do={ :error "tikray: choose a core release or latest" }
    :if ($offline and ($core = "latest")) do={ :error "tikray: choose an exact offline core release" }
    :local folder $tikrayDir
    :if ([:typeof $folder] = "nothing") do={ :set folder "tikray" }
    :if (!(($folder = "tikray") or ($folder ~ "^tikray-[A-Za-z0-9_][A-Za-z0-9_-]*\$"))) do={ :error "tikray: select a dedicated tikray data folder" }
    :local base ($disk . "/" . $folder)
    :local data ($base . "/data")
    :local arch [/system/resource/get architecture-name]
    :local version [:pick [:tostr [/system/resource/get version]] 0 [:find ([:tostr [/system/resource/get version]] . " ") " "]]
    :local installed [:tostr [/system/resource/get version]]
    :if (($installed != $version) and ($installed != ($version . " (stable)")) and ($installed != ($version . " (long-term)"))) do={ :error "tikray: choose a supported stable or long-term release" }
    :local board [/system/resource/get board-name]
    :if ($arch = "x86_64") do={ :if (($board != "CHR") and ([:pick $board 0 4] != "CHR ")) do={ :error "tikray: x86_64 requires CHR" }; :set arch "amd64" }
    :if (($arch != "amd64") and ($arch != "arm64")) do={ :error "tikray: unsupported container architecture" }
    :local imageBytes 0
    # @TIKRAY_PLATFORM@
    # @TIKRAY_VERIFIER@
    # @TIKRAY_LOCK@
    :if ($imageBytes = 0) do={ :error "tikray: use a packaged signed installer" }
    :if (([:len [/system/package/find where name="container" and !disabled]] != 1)) do={ :error "tikray: install the matching container package and reboot" }
    :if ([:tostr [/system/package/get [find where name="container" and !disabled] version]] != $version) do={ :error "tikray: install the container package matching the running release" }
    :if (![/system/device-mode/get container]) do={
        :put "tikray: confirm container mode physically as prompted, then import again"
        /system/device-mode/update container=yes
        :error "tikray: confirm device mode and retry"
    }
    :if (![/ip/dns/get allow-remote-requests]) do={ :error "tikray: enable router DNS for authorized LAN clients before installing" }
    :local volume [/disk/find where mount-point=$disk and fs="ext4"]
    :if ([:len $volume] != 1) do={ :error "tikray: select a mounted ext4 container data disk" }
    :if (([/disk/get $volume free] < (157286400 + ($imageBytes * 3))) or ([/system/resource/get free-memory] < 134217728)) do={ :error "tikray: provide more free RAM or data disk space" }
    :local tmp [:tostr [/container/config/get tmpdir]]
    :if ([:pick $tmp 0 1] = "/") do={ :set tmp [:pick $tmp 1 [:len $tmp]] }
    :if (($tmp != "") and ([:pick $tmp 0 ([:len $disk]+1)] != ($disk . "/"))) do={ :error "tikray: configure a compatible container tmpdir on the selected disk" }

    # RouterOS prefix membership also accepts the network and broadcast addresses.
    :local slash [:find $subnet "/"]
    :if ([:typeof $slash] != "num") do={ :error "tikray: choose a canonical private IPv4 container subnet" }
    :local bits [:tonum [:pick $subnet ($slash+1) [:len $subnet]]]
    :local network [:toip [:pick $subnet 0 $slash]]
    :if (([:typeof $bits] != "num") or ($bits > 29) or ($bits < 8) or ([:typeof $network] != "ip")) do={ :error "tikray: invalid container subnet" }
    :local mask (255.255.255.255 << (32-$bits))
    :if ((($network & $mask) != $network) or (!(($network in 10.0.0.0/8) or (($network in 172.16.0.0/12) and ($bits >= 12)) or (($network in 192.168.0.0/16) and ($bits >= 16))))) do={ :error "tikray: choose an aligned private subnet" }
    :local routerIP ($network + 1)
    :local ctlIP ($network + 2)
    :local runnerIP ($network + 3)
    :local prefixOf do={
        :local s [:tostr $1]; :local pos [:find $s "/"]
        :local n [:tonum [:pick $s ($pos+1) [:len $s]]]
        :return (([:toip [:pick $s 0 $pos]] & (255.255.255.255 << (32-$n))) . "/" . $n)
    }
    :local overlaps do={
        :local p [:tostr $1]; :local q [:tostr $2]
        :local a [:toip [:pick $p 0 [:find $p "/"]]]; :local b [:toip [:pick $q 0 [:find $q "/"]]]
        :local bitsA [:tonum [:pick $p ([:find $p "/"]+1) [:len $p]]]
        :local bitsB [:tonum [:pick $q ([:find $q "/"]+1) [:len $q]]]
        :local n $bitsA; :if ($bitsB < $n) do={ :set n $bitsB }
        :local m (255.255.255.255 << (32-$n))
        :return (($a & $m) = ($b & $m))
    }
    :foreach id in=[/ip/address/find] do={
        :if ([$overlaps [$prefixOf [/ip/address/get $id address]] $subnet] and !(([/ip/address/get $id comment] = "tikray:addr") and ([/ip/address/get $id interface] = "tikray") and ([:tostr [/ip/address/get $id address]] = ($routerIP . "/" . $bits)))) do={ :error "tikray: bridge overlaps another router address; choose a new subnet" }
    }
    # A more-specific connected route would also steal an existing remote LAN.
    # Test ancestors by exact prefix and descendants by native containment.
    :for n from=1 to=($bits-1) do={
        :local other (($network & (255.255.255.255 << (32-$n))) . "/" . $n)
        :if ([:len [/ip/route/find where routing-table=main and dst-address=$other]] > 0) do={ :error "tikray: bridge overlaps a configured route; choose a new subnet" }
    }
    :local descendants [:parse (":return [/ip/route/find where routing-table=main and dst-address in " . $network . "/" . $bits . "]")]
    :foreach id in=[$descendants] do={
        :local r [/ip/route/get $id]
        :if (!( (($r->"dynamic") = true) and ([:tostr ($r->"dst-address")] = $subnet) and ([:tostr ($r->"gateway")] = "tikray") and ([:len [/ip/address/find where interface="tikray" and comment="tikray:addr"]] = 1) )) do={ :error "tikray: bridge overlaps a configured route; choose a new subnet" }
    }
    :foreach listName in=($lanList,$wanList) do={
        :local list [/interface/list/find where name=$listName and !dynamic]
        :if ([:len $list] != 1) do={ :error "tikray: specify existing LAN and WAN interface lists" }
        :if (([:len [/interface/list/get $list include]] > 0) or ([:len [/interface/list/get $list exclude]] > 0)) do={ :error "tikray: select explicit LAN and WAN interface lists" }
        :if ([:len [/interface/list/member/find where list=$listName]] = 0) do={ :error "tikray: verify LAN and WAN list membership" }
    }
    :local lans [:toarray ""]
    :foreach member in=[/interface/list/member/find where list=$lanList] do={
        :local iface [/interface/list/member/get $member interface]
        :if (($iface = "tikray") or ([:len [/interface/list/member/find where list=$wanList and interface=$iface]] > 0)) do={ :error "tikray: LAN and WAN or container interfaces overlap" }
        :local addresses [/ip/address/find where interface=$iface and !disabled and !invalid]
        :if ([:len $addresses] = 0) do={ :error "tikray: identify every managed LAN IPv4 network" }
        :foreach id in=$addresses do={
            :local cidr [$prefixOf [/ip/address/get $id address]]
            :foreach lan in=$lans do={ :if ([$overlaps ($lan->"prefix") $cidr]) do={ :error "tikray: overlapping managed LAN networks" } }
            :local entry {"interface"=$iface;"prefix"=$cidr;"dedicated"=true}
            :set ($lans->[:len $lans]) $entry
        }
    }
    :local defaults [/ip/route/find where active and routing-table=main and dst-address=0.0.0.0/0]
    :if ([:len $defaults] != 1) do={ :error "tikray: choose one active IPv4 main WAN default" }
    :local actual [/ip/route/get $defaults]
    :if (($actual->"ecmp") = true) do={ :error "tikray: multiple active gateways; choose one WAN" }
    :local hop [:tostr ($actual->"immediate-gw")]
    :local wanIf $hop
    :local pct [:find $hop "%"]
    :if ([:typeof $pct] = "num") do={ :set wanIf [:pick $hop ($pct+1) [:len $hop]] }
    :if ([:len [/interface/list/member/find where list=$wanList and interface=$wanIf]] != 1) do={ :error "tikray: default gateway does not resolve to selected WAN" }
    :local ifaceId [/interface/find where name=$wanIf and running and !disabled]
    :local logical [:tostr ($actual->"gateway")]
    :if ([:len $ifaceId] != 1) do={ :error "tikray: verify the resolved WAN interface" }
    :if ($logical = $wanIf) do={
        :if ([:find {"pppoe-out";"pptp-out";"sstp-out";"l2tp-out";"ovpn-out";"gre-tunnel";"ipip-tunnel"} [:tostr [/interface/get $ifaceId type]]] = nil) do={ :error "tikray: ambiguous WAN interface gateway" }
    } else={
        :if ([:typeof $pct] != "num") do={ :error "tikray: verify the active WAN gateway" }
        :local ip [:toip [:pick $hop 0 $pct]]
        :if (([:typeof $ip] != "ip") or (($logical != [:tostr $ip]) and ($logical != $hop))) do={ :error "tikray: verify the active WAN gateway" }
        :local onlink 0
        :foreach id in=[/ip/address/find where interface=$wanIf and !disabled and !invalid] do={
            :local assigned [/ip/address/get $id address]
            :if ([$overlaps ($ip . "/32") [$prefixOf $assigned]]) do={ :set onlink ($onlink+1) }
        }
        :if ($onlink != 1) do={ :error "tikray: verify the on-link WAN gateway" }
    }
    :local serviceRow [/ip/service/get [:pick [/ip/service/find where name="api-ssl" and !dynamic] 0]]
    :local apiPort ($serviceRow->"port")
    :if (([:typeof $apiPort] != "num") or ($apiPort < 1) or ($apiPort > 65535) or ([:typeof ($serviceRow->"disabled")] != "bool")) do={ :error "tikray: cannot verify api-ssl port or enabled state" }
    :local ctlID
    :local runnerID
    # @TIKRAY_CERTIFICATE@
    :local checkPin [$tls false $routerIP $ctlIP]
    # @TIKRAY_WATCHDOG_PREFLIGHT@
    :local emergency [/system/script/find where name="tikray-emergency-off" or comment="tikray:emergency-off"]
    :if (([:len $emergency] > 1) or (([:len $emergency] = 1) and (([/system/script/get $emergency name] != "tikray-emergency-off") or ([/system/script/get $emergency comment] != "tikray:emergency-off")))) do={ :error "tikray: object conflict in emergency script" }
    :if ([:len [/system/script/job/find where script="tikray-emergency-off"]] > 0) do={ :error "tikray: installer busy; retry after emergency off completes" }
    :if ([:len $emergency] = 1) do={
        :local count 0
        :foreach right in=[/system/script/get $emergency policy] do={
            :if ([:pick $right 0 1] != "!") do={
                :if ([:find {"read";"write";"test"} $right] = nil) do={ :error "tikray: object conflict in emergency script permissions" }
                :set count ($count+1)
            }
        }
        :if (($count != 3) or [/system/script/get $emergency dont-require-permissions]) do={ :error "tikray: object conflict in emergency script permissions" }
    }
    # @TIKRAY_EMERGENCY_PROOF@
    # Menu and property names here are installer constants. Values from the
    # environment are arguments to parsed functions, never executable source.
    :local ensure do={
        :local menu $1; :local role $2; :local keys $3; :local props $4; :local apply $5; :local anchor $6
        :if ($apply) do={ :local check $7; $check $8 }
        :local byTag [:parse (":return [" . $menu . "/find where comment=\$1]")]
        :local found [$byTag $role]
        :local test ""
        :foreach k,v in=$keys do={
            :if ([:len $test] > 0) do={ :set test ($test . " and ") }
            :set test ($test . $k . "=(\$1->\"" . $k . "\")")
        }
        :if ([:len $test] > 0) do={
            :local findKey [:parse (":return [" . $menu . "/find where " . $test . "]")]
            :local same [$findKey $keys]
            :if (([:len $same] != [:len $found]) or ([:tostr $same] != [:tostr $found])) do={ :error ("tikray: object conflict at " . $role) }
        }
        :if ([:len $found] > 1) do={ :error ("tikray: object conflict at " . $role) }
        :if ([:len $found] = 1) do={
            :local get [:parse (":return [" . $menu . "/get \$1]")]
            :local got [$get [:pick $found 0]]
            :if ((($got->"disabled") = true) or (($got->"dynamic") = true)) do={ :error ("tikray: object conflict at " . $role) }
            :foreach k,v in=$props do={
                :local gotValue [:tostr ($got->$k)]
                :if (($menu = "/container/mounts") and ($k = "src") and ([:pick $gotValue 0 1] = "/")) do={ :set gotValue [:pick $gotValue 1 [:len $gotValue]] }
                :if ($gotValue != [:tostr $v]) do={ :error ("tikray: object conflict at " . $role . " " . $k) }
            }
            :if (($menu = "/ip/firewall/filter") or ($menu = "/ip/firewall/raw") or ($menu = "/ip/firewall/nat") or ($menu = "/ipv6/firewall/filter")) do={
                # A hidden selector could turn a bridge drop into a false assurance.
                :foreach k,v in=$got do={
                    :if (([:typeof ($props->$k)] = "nothing") and ([:find {"comment";".id";"dynamic";"disabled";"invalid";"log";"log-prefix";"bytes";"packets"} $k] = nil) and ([:len [:tostr $v]] > 0)) do={ :error ("tikray: object conflict in firewall selectors at " . $role) }
                }
            }
            :local id [:pick $found 0]
            :if ($apply and ([:len [:tostr $anchor]] > 0) and ($id != $anchor)) do={
                :local orderFn [:parse (":return [" . $menu . "/find where chain=\$1 and !dynamic]")]
                :local order [$orderFn ($props->"chain")]
                :if ([:find $order $id] > [:find $order $anchor]) do={
                    :local move [:parse ($menu . "/move \$1 destination=\$2")]
                    $move $id $anchor
                }
            }
            :return $id
        }
        :if (!$apply) do={ :return "" }
        :local source ($menu . "/add comment=\$1")
        :foreach k,v in=$props do={ :set source ($source . " " . $k . "=(\$2->\"" . $k . "\")") }
        :if ([:len [:tostr $anchor]] > 0) do={ :set source ($source . " place-before=\$3") }
        :local add [:parse $source]; $add $role $props $anchor
        :set found [$byTag $role]
        :if ([:len $found] != 1) do={ :error ("tikray: verify new " . $role) }
        :return [:pick $found 0]
    }
    :local dir do={
        :local path $1
        :local ids [/file/find where name=$path]
        :if ([:len $ids] = 0) do={ /file/add name=$path type=directory; :set ids [/file/find where name=$path] }
        :if (([:len $ids] != 1) or ([/file/get $ids type] != "directory")) do={ :error "tikray: installation path conflict" }
    }
    :local noKeys [:toarray ""]
    :foreach n in={"tikray";"tikray-runner";"tikray-ctl"} do={
        :local id [/interface/find where name=$n]
        :local wanted "tikray:bridge"
        :if ($n = "tikray-runner") do={ :set wanted "tikray:veth-runner" }
        :if ($n = "tikray-ctl") do={ :set wanted "tikray:veth-ctl" }
        :if (([:len $id] > 0) and ([:len [/interface/find where name=$n and comment=$wanted]] != 1)) do={ :error "tikray: object conflict at reserved interface" }
    }
    :foreach port in=[/interface/bridge/port/find where bridge="tikray"] do={
        :local iface [/interface/bridge/port/get $port interface]; :local ownedTag [/interface/bridge/port/get $port comment]
        :if (!(($iface = "tikray-ctl" and $ownedTag = "tikray:port-ctl") or ($iface = "tikray-runner" and $ownedTag = "tikray:port-runner"))) do={ :error "tikray: shared_reference_refuses; unexpected bridge port" }
    }
    :local seedPath ($data . "/install.json")
    :local statePath ($data . "/state/routeros.json")
    :local readyPath ($data . "/state/install.ready")
    :local originalUser [/user/find where name="tikray" or comment="tikray:user"]
    :local seedFiles [/file/find where name=$seedPath]
    :if ([:len $seedFiles] = 0) do={
        # An upload directory does not grant ownership of unrelated content.
        # Only the documented public trust input, signed inbox and image pair
        # may be staged in an otherwise new installation tree.
        :local prefix ("^" . $base . "/")
        :foreach f in=[/file/find where name~$prefix] do={
            :local rel [:pick [/file/get $f name] ([:len $base]+1) [:len [/file/get $f name]]]
            :local ok false
            :if ([/file/get $f type] = "directory") do={
                :set ok ([:find {"tmp";"images";"containers";"data";"data/state";"data/cores";"data/run";"data/geo";"data/inbox"} $rel] != nil)
            } else={
                :set ok (($rel = ("images/tikray-" . $arch . ".tar")) or ($rel = ("images/tikray-runner-" . $arch . ".tar")) or ($rel = "data/state/index.pub") or ($rel = "data/inbox/index.json") or ($rel = "data/inbox/index.json.sig") or ($rel ~ "^data/inbox/Xray-linux-[A-Za-z0-9_-]+\\.zip(\\.dgst)?\$"))
                # Unknown incomplete uploads are never imported or removed.
                :if (([:pick $rel 0 17] = "images/.incoming-") and ([:len $rel] >= 49)) do={
                    :local tail [:pick $rel 49 [:len $rel]]
                    :if (([:pick $rel 17 49] ~ "^[a-f0-9]+\$") and ([:find {"-tikray-amd64.tar";"-tikray-arm64.tar";"-tikray-runner-amd64.tar";"-tikray-runner-arm64.tar"} $tail] != nil)) do={ :set ok true }
                }
            }
            :if (!$ok) do={ :error "tikray: object conflict in data folder; select a new dedicated tikray directory" }
        }
    }
    :if (([:len $originalUser] > 0) and ([:len [/file/find where name=$statePath]] != 1)) do={ :error "tikray: object conflict; restore the original private control state" }
    :if (([:len $seedFiles] = 0) and (([:len [/file/find where name=$statePath]] > 0) or ([:len [/file/find where name=$readyPath]] > 0))) do={ :error "tikray: object conflict; restore the original installation handoff" }
    # A changed service pin never authorizes upgrading or replacing an install.
    :if ([:len $seedFiles] > 0) do={
        :local saved [:deserialize from=json options=json.no-string-conversion value=[/file/get $seedFiles contents]]
        :if ((($saved->"scope"->"subnet") != $subnet) or (($saved->"scope"->"lan_list") != $lanList) or (($saved->"address") != ($routerIP . ":" . $apiPort)) or (($saved->"fingerprint") != [/certificate/get [find where name=[/ip/service/get api-ssl certificate]] fingerprint])) do={ :error "tikray: object conflict; verify existing install topology and pin" }
    }
    :local groupId [/user/group/find where name="tikray" or comment="tikray:group"]
    :if ([:len $groupId] > 0) do={
        :if (([:len $groupId] != 1) or ([:len [/user/group/find where name="tikray" and comment="tikray:group"]] != 1)) do={ :error "tikray: object conflict at restricted group" }
        :local count 0
        :foreach right in=[/user/group/get $groupId policy] do={
            :if ([:pick [:tostr $right] 0 1] != "!") do={
                :if (($right != "read") and ($right != "write") and ($right != "api")) do={ :error "tikray: object conflict at restricted group policy" }
                :set count ($count+1)
            }
        }
        :if ($count != 3) do={ :error "tikray: object conflict at restricted group policy" }
    }
    :if ([:len $originalUser] > 0) do={
        :if (([:len $originalUser] != 1) or ([:len [/user/find where name="tikray" and comment="tikray:user" and group="tikray" and !disabled]] != 1) or (([:tostr [/user/get $originalUser address]] != ($ctlIP . "/32")) and ([:tostr [/user/get $originalUser address]] != [:tostr $ctlIP]))) do={ :error "tikray: object conflict at restricted user" }
    }
    :foreach id in=[/container/mounts/find where list="tikray" or list="tikray-runner" or comment~"^tikray:mount-"] do={
        :local c [/container/mounts/get $id comment]
        :if ([:find {"tikray:mount-tikray-data";"tikray:mount-runner-run";"tikray:mount-runner-cores";"tikray:mount-runner-geo"} $c] = nil) do={ :error "tikray: object conflict in mount list" }
    }
    :foreach id in=[/container/envs/find where list="tikray" or list="tikray-runner" or comment~"^tikray:env-"] do={
        :local tagSeen [/container/envs/get $id comment]
        :if ([:find {"tikray:env-ctl-data";"tikray:env-runner-data"} $tagSeen] = nil) do={ :error "tikray: object conflict; unexpected container environment" }
    }
    # Paths returned by v7 container menus have a leading slash. Match a full
    # path component so an owner's neighbouring folder is never taken as ours.
    :local normalized do={
        :local p [:tostr $1]
        :if ([:pick $p 0 1] = "/") do={ :set p [:pick $p 1 [:len $p]] }
        :if (([:len $p] > 0) and ([:pick $p ([:len $p]-1) [:len $p]] = "/")) do={ :set p [:pick $p 0 ([:len $p]-1)] }
        :return $p
    }
    :foreach componentName in={"tikray";"tikray-runner"} do={
        :local ownedTag "tikray:tikray"; :local iface "tikray-ctl"; :local root ($base . "/containers/control")
        :if ($componentName = "tikray-runner") do={ :set ownedTag "tikray:runner"; :set iface "tikray-runner"; :set root ($base . "/containers/runner") }
        :local ids [/container/find where name=$componentName or comment=$ownedTag or root-dir=$root or root-dir=("/" . $root) or interface=$iface]
        :if ([:len $ids] > 0) do={
            :if (([:len $ids] != 1) or ([:len [/container/find where name=$componentName and comment=$ownedTag and interface=$iface]] != 1) or ([:len $seedFiles] = 0)) do={ :error "tikray: object conflict at container; inspect the existing installation" }
            :local item [/container/get $ids]
            :if (([$normalized ($item->"root-dir")] != $root) or ([:tostr ($item->"mountlists")] != $componentName) or ([:tostr ($item->"envlists")] != $componentName) or ([:tostr ($item->"dns")] != [:tostr $routerIP]) or ([:len ($item->"entrypoint")] > 0)) do={ :error "tikray: object conflict in container executable, mounts or DNS" }
        } else={
            :if ([:len [/file/find where name=$root]] > 0) do={ :error "tikray: object conflict in container root directory" }
        }
    }
    :local diskSlot [:tostr [/disk/get $volume slot]]
    :local overlapsPath do={
        :local p ([:tostr $1] . "/"); :local q ([:tostr $2] . "/")
        :local alias ($3 . "/")
        :if ([:pick $p 0 [:len $alias]] = $alias) do={ :set p ($4 . "/" . [:pick $p [:len $alias] [:len $p]]) }
        :return (([:pick $p 0 [:len $q]] = $q) or ([:pick $q 0 [:len $p]] = $p) or ([:find $p "//"] != nil) or ([:find ("/" . $p) "/../"] != nil) or ([:find ("/" . $p) "/./"] != nil))
    }
    :local restrictions {"tikray";"tikray-runner"}
    :foreach c in=[/container/find] do={
        :local mounts [/container/get $c mountlists]
        :local own ([:find {"tikray:tikray";"tikray:runner"} [/container/get $c comment]] != nil)
        :if (!$own and [$overlapsPath [$normalized [/container/get $c root-dir]] $base $diskSlot $disk]) do={ :error "tikray: shared_reference_refuses; overlapping container root" }
        :if (!$own) do={
            :foreach envList in=[/container/get $c envlists] do={
                :if ([:find $restrictions $envList] != nil) do={ :error "tikray: shared_reference_refuses; private environment list is in use" }
            }
        }
        :foreach list in=$mounts do={
            :if (!$own) do={
                :foreach m in=[/container/mounts/find where list=$list] do={
                    :local origin [$normalized [/container/mounts/get $m src]]
                    :if (([:len $origin] = 0) or [$overlapsPath $origin $base $diskSlot $disk]) do={ :error "tikray: shared_reference_refuses; another container can access private installation files" }
                }
            }
            :if (([:find $restrictions $list] != nil) and ([:find {"tikray:tikray";"tikray:runner"} [/container/get $c comment]] = nil)) do={ :error "tikray: shared_reference_refuses; private mount list is in use" }
        }
    }
    :local tags {"tikray:acl-control-runner";"tikray:acl-runner-reply";"tikray:acl-established";"tikray:acl-lan-https";"tikray:acl-dns-udp";"tikray:acl-dns-tcp";"tikray:acl-deny";"tikray:acl-input-dns-udp";"tikray:acl-input-dns-tcp";"tikray:acl-input-reply";"tikray:acl-input-api";"tikray:acl-input-deny"}
    :foreach f in=[/ip/firewall/filter/find where chain="tikray-bridge-fw" or chain="tikray-bridge-in" or jump-target="tikray-bridge-fw" or jump-target="tikray-bridge-in"] do={
        :local ownedTag [/ip/firewall/filter/get $f comment]
        :if (([:find $tags $ownedTag] = nil) and ($ownedTag != "tikray:acl-hook") and ($ownedTag != "tikray:acl-input-hook")) do={ :error "tikray: shared_reference_refuses; firewall chain is already used" }
    }
    :local oldApiOff ($serviceRow->"disabled")
    :local receipt [/system/script/find where name="tikray-api-receipt" or name="tikray-api-access"]
    :if ([:len $receipt] > 0) do={
        :local comment [/system/script/get $receipt comment]
        :local z [:deserialize from=json options=json.no-string-conversion value=[:pick $comment ([:find $comment " "]+1) [:len $comment]]]
        :set oldApiOff ($z->"disabled")
    }
    :local lease [:toarray ""]
    :onerror installError in={
    :foreach apply in={false;true} do={
        :if ($apply) do={
            :set lease [$acquireInstall]
            # The claim prevents a later tick from restarting a container
            # under the installer. Give an already running tick time to end.
            :local waitTick 0
            :while (([:len [/system/script/job/find where script="tikray-watchdog"]] > 0) and ($waitTick < 20)) do={ :delay 1s; :set waitTick ($waitTick+1) }
            :if (([:len [/system/script/job/find where script="tikray-watchdog" or script="tikray-emergency-off"]] > 0)) do={ :error "tikray: installer busy; retry after the local job completes" }
            $requireInstall $lease
            :if (([:tostr [/file/find where name=$seedPath]] != [:tostr $seedFiles]) or ([:tostr [/user/find where name="tikray" or comment="tikray:user"]] != [:tostr $originalUser]) or ([:tostr [/user/group/find where name="tikray" or comment="tikray:group"]] != [:tostr $groupId])) do={ :error "tikray: installation changed during preflight; retry import" }
            $dir $base; $dir ($base . "/images")
            :local archivesVerified false
            # @TIKRAY_ARCHIVES@
            :if (!$archivesVerified) do={ :error "tikray: archive verification required" }
            $dir ($base . "/containers"); $dir $data
            :foreach part in={"run";"cores";"geo"} do={ $dir ($data . "/" . $part) }
        }
        :local i [$ensure "/interface/bridge" "tikray:bridge" ({"name"="tikray"}) ({"name"="tikray";"protocol-mode"="none"}) $apply "" $requireInstall $lease]
        :foreach side in={"ctl";"runner"} do={
            :local componentName ("tikray-" . $side); :local ip $ctlIP
            :if ($side = "runner") do={ :set ip $runnerIP }
            :local p {"name"=$componentName;"address"=($ip . "/" . $bits);"gateway"=$routerIP}
            :set i [$ensure "/interface/veth" ("tikray:veth-" . $side) ({"name"=$componentName}) $p $apply "" $requireInstall $lease]
            :set i [$ensure "/interface/bridge/port" ("tikray:port-" . $side) ({"interface"=$componentName}) ({"bridge"="tikray";"interface"=$componentName}) $apply "" $requireInstall $lease]
        }
        :set i [$ensure "/ip/address" "tikray:addr" ({"address"=($routerIP . "/" . $bits)}) ({"address"=($routerIP . "/" . $bits);"interface"="tikray"}) $apply "" $requireInstall $lease]
        :set i [$ensure "/ip/firewall/nat" "tikray:nat-containers" $noKeys ({"chain"="srcnat";"src-address"=$subnet;"out-interface-list"=$wanList;"action"="masquerade"}) $apply "" $requireInstall $lease]
        :local fwd "tikray-bridge-fw"; :local inChain "tikray-bridge-in"
        :local before [$ensure "/ip/firewall/filter" "tikray:acl-deny" $noKeys ({"chain"=$fwd;"action"="drop"}) $apply "" $requireInstall $lease]
        :foreach proto in={"udp";"tcp"} do={
            :local props {"chain"=$fwd;"action"="accept";"in-interface-list"=$lanList;"dst-address"=$runnerIP;"protocol"=$proto;"dst-port"="53";"connection-nat-state"="dstnat"}
            :set before [$ensure "/ip/firewall/filter" ("tikray:acl-dns-" . $proto) $noKeys $props $apply $before $requireInstall $lease]
        }
        :set before [$ensure "/ip/firewall/filter" "tikray:acl-lan-https" $noKeys ({"chain"=$fwd;"action"="accept";"in-interface-list"=$lanList;"dst-address"=$ctlIP;"protocol"="tcp";"dst-port"="443"}) $apply $before $requireInstall $lease]
        :set before [$ensure "/ip/firewall/filter" "tikray:acl-established" $noKeys ({"chain"=$fwd;"action"="accept";"connection-state"="established,related";"connection-nat-state"="srcnat"}) $apply $before $requireInstall $lease]
        # With global bridge filtering, packets between the two veths enter
        # forward as well. The exact ingress bridge port excludes LAN spoofs.
        :if ([/interface/bridge/settings/get use-ip-firewall]) do={
            :set before [$ensure "/ip/firewall/filter" "tikray:acl-control-runner" $noKeys ({"chain"=$fwd;"action"="accept";"in-bridge-port"="tikray-ctl";"src-address"=$ctlIP;"dst-address"=$runnerIP}) $apply $before $requireInstall $lease]
            :set before [$ensure "/ip/firewall/filter" "tikray:acl-runner-reply" $noKeys ({"chain"=$fwd;"action"="accept";"in-bridge-port"="tikray-runner";"src-address"=$runnerIP;"dst-address"=$ctlIP;"connection-state"="established,related"}) $apply $before $requireInstall $lease]
        }
        :set before [$ensure "/ip/firewall/filter" "tikray:acl-input-deny" $noKeys ({"chain"=$inChain;"action"="drop"}) $apply "" $requireInstall $lease]
        :set before [$ensure "/ip/firewall/filter" "tikray:acl-input-api" $noKeys ({"chain"=$inChain;"action"="accept";"src-address"=$ctlIP;"dst-address"=$routerIP;"protocol"="tcp";"dst-port"=$apiPort}) $apply $before $requireInstall $lease]
        :set before [$ensure "/ip/firewall/filter" "tikray:acl-input-reply" $noKeys ({"chain"=$inChain;"action"="accept";"connection-state"="established,related"}) $apply $before $requireInstall $lease]
        :foreach proto in={"udp";"tcp"} do={
            :set before [$ensure "/ip/firewall/filter" ("tikray:acl-input-dns-" . $proto) $noKeys ({"chain"=$inChain;"action"="accept";"src-address"=$subnet;"dst-address"=$routerIP;"protocol"=$proto;"dst-port"="53"}) $apply $before $requireInstall $lease]
        }
        :local first [:pick [/ip/firewall/filter/find where chain="forward" and !dynamic] 0]
        :local hook [$ensure "/ip/firewall/filter" "tikray:acl-hook" $noKeys ({"chain"="forward";"action"="jump";"jump-target"=$fwd;"dst-address"=$subnet}) $apply $first $requireInstall $lease]
        :if ($apply and ([:len [:tostr $first]] > 0) and ($first != $hook) and ([:pick [/ip/firewall/filter/find where chain="forward" and !dynamic] 0] != $hook)) do={ /ip/firewall/filter/move $hook destination=$first }
        :set first [:pick [/ip/firewall/filter/find where chain="input" and !dynamic and comment!="tikray:acl-input-hook" and comment!="tikray:acl-wan-api"] 0]
        :set hook [$ensure "/ip/firewall/filter" "tikray:acl-input-hook" $noKeys ({"chain"="input";"action"="jump";"jump-target"=$inChain;"in-interface"="tikray"}) $apply $first $requireInstall $lease]
        :if ($oldApiOff) do={
            :set hook [$ensure "/ip/firewall/filter" "tikray:acl-wan-api" $noKeys ({"chain"="input";"action"="drop";"in-interface-list"=$wanList;"protocol"="tcp";"dst-port"=$apiPort}) $apply $hook $requireInstall $lease]
        }
        :if ($oldApiOff) do={
            :set first [:pick [/ipv6/firewall/filter/find where chain="input" and !dynamic and comment!="tikray:acl-wan-api6"] 0]
            :set hook [$ensure "/ipv6/firewall/filter" "tikray:acl-wan-api6" $noKeys ({"chain"="input";"action"="drop";"in-interface-list"=$wanList;"protocol"="tcp";"dst-port"=$apiPort}) $apply $first $requireInstall $lease]
        }
        # Inspect the original destination before DNS dstnat can replace it.
        # The routed TUN data path retains the original Internet destination.
        :set first [:pick [/ip/firewall/raw/find where chain="prerouting" and !dynamic] 0]
        :set hook [$ensure "/ip/firewall/raw" "tikray:acl-runner-direct" $noKeys ({"chain"="prerouting";"action"="drop";"in-interface-list"=$lanList;"dst-address"=$runnerIP}) $apply $first $requireInstall $lease]
        :if ($apply and ([:len [:tostr $first]] > 0) and ($first != $hook) and ([:pick [/ip/firewall/raw/find where chain="prerouting" and !dynamic] 0] != $hook)) do={ /ip/firewall/raw/move $hook destination=$first }
        :set first [:pick [/ipv6/firewall/filter/find where chain="forward" and !dynamic] 0]
        :set hook [$ensure "/ipv6/firewall/filter" "tikray:acl-v6-bridge" $noKeys ({"chain"="forward";"action"="drop";"out-interface"="tikray"}) $apply $first $requireInstall $lease]
        :set i [$ensure "/container/envs" "tikray:env-ctl-data" $noKeys ({"list"="tikray";"key"="TIKRAY_DATA";"value"="/data"}) $apply "" $requireInstall $lease]
        :set i [$ensure "/container/envs" "tikray:env-runner-data" $noKeys ({"list"="tikray-runner";"key"="TIKRAY_DATA";"value"="/data"}) $apply "" $requireInstall $lease]
        :set i [$ensure "/container/mounts" "tikray:mount-tikray-data" ({"list"="tikray";"dst"="/data"}) ({"list"="tikray";"dst"="/data";"src"=$data;"mode"="rw"}) $apply "" $requireInstall $lease]
        :foreach part in={"run";"cores";"geo"} do={
            :local mode "ro"; :if ($part = "run") do={ :set mode "rw" }
            :set i [$ensure "/container/mounts" ("tikray:mount-runner-" . $part) ({"list"="tikray-runner";"dst"=("/data/" . $part)}) ({"list"="tikray-runner";"dst"=("/data/" . $part);"src"=($data . "/" . $part);"mode"=$mode}) $apply "" $requireInstall $lease]
        }
    }
    $requireInstall $lease
    :local pin [$tls true $routerIP $ctlIP]
    :local scope {"subnet"=$subnet;"lan_list"=$lanList;"lans"=$lans;"wan"={"interface"=$wanIf}}
    :local seed {"version"=1;"address"=($routerIP . ":" . $apiPort);"fingerprint"=$pin;"scope"=$scope;"core"=$core;"offline"=$offline}
    :if ([:len $seedFiles] = 0) do={
        /file/add name=$seedPath type=file contents=[:serialize to=json options=json.no-string-conversion value=$seed]
    }
    :if ([:len $groupId] = 0) do={ /user/group/add name=tikray policy=read,write,api comment="tikray:group" }
    :foreach componentName in={"tikray-runner";"tikray"} do={
        :local ownedTag "tikray:tikray"; :local iface "tikray-ctl"; :local root ($base . "/containers/control"); :local high 134217728; :local maxMem 201326592
        :if ($componentName = "tikray-runner") do={ :set ownedTag "tikray:runner"; :set iface "tikray-runner"; :set root ($base . "/containers/runner"); :set high 201326592; :set maxMem 268435456 }
        :local ids [/container/find where name=$componentName and comment=$ownedTag]
        :if ([:len $ids] = 0) do={
            :local archivePath ($base . "/images/" . $componentName . "-" . $arch . ".tar")
            :if ([$verifyStaged $componentName $archivePath] != true) do={ :error "tikray: archive changed before container import" }
            $requireInstall $lease
            /container/add name=$componentName comment=$ownedTag interface=$iface file=$archivePath root-dir=$root dns=$routerIP mountlists=$componentName envlists=$componentName start-on-boot=yes restart-policy=on-failure memory-high=$high memory-max=$maxMem logging=no
            :local appeared 0
            :set ids [/container/find where name=$componentName and comment=$ownedTag]
            :while (([:len $ids] = 0) and ($appeared < 120)) do={
                :delay 1s; :set appeared ($appeared+1)
                :set ids [/container/find where name=$componentName and comment=$ownedTag]
            }
        }
        :if ([:len $ids] != 1) do={ :error "tikray: verify container import" }
        :local id [:pick $ids 0]
        :if ($componentName = "tikray") do={ :set ctlID $id } else={ :set runnerID $id }
        :local waited 0
        :while (([:len [/container/find where name=$componentName and running]] = 0) and ([:len [/container/find where name=$componentName and stopped]] = 0) and ($waited < 180)) do={ :delay 1s; :set waited ($waited+1) }
        :if ($waited = 180) do={ :error "tikray: inspect container extraction on the data disk" }
        $requireInstall $lease
        :if (([/container/get $id memory-high] != $high) or ([/container/get $id memory-max] != $maxMem) or ([:tostr [/container/get $id restart-policy]] != "on-failure") or (![/container/get $id start-on-boot])) do={
            /container/set $id memory-high=$high memory-max=$maxMem restart-policy=on-failure start-on-boot=yes
        }
        :if ($componentName = "tikray") do={
            :local cmd [:tostr [/container/get $id cmd]]
            :if ((($cmd != "") and ($cmd != "serve")) or ([:len [/container/find where name=$componentName and stopped]] = 1)) do={
                :if ([:len [/container/find where name=$componentName and running]] > 0) do={ /container/stop $id; :delay 2s }
                /container/unset $id cmd
            }
        }
        :if ([:len [/container/find where name=$componentName and stopped]] = 1) do={ /container/start $id }
    }
    :local waited 0
    :while (([:len [/file/find where name=$statePath]] = 0) and ($waited < 120)) do={ :delay 1s; :set waited ($waited + 1) }
    :if ([:len [/file/find where name=$statePath]] != 1) do={ :error "tikray: retry bootstrap after checking the private control volume" }
    $requireInstall $lease
    :if ([:len $originalUser] = 0) do={
        :local auth
        :onerror e in={ :set auth [:deserialize from=json options=json.no-string-conversion value=[/file/get [/file/find where name=$statePath] contents]] } do={ :error "tikray: inspect private handoff permissions and format" }
        :if ((($auth->"username") != "tikray") or ([:len ($auth->"password")] < 32) or (($auth->"fingerprint") != $pin) or (($auth->"address") != ($routerIP . ":" . $apiPort))) do={ :error "tikray: refuse incompatible private handoff" }
        :onerror e in={ /user/add name=tikray group=tikray address=($ctlIP . "/32") password=($auth->"password") comment="tikray:user" } do={ :error "tikray: inspect restricted account creation" }
    }
    $requireInstall $lease
    # @TIKRAY_EMERGENCY@
    # @TIKRAY_WATCHDOG@
    :set waited 0
    :while (([:len [/file/find where name=$readyPath]] = 0) and ($waited < 300)) do={ :delay 1s; :set waited ($waited + 1) }
    :if ([:len [/file/find where name=$readyPath]] != 1) do={ :error "tikray: retry bootstrap; check the core source and rerun install" }
    :local httpsPin [/file/get [/file/find where name=$readyPath] contents]
    :if (!($httpsPin ~ "^[a-f0-9]+\$") or ([:len $httpsPin] != 64)) do={ :error "tikray: retry bootstrap; control identity could not be verified" }
    # A leftover ready file cannot prove the current router or runner is
    # reachable. Only the state-owning daemon can answer a fresh challenge.
    $requireInstall $lease
    :local nonce [:rndstr length=32 from="0123456789abcdef"]
    :local request ($data . "/install.check")
    :local checked ($data . "/state/install.checked")
    :local rq [/file/find where name=$request]
    :if ([:len $rq] = 0) do={ /file/add name=$request type=file contents=$nonce } else={
        :if (([:len $rq] != 1) or ([/file/get $rq type] = "directory") or ([:len [/file/get $rq contents]] != 32)) do={ :error "tikray: verify install challenge file" }
        /file/set $rq contents=$nonce
    }
    :local answer ""; :set waited 0
    :while (($answer != ($nonce . " " . $httpsPin)) and ($waited < 60)) do={
        :local f [/file/find where name=$checked]
        :if ([:len $f] = 1) do={ :set answer [/file/get $f contents] }
        :if ($answer != ($nonce . " " . $httpsPin)) do={ :delay 1s; :set waited ($waited+1) }
    }
    :if ($answer != ($nonce . " " . $httpsPin)) do={ :error "tikray: retry bootstrap; live control, runner and router verification failed" }
    :put ("tikray: https://" . $ctlIP . "/  SHA-256 " . $httpsPin)
    :if ([:len [/file/find where name=($data . "/state/setup.code")]] = 1) do={
        :local shown false
        :if ($displaySetup) do={
            :onerror e in={
                :local show [:parse "/container/shell \$1 cmd=\"tikray setup-code\""]
                $show $ctlID; :set shown true
            } do={}
        }
        :if (!$shown) do={ :put ("For first setup, run /container/shell " . $ctlID . " in your private router terminal, then run tikray setup-code.") }
    }

    } do={
        $releaseInstall $lease
        :error $installError
    }
    $releaseInstall $lease
}
