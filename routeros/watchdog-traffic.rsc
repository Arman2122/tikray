# Snapshot the installed aperture before changing it. A runner can answer
# ping before its xray or DNS is usable, so native check-gateway alone is
# insufficient during a replacement.
:local imageTraffic do={
    :local operation $1; :local prior $2; :local peer $3; :local lan $4
    :local checkOwner $5; :local grant $6; :local emergency $7
    :local collect do={
        :local runIP $1; :local lanList $2; :local off $3; :local op $4; :local rows [:toarray ""]
        :local tableCount [:len [/routing/table/find where name="tikray-open" or name="tikray-closed" or comment="tikray:table-open" or comment="tikray:table-closed"]]
        :if ($tableCount=0) do={
            :if (([:len [/ip/firewall/mangle/find where comment="tikray:jump-pre"]]>0) or ([:len [/tool/netwatch/find where comment="tikray:runner-watch"]]>0) or ([:len [/ip/firewall/nat/find where comment~"^tikray:dns-"]]>0)) do={:error "image: incomplete native policy"}
            :return $rows
        }
        :if ($tableCount!=2) do={:error "image: routing table identity conflict"}
        :foreach class in={"open";"closed"} do={
            :local tableName ("tikray-" . $class)
            :if ([:len [/routing/table/find where name=$tableName and comment=("tikray:table-" . $class) and fib and !disabled]]!=1) do={:error "image: routing table conflict"}
            :local tagValue ("tikray:route-" . $class . "-runner")
            :local tagged [/ip/route/find where comment=$tagValue]
            :local safe [/ip/route/find where comment=$tagValue and routing-table=$tableName and dst-address="0.0.0.0/0" and distance=1 and !dynamic]
            :if (([:len $tagged]!=1) or ([:len $safe]!=1) or ([:pick $safe 0]!=[:pick $tagged 0])) do={:error "image: primary route conflict"}
            :local id [:pick $safe 0]; :local r [/ip/route/get $id]
            :if (([:tostr ($r->"gateway")]!=[:tostr $runIP]) or ([:tostr ($r->"check-gateway")]!="ping") or (($r->"blackhole")=true)) do={:error "image: wrong native primary"}
            :set ($rows->$tagValue) {"menu"="/ip/route";"id"=$id;"disabled"=(($r->"disabled")=true)}
            :local secondary ("tikray:route-" . $class . "-fallback")
            :local fall [/ip/route/find where comment=$secondary and routing-table=$tableName and dst-address="0.0.0.0/0" and distance=2 and !disabled and !dynamic]
            :if (([:len $fall]!=1) or ([:len [/ip/route/find where comment=$secondary]]!=1) or ([:len [/ip/route/find where routing-table=$tableName]]!=2)) do={:error "image: native fallback conflict"}
            :set r [/ip/route/get [:pick $fall 0]]
            :if ($class="closed") do={
                :if (($r->"blackhole")!=true) do={:error "image: missing closed blackhole"}
            } else={
                :local marker [/ip/firewall/mangle/find where comment="tikray:route-open" and chain=tikray-pre and action=mark-routing and new-routing-mark=tikray-open and !passthrough and !dynamic]
                :if (([:len $marker]!=1) or ([:len [/ip/firewall/mangle/find where comment="tikray:route-open"]]!=1)) do={:error "image: open steering changed"}
                :local match false
                :if ($op!="hold") do={
                    # Limit untagged route reads to the approved filtered and projected main defaults.
                    :local wan [/ip/route/print as-value proplist=gateway,immediate-gw,ecmp where routing-table="main" and dst-address="0.0.0.0/0" and active]
                    :if ([:len $wan]=1) do={
                        :local def [:pick $wan 0]; :local remote [:tostr ($def->"immediate-gw")]
                        :local target [:tostr ($r->"gateway")]; :local hop [:tostr ($r->"immediate-gw")]
                        :set match (($remote!="") and (($def->"ecmp")!=true) and (($target=[:tostr ($def->"gateway")]) or ($target=$remote) or ($hop=$remote)))
                    }
                    :if ((!$match) and ($op="read")) do={:error "image: unverified WAN fallback"}
                }
                # Open-marked connections use main throughout hold. A changed
                # WAN continues to work until ordinary post-update reconciliation
                # verifies and updates the tagged fallback and restores this rule.
                :local markID [:pick $marker 0]; :if ([:tostr [/ip/firewall/mangle/get $markID connection-mark]]!="tikray-open") do={:error "image: open connection mark changed"}
                :set ($rows->"tikray:route-open") {"menu"="/ip/firewall/mangle";"id"=$markID;"disabled"=[/ip/firewall/mangle/get $markID disabled];"verified"=$match}
            }
        }
        :local watches [/tool/netwatch/find where comment="tikray:runner-watch"]
        :if (([:len $watches]!=1) or ([:len [/tool/netwatch/find where comment="tikray:runner-watch" and type=simple and host=$runIP]]!=1)) do={:error "image: netwatch conflict"}
        :local id [:pick $watches 0]
        :set ($rows->"tikray:runner-watch") {"menu"="/tool/netwatch";"id"=$id;"disabled"=[/tool/netwatch/get $id disabled]}
        :foreach proto in={"tcp";"udp"} do={
            :local number "6"; :if ($proto="udp") do={:set number "17"}
            :local acl ("tikray:acl-dns-" . $proto); :local items [/ip/firewall/filter/find where comment=$acl]
            :local aclMatch [/ip/firewall/filter/find where comment=$acl and chain="tikray-bridge-fw" and action=accept and in-interface-list=$lanList and !dynamic]
            :if (([:len $items]!=1) or ([:len $aclMatch]!=1)) do={:error "image: runner DNS aperture identity changed"}
            :set id [:pick $items 0]; :local r [/ip/firewall/filter/get $id]
            :local addr [:tostr ($r->"dst-address")]; :local pt [:tostr ($r->"dst-port")]; :local pr [:tostr ($r->"protocol")]
            :if ([:tostr ($r->"connection-nat-state")]!="dstnat") do={:error "image: runner DNS aperture NAT changed"}
            :if ((($addr!=[:tostr $runIP]) and ($addr!=([:tostr $runIP] . "/32"))) or (($pt!="53") and ($pt!="53-53")) or (($pr!=$proto) and ($pr!=$number))) do={:error "image: runner DNS aperture changed"}
            :set ($rows->$acl) {"menu"="/ip/firewall/filter";"id"=$id;"disabled"=(($r->"disabled")=true)}
            :foreach mode in={"smart";"full"} do={
                :local role ("tikray:dns-" . $mode . "-open-" . $proto)
                :local fallback ("tikray:dns-router-" . $mode . "-open-" . $proto)
                :local srcList ("tikray-src-" . $mode . "-open")
                :local nat [/ip/firewall/nat/find where comment=$role]; :local redirect [/ip/firewall/nat/find where comment=$fallback]
                :if (([:len $nat]>0) or ([:len $redirect]>0) or ([:len [/ip/firewall/address-list/find where list=$srcList]]>0)) do={
                    :if (([:len $nat]!=1) or ([:len $redirect]!=1)) do={:error "image: incomplete native open DNS"}
                    :foreach flag in={"primary";"fallback"} do={
                        :local key $role; :local act "dst-nat"; :if ($flag="fallback") do={:set key $fallback; :set act "redirect"}
                        :local safe [/ip/firewall/nat/find where comment=$key and chain=dstnat and action=$act and in-interface-list=$lanList and src-address-list=$srcList and !dynamic]
                        :if ([:len $safe]!=1) do={:error "image: native open DNS changed"}
                        :set id [:pick $safe 0]; :set r [/ip/firewall/nat/get $id]
                        :set pr [:tostr ($r->"protocol")]; :set pt [:tostr ($r->"dst-port")]; :local toPort [:tostr ($r->"to-ports")]
                        :if ((($pr!=$proto) and ($pr!=$number)) or (($pt!="53") and ($pt!="53-53")) or (($toPort!="53") and ($toPort!="53-53"))) do={:error "image: native open DNS changed"}
                        :if ($flag="primary") do={
                            :if ([:tostr ($r->"to-addresses")]!=[:tostr $runIP]) do={:error "image: native DNS target changed"}
                            :set ($rows->$role) {"menu"="/ip/firewall/nat";"id"=$id;"disabled"=(($r->"disabled")=true)}
                        } else={:if ((!$off) and (($r->"disabled")=true)) do={:error "image: native DNS fallback disabled"}}
                    }
                }
            }
        }
        # The row can be re-enabled only if every program consists of the
        # exact, compiler-owned open DNS actions in native policy order.
        :local enable ""; :local disable ""
        :foreach mode in={"smart";"full"} do={
            :foreach proto in={"tcp";"udp"} do={
                :local role ("tikray:dns-" . $mode . "-open-" . $proto)
                :if ([:typeof ($rows->$role)]="array") do={
                    :local first (":foreach id in=[/ip/firewall/nat/find where comment=\"" . $role . "\" and disabled=")
                    :set enable ($enable . $first . "yes] do={/ip/firewall/nat/enable \$id};")
                    :set disable ($disable . $first . "no] do={/ip/firewall/nat/disable \$id};")
                }
            }
        }
        :local watcher [:pick $watches 0]
        :if (([:tostr [/tool/netwatch/get $watcher up-script]]!=$enable) or ([:tostr [/tool/netwatch/get $watcher down-script]]!=$disable) or ([:tostr [/tool/netwatch/get $watcher test-script]]!=(":if (\$status = \"up\") do={" . $enable . "} else={" . $disable . "}"))) do={:error "image: open DNS watcher changed"}
        :return $rows
    }
    :local live [$collect $peer $lan $emergency $operation]
    :if ($operation="read") do={
        :local saved [:toarray ""]
        :foreach key,row in=$live do={ :set ($saved->$key) ($row->"disabled") }
        :return $saved
    }
    :if ([:len $prior]!=[:len $live]) do={:error "image: native policy changed during trial"}
    :foreach key,row in=$live do={:if ([:typeof ($prior->$key)]!="bool") do={:error "image: unknown native policy row"}}
    :local release ($operation="release"); :local order {"watch";"open";"routes";"dns";"acl"}
    :if ($release) do={:set order {"acl";"dns";"routes";"open";"watch"}}
    :foreach group in=$order do={
        :foreach key,row in=$live do={
            :local menu ($row->"menu"); :local want true; :if ($release) do={:set want ($prior->$key)}
            :local apply ((($group="watch") and ($menu="/tool/netwatch")) or (($group="open") and ($menu="/ip/firewall/mangle")) or (($group="routes") and ($menu="/ip/route")) or (($group="dns") and ($menu="/ip/firewall/nat")) or (($group="acl") and ($menu="/ip/firewall/filter")))
            # Emergency off owns steering/netwatch while suspended. Only
            # undo the separate bridge DNS lock after real health returns.
            :if ($emergency and ($group!="acl")) do={:set apply false}
            :if ($apply and (($row->"disabled")!=$want)) do={
                :local f [$checkOwner $grant]
                :local fresh [$collect $peer $lan $emergency $operation]; :local match ($fresh->$key)
                :if (([:len $fresh]!=[:len $prior]) or (($match->"id")!=($row->"id"))) do={:error "image: native policy identity changed"}
                :if (($group="open") and $release and (($match->"verified")!=true)) do={:set want true}
                :local setBit [:parse ($menu . "/set \$1 disabled=\$2")]
                $setBit ($match->"id") $want
                :local readBit [:parse (":return [" . $menu . "/get \$1 disabled]")]
                :if ([$readBit ($match->"id")]!=$want) do={:error "image: native policy write unverified"}
            }
        }
        :if (($group="watch") and (!$release) and ([:len $live]>0)) do={:delay 1s; :set live [$collect $peer $lan $emergency $operation]}
    }
    :return true
}
