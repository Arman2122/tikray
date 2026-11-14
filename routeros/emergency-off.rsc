# This block is also included by the installation script.
{
    :local existing [/system/script/find where name="tikray-emergency-off" or comment="tikray:emergency-off"]
    :if ([:len $existing] > 0) do={
        :if (([:len $existing] != 1) or ([:len [/system/script/find where name="tikray-emergency-off" and comment="tikray:emergency-off"]] != 1)) do={
            :error "tikray: emergency script ownership conflict"
        }
    } else={
        /system/script/add name=tikray-emergency-off comment="tikray:emergency-off" policy=read,write,test source={
            :if ([:len [/system/script/job/find where script="tikray-emergency-off"]] > 1) do={ :error "tikray: emergency command already running" }

            :local marker [/system/script/find where name="tikray-emergency-state" or comment="tikray:emergency-state"]
            :if ([:len $marker] > 0) do={
                :if (([:len $marker] != 1) or ([:len [/system/script/find where name="tikray-emergency-state" and comment="tikray:emergency-state" and source=""]] != 1)) do={
                    :error "tikray: emergency marker ownership conflict"
                }
            }
            :local bridge [/interface/bridge/find where name="tikray" and comment="tikray:bridge" and protocol-mode=none and !disabled]
            :local assigned [/ip/address/find where interface="tikray" and comment="tikray:addr" and !disabled and !invalid]
            :if (([:len $bridge] != 1) or ([:len $assigned] != 1)) do={ :error "tikray: installation address unverified" }
            :local addressText [:tostr [/ip/address/get $assigned address]]
            :local routerIP [:pick $addressText 0 [:find $addressText "/"]]
            :local last 0
            :for i from=1 to=3 do={ :set last ([:find $routerIP "." $last] + 1) }
            :local runnerIP [:toip ([:pick $routerIP 0 $last] . ([:tonum [:pick $routerIP $last [:len $routerIP]]] + 2))]

            # The same selectors preflight and execute. A retagged hook into
            # our private chain is ambiguous, even if its old tag is missing.
            :local entries do={
                :local apply ($1 = "mutate")
                :local runner $2
                :local selectOne do={
                    :if (([:len $1] != 1) or ([:len $2] != 1) or ([:tostr $1] != [:tostr $2])) do={ :error ("tikray: emergency " . $3 . " ownership conflict") }
                }
                :local candidates [/tool/netwatch/find where comment="tikray:runner-watch"]
                :if ([:len $candidates] > 0) do={
                    :local safe [/tool/netwatch/find where comment="tikray:runner-watch" and type=simple and host=$runner]
                    $selectOne $candidates $safe "watch"
                    :if ($apply) do={ /tool/netwatch/disable $safe }
                }
                :set candidates [/ip/firewall/mangle/find where jump-target="tikray-pre" or comment="tikray:jump-pre"]
                :if ([:len $candidates] > 0) do={
                    :local safe [/ip/firewall/mangle/find where comment="tikray:jump-pre" and chain=prerouting and action=jump and jump-target="tikray-pre" and !dynamic]
                    $selectOne $candidates $safe "steering"
                    :if ($apply) do={ /ip/firewall/mangle/disable $safe }
                }
                :set candidates [/ip/firewall/filter/find where jump-target="tikray-egress" or comment="tikray:egress-guard"]
                :if ([:len $candidates] > 0) do={
                    :local safe [/ip/firewall/filter/find where comment="tikray:egress-guard" and chain=forward and action=jump and jump-target="tikray-egress" and !dynamic]
                    $selectOne $candidates $safe "egress"
                    :if ($apply) do={ /ip/firewall/filter/disable $safe }
                }
                :set candidates [/ipv6/firewall/filter/find where jump-target="tikray-ipv6" or comment="tikray:ipv6:jump"]
                :if ([:len $candidates] > 0) do={
                    :local safe [/ipv6/firewall/filter/find where comment="tikray:ipv6:jump" and chain=forward and action=jump and jump-target="tikray-ipv6" and !dynamic]
                    $selectOne $candidates $safe "ipv6"
                    :if ($apply) do={ /ipv6/firewall/filter/disable $safe }
                }
                :set candidates [/ip/firewall/filter/find where comment="tikray:no-fasttrack"]
                :if ([:len $candidates] > 0) do={
                    :local safe [/ip/firewall/filter/find where comment="tikray:no-fasttrack" and chain=forward and action=accept and packet-mark="tikray-proxied" and !dynamic]
                    $selectOne $candidates $safe "fasttrack"
                    :if ($apply) do={ /ip/firewall/filter/disable $safe }
                }
                :foreach class in={"open";"closed"} do={
                    :local mark ("tikray-" . $class)
                    :foreach role in={"mss";"packet"} do={
                        :local tag ("tikray:" . $role . "-" . $class)
                        :set candidates [/ip/firewall/mangle/find where comment=$tag]
                        :if ([:len $candidates] > 0) do={
                            :local safe
                            :if ($role = "mss") do={
                                :set safe [/ip/firewall/mangle/find where comment=$tag and chain=forward and action=change-mss and connection-mark=$mark and !dynamic]
                            } else={
                                :set safe [/ip/firewall/mangle/find where comment=$tag and chain=forward and action=mark-packet and connection-mark=$mark and new-packet-mark="tikray-proxied" and !dynamic]
                            }
                            $selectOne $candidates $safe "tools"
                            :if ($apply) do={ /ip/firewall/mangle/disable $safe }
                        }
                    }
                }
                :foreach id in=[/ip/firewall/filter/find where comment~"^tikray:hold:[0-9a-f]+\$"] do={
                    :local tag [/ip/firewall/filter/get $id comment]
                    :if ([:len $tag] = 44) do={
                        :local safe [/ip/firewall/filter/find where comment=$tag and (chain=forward or chain=input) and action=drop and !dynamic]
                        :local ingress [/ip/firewall/filter/get $id in-interface-list]
                        :local src [/ip/firewall/filter/get $id src-address]
                        :local exclusions [:tostr [/ip/firewall/filter/get $id dst-address-list]]
                        :local dns (([/ip/firewall/filter/get $id protocol] = "tcp") or ([/ip/firewall/filter/get $id protocol] = "udp"))
                        :set dns ($dns and ([:tostr [/ip/firewall/filter/get $id dst-port]] = "53"))
                        :local scoped (([/ip/firewall/filter/get $id chain] = "forward") and ($exclusions ~ "^!tikray-h[0-9a-f]+\$") and ([:len $exclusions] = 41))
                        :if (([:len [:tostr $ingress]] = 0) or ([:len [:tostr $src]] = 0) or ((!$dns) and (!$scoped))) do={ :error "tikray: emergency hold selector conflict" }
                        :if (([:len $safe] != 1) or ([:tostr $id] != [:tostr $safe])) do={ :error "tikray: emergency hold ownership conflict" }
                        :if ($apply) do={ /ip/firewall/filter/disable $safe }
                    }
                }
                :foreach id in=[/ipv6/firewall/filter/find where chain=forward and (comment~"^tikray:hold:[0-9a-f]+\$" or jump-target~"^tikray-h[0-9a-f]+\$")] do={
                    :local tag [/ipv6/firewall/filter/get $id comment]
                    :local target [/ipv6/firewall/filter/get $id jump-target]
                    :if (([:len $tag] != 44) or (!($tag ~ "^tikray:hold:[0-9a-f]+\$")) or ([:len $target] != 40) or (!($target ~ "^tikray-h[0-9a-f]+\$"))) do={ :error "tikray: emergency IPv6 hold conflict" }
                    :local safe [/ipv6/firewall/filter/find where comment=$tag and chain=forward and action=jump and jump-target=$target and !dynamic]
                    :if (([:len $safe] != 1) or ([:tostr $id] != [:tostr $safe])) do={ :error "tikray: emergency hold ownership conflict" }
                    :if ($apply) do={ /ipv6/firewall/filter/disable $safe }
                }
                # Remove the source-NAT bypass as well as the classifiers.
                :foreach kind in={"preserve";"preserve-backup"} do={
                    :foreach class in={"open";"closed"} do={
                        :local tag ("tikray:" . $kind . "-" . $class)
                        :local mark ("tikray-" . $class)
                        :local claimed [/ip/firewall/nat/find where comment=$tag]
                        :if ([:len $claimed] > 0) do={
                            :local safe [/ip/firewall/nat/find where comment=$tag and chain=srcnat and action=accept and out-interface="tikray" and connection-mark=$mark and !dynamic]
                            $selectOne $claimed $safe "source NAT"
                            :if ($apply) do={ /ip/firewall/nat/disable $safe }
                        }
                        :foreach mode in={"smart";"full"} do={
                            :local lst ("tikray-src-" . $mode . "-" . $class)
                            :foreach proto in={"tcp";"udp"} do={
                                :set tag ("tikray:" . $kind . "-dns-" . $mode . "-" . $class . "-" . $proto)
                                :set claimed [/ip/firewall/nat/find where comment=$tag]
                                :if ([:len $claimed] > 0) do={
                                    :local safe [/ip/firewall/nat/find where comment=$tag and chain=srcnat and action=accept and out-interface="tikray" and src-address-list=$lst and !dynamic]
                                    $selectOne $claimed $safe "source NAT"
                                    # 7.23.8 prints 53 on this row but find dst-port=53 can miss it.
                                    :local wireProto [:tostr [/ip/firewall/nat/get $safe protocol]]
                                    :local port [:tostr [/ip/firewall/nat/get $safe dst-port]]
                                    :local isProto (($wireProto = $proto) or (($proto = "udp") and ($wireProto = "17")) or (($proto = "tcp") and ($wireProto = "6")))
                                    :if ((!$isProto) or (($port != "53") and ($port != "53-53"))) do={ :error "tikray: emergency source NAT DNS selector conflict" }
                                    :local target [:tostr [/ip/firewall/nat/get $safe dst-address]]
                                    :if (($target != [:tostr $runner]) and ($target != ([:tostr $runner] . "/32"))) do={ :error "tikray: emergency source NAT target conflict" }
                                    :if ($apply) do={ /ip/firewall/nat/disable $safe }
                                }
                            }
                        }
                    }
                }
                :foreach mode in={"smart";"full"} do={
                    :foreach class in={"open";"closed"} do={
                        :local lst ("tikray-src-" . $mode . "-" . $class)
                        :foreach id in=[/ip/firewall/address-list/find where list=$lst] do={
                            :local member [:tostr [/ip/firewall/address-list/get $id address]]
                            :if ([:typeof [:find $member "/"]] = "nil") do={ :set member ($member . "/32") }
                            :local tag ("tikray:src-" . $mode . "-" . $class . ":" . $member)
                            :if ((!($member ~ "^[0-9.]+/[0-9]+\$")) or ($member~"/0\$") or ([:len [/ip/firewall/address-list/find where list=$lst and comment=$tag and !dynamic]] != 1) or ([/ip/firewall/address-list/get $id comment] != $tag)) do={ :error "tikray: emergency source ownership conflict" }
                        }
                        :foreach proto in={"tcp";"udp"} do={
                            :foreach kind in={"primary";"fallback"} do={
                                :local role ("tikray:dns-" . $mode . "-" . $class . "-" . $proto)
                                :local act "dst-nat"
                                :if ($kind = "fallback") do={ :set act "redirect"; :set role ("tikray:dns-router-" . $mode . "-" . $class . "-" . $proto) }
                                :set candidates [/ip/firewall/nat/find where comment=$role or (src-address-list=$lst and action=$act)]
                                :foreach id in=$candidates do={
                                    :local tag [/ip/firewall/nat/get $id comment]
                                    :local wireProto [:tostr [/ip/firewall/nat/get $id protocol]]
                                    :local port [:tostr [/ip/firewall/nat/get $id dst-port]]
                                    :local isProto (($wireProto = $proto) or (($proto = "udp") and ($wireProto = "17")) or (($proto = "tcp") and ($wireProto = "6")))
                                    :local isDNS (($port = "53") or ($port = "53-53"))
                                    :if (($tag = $role) or ($isProto and $isDNS)) do={
                                        :local safe [/ip/firewall/nat/find where comment=$role and chain=dstnat and action=$act and src-address-list=$lst and !dynamic]
                                        :if (([:len $safe] != 1) or ([:tostr $id] != [:tostr $safe]) or (!$isProto) or (!$isDNS)) do={ :error "tikray: emergency DNS selector conflict" }
                                        :local translated [:tostr [/ip/firewall/nat/get $id to-ports]]
                                        :if (($translated != "53") and ($translated != "53-53")) do={ :error "tikray: emergency DNS port conflict" }
                                        :if (($kind = "fallback") and ($class = "closed")) do={ :error "tikray: unexpected closed DNS redirect" }
                                        :if (($kind = "primary") and ([:tostr [/ip/firewall/nat/get $id to-addresses]] != [:tostr $runner])) do={ :error "tikray: emergency DNS target conflict" }
                                        :if ($apply) do={ /ip/firewall/nat/disable $safe }
                                    }
                                }
                            }
                        }
                    }
                }
                :foreach class in={"open";"closed"} do={
                    :local mark ("tikray-" . $class)
                    :foreach id in=[/ip/firewall/mangle/find where new-connection-mark=$mark] do={
                        :local tag [/ip/firewall/mangle/get $id comment]
                        :local valid false
                        :foreach mode in={"smart";"full"} do={
                            :local role ("tikray:conn-" . $mode . "-" . $class)
                            :local lst ("tikray-src-" . $mode . "-" . $class)
                            :if ($tag = $role) do={
                                :local claimed [/ip/firewall/mangle/find where comment=$role]
                                :local safe [/ip/firewall/mangle/find where comment=$role and chain="tikray-pre" and action=mark-connection and new-connection-mark=$mark and src-address-list=$lst and !dynamic]
                                $selectOne $claimed $safe "mark"
                                :if ([:tostr $id] = [:tostr $safe]) do={ :set valid true }
                            }
                        }
                        :if (!$valid) do={ :error "tikray: emergency connection mark conflict" }
                    }
                }
            }

            $entries "inspect" $runnerIP
            # This menu can trap when a selected tuple expires during print.
            # Capture both directions together. The default projection omits
            # the reply fields; filtering by a retired .id can itself trap.
            :local readFlows do={
                :local kind $1; :local scope $2; :local prior $3
                :for attempt from=1 to=40 do={
                    :local rows; :local ok false
                    :onerror queryError in={
                        :if ($kind="marked") do={
                            :set rows [/ip/firewall/connection/print detail as-value where src-address in $scope and (connection-mark="tikray-open" or connection-mark="tikray-closed")]
                        } else={
                            :if ($kind="dns") do={
                                :set rows [/ip/firewall/connection/print detail as-value where src-address in $scope and dstnat and dst-port=53 and reply-src-port=53 and (protocol=tcp or protocol=udp)]
                            } else={
                                :local dst ($prior->"dst"); :local proto ($prior->"protocol")
                                :if (($proto="udp") or ($proto="tcp")) do={
                                    :local sp ($prior->"sport"); :local dp ($prior->"port")
                                    :set rows [/ip/firewall/connection/print detail as-value where src-address=$scope and dst-address=$dst and protocol=$proto and src-port=$sp and dst-port=$dp]
                                } else={
                                    :set rows [/ip/firewall/connection/print detail as-value where src-address=$scope and dst-address=$dst and protocol=$proto]
                                }
                            }
                        }
                        :set ok true
                    } do={ :set ok false }
                    :if ($ok) do={ :return $rows }
                    :delay 100ms
                }
                :error "tikray: affected flow read unverified"
            }
            :local capture do={
                :local row $1
                :local src ($row->"src-address"); :local dst ($row->"dst-address"); :local proto [:tostr ($row->"protocol")]
                :if (([:typeof ($row->".id")]!="id") or ([:typeof $src]!="ip") or ([:typeof $dst]!="ip") or ($proto="") or ([:typeof ($row->"reply-src-address")]!="ip") or ([:typeof ($row->"reply-dst-address")]!="ip")) do={ :error "tikray: incomplete affected tuple" }
                :if ((($proto="tcp") or ($proto="udp")) and (([:typeof ($row->"src-port")]!="num") or ([:typeof ($row->"dst-port")]!="num") or ([:typeof ($row->"reply-src-port")]!="num") or ([:typeof ($row->"reply-dst-port")]!="num"))) do={ :error "tikray: incomplete affected ports" }
                :local origin [:tostr $src]
                :foreach field in={"protocol";"dst-address";"src-port";"dst-port";"icmp-type";"icmp-code";"icmp-id";"gre-protocol";"gre-version";"gre-key"} do={ :set origin ($origin . "|" . [:tostr ($row->$field)]) }
                :local tuple $origin
                :foreach field in={"reply-src-address";"reply-src-port";"reply-dst-address";"reply-dst-port";"connection-mark";"dstnat"} do={ :set tuple ($tuple . "|" . [:tostr ($row->$field)]) }
                :return {"flow"=[:tostr ($row->".id")];"tuple"=$tuple;"origin"=$origin;"src"=$src;"dst"=$dst;"protocol"=$proto;"sport"=($row->"src-port");"port"=($row->"dst-port")}
            }
            # If an enabled owner redirect can produce this same DNS binding,
            # detaching our rule need not terminate the owner's connection.
            # For complex predicates preserve the ambiguous binding, too.
            :local ownerDNS do={
                :local flow $1
                :local peer $2
                :local routerPeer $3
                :local src ($flow->"src")
                :local proto ($flow->"protocol")
                :foreach rule in=[/ip/firewall/nat/find where chain=dstnat and !disabled and (action=redirect or action=dst-nat or action=netmap or action=jump)] do={
                    :local tag [:tostr [/ip/firewall/nat/get $rule comment]]
                    :if (!($tag ~ "^tikray:dns-(router-)?(smart|full)-(open|closed)-(tcp|udp)\$")) do={
                        :local act [/ip/firewall/nat/get $rule action]
                        :local same (($act = "jump") or (($act = "redirect") and $routerPeer))
                        :if (($act = "dst-nat") or ($act = "netmap")) do={
                            :local to [:tostr [/ip/firewall/nat/get $rule to-addresses]]
                            :local single [:toip $to]
                            :set same (([:typeof $single] != "ip") or ($single = $peer))
                        }
                        :local scope [:tostr [/ip/firewall/nat/get $rule src-address]]
                        :if (($scope ~ "^[0-9.]+\$") and ([:toip $scope] != $src)) do={ :set same false }
                        :if ($scope ~ "^[0-9.]+/[0-9]+\$") do={
                            :local literal [:parse (":return " . $scope)]
                            :if (!($src in [$literal])) do={ :set same false }
                        }
                        :local rp [:tostr [/ip/firewall/nat/get $rule protocol]]
                        :if ((($rp = "tcp") and ($proto = "udp")) or (($rp = "udp") and ($proto = "tcp"))) do={ :set same false }
                        :foreach key in={"dst-port";"to-ports"} do={
                            :local port [:tostr [/ip/firewall/nat/get $rule $key]]
                            :if (($port ~ "^[0-9]+\$") and ($port != "53")) do={ :set same false }
                        }
                        :if ($same) do={ :return true }
                    }
                }
                :return false
            }
            # RouterOS may assign a new menu ID while the connection stays
            # alive. Only the original verified ID authorizes a removal. Any
            # surviving owned path on the same original tuple prevents success.
            :local checkFlow do={
                :local purpose $1; :local record $2; :local read $3; :local captureRow $4; :local ownedDNS $5; :local runner $6
                :local matches 0; :local removable false
                :foreach row in=[$read "exact" ($record->"src") $record] do={
                    :local live [$captureRow $row]
                    :if (($live->"origin")=($record->"origin")) do={
                        :set matches ($matches+1)
                        :if ($purpose="remove") do={
                            :if ((($live->"flow")=($record->"flow")) and (($live->"tuple")=($record->"tuple"))) do={ :set removable true }
                        } else={
                            :local mark [:tostr ($row->"connection-mark")]
                            :if (($mark="tikray-open") or ($mark="tikray-closed")) do={ :return true }
                            :local peer ($row->"reply-src-address")
                            :if ((($live->"port")=53) and (($row->"reply-src-port")=53) and (($row->"dstnat")=true) and (($peer=$runner) or ($peer=($record->"dns-peer")))) do={
                                :if (![$ownedDNS $live $peer ($peer!=$runner)]) do={ :return true }
                            }
                        }
                    }
                }
                :return (($purpose="remove") and ($matches=1) and $removable)
            }
            :local frozen [:toarray ""]
            :local dnsRules [:toarray ""]
            # Freeze fallback DNS before detach. After both hooks and netwatch
            # stop, pick up late reserved marks and runner translations only.
            # A new owner redirect to the router must survive this second pass.
            :for pass from=0 to=1 do={
                :if ($pass = 1) do={
                    :if ([:len $marker] = 0) do={ /system/script/add name=tikray-emergency-state comment="tikray:emergency-state" policy=read,write source="" }
                    # A watchdog already inside its restart path must finish first.
                    :local ticks 0
                    :while (([:len [/system/script/job/find where script="tikray-watchdog"]] > 0) and ($ticks < 50)) do={ :delay 100ms; :set ticks ($ticks + 1) }
                    :if ([:len [/system/script/job/find where script="tikray-watchdog"]] > 0) do={ :error "tikray: watchdog is busy" }
                    $entries "mutate" $runnerIP

                    # The netwatch worker may have started a last short toggle before
                    # disable took effect. Restore every redirect bit once it drains.
                    :delay 1s
                    $entries "mutate" $runnerIP
                }
                # RouterOS performs the original-source filter before returning
                # IDs. The numeric-only prefix literal was verified above.
                :foreach mode in={"smart";"full"} do={
                    :foreach class in={"open";"closed"} do={
                        :local lst ("tikray-src-" . $mode . "-" . $class)
                        :if ($pass = 0) do={
                            :foreach proto in={"tcp";"udp"} do={
                                :local primary ("tikray:dns-" . $mode . "-" . $class . "-" . $proto)
                                :local fallback ("tikray:dns-router-" . $mode . "-" . $class . "-" . $proto)
                                # An interrupted command may already have disabled the
                                # primary. Its verified target still identifies a stale
                                # runner binding unless an owner rule would translate it.
                                :if ([:len [/ip/firewall/nat/find where comment=$primary]] = 1) do={ :set ($dnsRules->$primary) "yes" }
                                :if ([:len [/ip/firewall/nat/find where !disabled and comment=$fallback]] = 1) do={ :set ($dnsRules->$fallback) "yes" }
                            }
                        }
                        :foreach memberID in=[/ip/firewall/address-list/find where list=$lst and !dynamic and !disabled] do={
                            :local member [:tostr [/ip/firewall/address-list/get $memberID address]]
                            :if ([:typeof [:find $member "/"]] = "nil") do={ :set member ($member . "/32") }
                            :local tag ("tikray:src-" . $mode . "-" . $class . ":" . $member)
                            :if ((!($member ~ "^[0-9.]+/[0-9]+\$")) or ($member~"/0\$") or ([/ip/firewall/address-list/get $memberID comment] != $tag)) do={ :error "tikray: emergency source changed" }
                            :local literal [:parse (":return " . $member)]
                            :local prefix [$literal]
                            :foreach row in=[$readFlows "marked" $prefix] do={
                                :local record [$capture $row]; :local key [:tostr ($record->"flow")]
                                :set ($frozen->$key) $record
                            }
                            :foreach row in=[$readFlows "dns" $prefix] do={
                                :local record [$capture $row]
                                :local peer ($row->"reply-src-address")
                                :local owned ($peer=$runnerIP)
                                # Open DNS fallback redirects to the router's own
                                # interface; preserve translations to other peers.
                                :if (($pass = 0) and (!$owned) and ([:typeof $peer] = "ip") and ($class = "open")) do={
                                    :local match ("^" . [:tostr $peer] . "/")
                                    :foreach localID in=[/ip/address/find where address~$match and !disabled] do={
                                        :local text [:tostr [/ip/address/get $localID address]]
                                        :if ([:pick $text 0 [:find $text "/"]] = [:tostr $peer]) do={ :set owned true }
                                    }
                                }
                                :if ($owned) do={
                                    :local proto ($record->"protocol")
                                    :local role ("tikray:dns-" . $mode . "-" . $class . "-" . $proto)
                                    :if ($peer != $runnerIP) do={ :set role ("tikray:dns-router-" . $mode . "-" . $class . "-" . $proto) }
                                    :if (($dnsRules->$role) = "yes") do={
                                        :local key [:tostr ($record->"flow")]
                                        :if (![$ownerDNS $record $peer ($peer != $runnerIP)]) do={ :set ($record->"dns-peer") $peer; :set ($frozen->$key) $record }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            :local uncertain false
            :foreach key,record in=$frozen do={
                :local flow ($record->"flow")
                :if ([$checkFlow "remove" $record $readFlows $capture $ownerDNS $runnerIP]) do={
                    # The native row can expire while the mutation is in
                    # flight. Never replay an unacknowledged removal.
                    :onerror removalError in={ /ip/firewall/connection/remove [:toid $flow] } do={ :set uncertain true }
                }
            }
            :if ($uncertain) do={ :delay 100ms }
            # A successful empty exact query or a different tuple proves the
            # old binding gone. A trap or unreadable row cannot prove removal.
            :local pending $frozen
            :local tries 0
            :while (([:len $pending]>0) and ($tries<40)) do={
                :set tries ($tries+1)
                :local outstanding [:toarray ""]
                :foreach key,record in=$pending do={
                    :if ([$checkFlow "verify" $record $readFlows $capture $ownerDNS $runnerIP]) do={ :set ($outstanding->$key) $record }
                }
                :set pending $outstanding
                :if ([:len $pending]>0) do={ :delay 100ms }
            }
            :if ([:len $pending]>0) do={ :error "tikray: affected flow removal unverified" }
        }
    }
}
