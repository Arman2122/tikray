# Separate new open connections from the retained 5-tuples before
# changing the route. A retained no-NAT binding must never reach the WAN.
:local openFlows do={
    :local action $1; :local policy $2; :local runner $3; :local grant $4; :local check $5; :local mode $6; :local emergency $7
    :local nonce ($grant->"staging"->"nonce")
    :if (([:typeof $nonce]!="str") or ([:len $nonce]!=32) or (!($nonce~"^[0-9a-f]+\$"))) do={:error "image: unverified flow operation"}
    :local transit ("tikray-i-" . $nonce); :local normal "tikray-open"; :local pending "tikray-open-udp"
    :local sourceRows [:toarray ""]; :local writers [:toarray ""]; :local expected [:toarray ""]
    :foreach kind in={"smart";"full"} do={
        :local listName ("tikray-src-" . $kind . "-open")
        :local enabled ([:typeof ($policy->("tikray:dns-" . $kind . "-open-udp"))]="array")
        :local split ([:len [/ip/firewall/mangle/find where comment=("tikray:conn-" . $kind . "-open-udp")]]>0)
        :foreach wanted in=({$normal;$pending}) do={
            :local own ("tikray:conn-" . $kind . "-open"); :local protocol ""
            :if ($split) do={:set protocol "!udp"}
            :if ($wanted=$pending) do={:set own ($own . "-udp"); :set protocol "udp"}
            :local ids [/ip/firewall/mangle/find where comment=$own]
            :if (([:len $ids]>0) or ($enabled and (($wanted=$normal) or $split))) do={
                :local configured [/ip/firewall/mangle/find where comment=$own and chain=tikray-pre and action=mark-connection and src-address-list=$listName and passthrough and !dynamic]
                :if ((!$enabled) or ([:len $ids]!=1) or ([:len $configured]!=1) or ([:pick $ids 0]!=[:pick $configured 0])) do={:error "image: open classifier changed"}
                :local id [:pick $ids 0]; :local row [/ip/firewall/mangle/get $id]
                :local current [:tostr ($row->"new-connection-mark")]; :local dest ""
                :if ($kind="smart") do={:set dest "!tikray-domestic"}
                :if (([:tostr ($row->"connection-state")]!="new") or ([:tostr ($row->"connection-mark")]!="no-mark") or ([:tostr ($row->"dst-address-list")]!=$dest) or ([:tostr ($row->"protocol")]!=$protocol) or (($current!=$wanted) and (($mode="read") or ($current!=$transit)))) do={:error "image: open classifier changed"}
                :set ($writers->[:tostr $id]) $own
                :set ($expected->[:tostr $id]) $wanted
            }
        }
        :foreach row in=[/ip/firewall/address-list/print as-value proplist=address,comment,dynamic where list=$listName and !disabled] do={
            :local member [:tostr ($row->"address")]
            :if ([:typeof [:find $member "/"]]="nil") do={:set member ($member . "/32")}
            :local tag ("tikray:src-" . $kind . "-open:" . $member)
            :if ((!$enabled) or (!($member~"^[0-9.]+/[0-9]+\$")) or ($member~"/0\$") or (($row->"dynamic")=true) or (($row->"comment")!=$tag)) do={:error "image: open source ownership changed"}
            :set ($sourceRows->$member) $kind
        }
    }
    # RouterOS can drop the symbolic connection-mark after its last rule
    # is changed. Keep exactly one inert reference until final readback.
    :local tag ("tikray:image-mark:" . $nonce)
    :local keeper do={
        :local group $1; :local stamp $2
        :local refs [/ip/firewall/mangle/find where comment=$group]
        :if ([:len $refs]=0) do={:return ""}
        :local safe [/ip/firewall/mangle/find where comment=$group and chain=tikray-pre and action=mark-connection and !disabled and !dynamic and passthrough and new-connection-mark=$stamp]
        :if (([:len $refs]!=1) or ([:len $safe]!=1) or ([:pick $refs 0]!=[:pick $safe 0])) do={:error "image: transient mark reference changed"}
        :local id [:pick $refs 0]
        :if ([:tostr [/ip/firewall/mangle/get $id connection-mark]]!=$stamp) do={:error "image: transient mark reference changed"}
        :return [:tostr $id]
    }
    :local pin [$keeper $tag $transit]
    :local heldRefs [/ip/firewall/mangle/find where comment~"^tikray:image-mark:"]
    :if (([:len $heldRefs]>0) and (([:len $heldRefs]!=1) or ([:tostr [:pick $heldRefs 0]]!=$pin))) do={:error "image: ambiguous transient mark reference"}
    :if (($mode="read") and ($pin!="")) do={:error "image: transient mark reference already exists"}
    :foreach stamp in=({$normal;$pending;$transit}) do={
        :foreach id in=[/ip/firewall/mangle/find where new-connection-mark=$stamp] do={:if (([:tostr $id]!=$pin) and ([:typeof ($writers->[:tostr $id])]!="str")) do={:error "image: shared connection mark writer"}}
    }
    # Retagging a managed flow must not bypass an owner's explicit policy
    # on the original connection mark. The only allowed consumers are the
    # routing compiler's own named marks and its two source-NAT exceptions.
    :local standard "^!?tikray-open(-udp|-runner|-wan)?\$"
    :foreach id in=[/ip/firewall/filter/find where connection-mark~$standard] do={
        :local row [/ip/firewall/filter/get $id]; :local role ($row->"comment"); :local mark [:tostr ($row->"connection-mark")]
        :local ok ((($role="tikray:udp-guard-legacy") and ($mark=$normal)) or (($role="tikray:udp-guard-pending") and ($mark=$pending)) or (($role="tikray:udp-guard-runner") and ($mark="tikray-open-runner") and ([:tostr ($row->"out-interface")]="!tikray")) or (($role="tikray:udp-guard-wan") and ($mark="tikray-open-wan") and ([:tostr ($row->"out-interface")]="tikray")))
        :if ((!$ok) or (($row->"chain")!="forward") or (($row->"action")!="drop") or ([:tostr ($row->"protocol")]!="udp")) do={:error "image: owner consumes normal open mark"}
    }
    :foreach id in=[/ip/firewall/nat/find where connection-mark~$standard] do={
        :local row [/ip/firewall/nat/get $id]; :local mark [:tostr ($row->"connection-mark")]; :local role ($row->"comment")
        :local ok ((($mark=$normal) and (($role="tikray:preserve-open") or ($role="tikray:preserve-backup-open"))) or (($mark="tikray-open-runner") and (($role="tikray:preserve-open-runner") or ($role="tikray:preserve-backup-open-runner"))))
        :if ((!$ok) or (($row->"chain")!="srcnat") or (($row->"action")!="accept") or ([:tostr ($row->"out-interface")]!="tikray")) do={:error "image: owner consumes normal open mark"}
    }
    :foreach id in=[/ip/firewall/mangle/find where connection-mark~$standard] do={
        :local row [/ip/firewall/mangle/get $id]; :local role ($row->"comment"); :local chain ($row->"chain"); :local op ($row->"action")
        :local mark [:tostr ($row->"connection-mark")]; :local owned false
        :if (($chain="tikray-pre") and ($op="mark-routing") and ([:tostr ($row->"new-routing-mark")]=$normal)) do={
            :set owned ((($role="tikray:route-open") and ($mark=$normal)) or (($role="tikray:route-udp-pending") and ($mark=$pending)) or (($role="tikray:route-udp-runner") and ($mark="tikray-open-runner")) or (($role="tikray:route-udp-wan") and ($mark="tikray-open-wan")))
        }
        :if (($chain="forward") and ($role="tikray:mss-open") and ($mark=$normal) and ($op="change-mss") and ([:tostr ($row->"new-mss")]="clamp-to-pmtu")) do={:set owned true}
        :if (($chain="forward") and ($op="mark-packet") and ([:tostr ($row->"new-packet-mark")]="tikray-proxied")) do={
            :set owned ((($role="tikray:packet-open") and ($mark=$normal)) or (($role="tikray:packet-udp-runner") and ($mark="tikray-open-runner")) or (($role="tikray:packet-udp-wan") and ($mark="tikray-open-wan")))
        }
        :if (($chain="forward") and ($op="mark-connection") and ($mark=$pending) and ([:tostr ($row->"protocol")]="udp")) do={
            :set owned ((($role="tikray:udp-birth-runner") and ([:tostr ($row->"out-interface")]="tikray") and ([:tostr ($row->"new-connection-mark")]="tikray-open-runner")) or (($role="tikray:udp-birth-wan") and ([:tostr ($row->"out-interface")]="!tikray") and ([:tostr ($row->"new-connection-mark")]="tikray-open-wan")))
        }
        :if (!$owned) do={:error "image: owner consumes normal open mark"}
    }
    :foreach path in={"runner";"wan"} do={
        :local birth ("tikray:udp-birth-" . $path); :local newMark ("tikray-open-" . $path)
        :foreach id in=[/ip/firewall/mangle/find where new-connection-mark=$newMark] do={
            :if ([:len [/ip/firewall/mangle/find where .id=$id and comment=$birth and chain=forward and action=mark-connection and connection-mark=$pending and !dynamic]]!=1) do={:error "image: shared UDP path mark writer"}
        }
    }
    # No owner may consume the operation-specific mark. The selector is
    # router-filtered and numeric nonce text is the only variable part.
    :local markPattern ("^!?" . $transit . "\$")
    :foreach id in=[/ip/firewall/mangle/find where connection-mark~$markPattern] do={:if ([:tostr $id]!=$pin) do={:error "image: shared transient connection mark"}}
    :if (([:len [/ip/firewall/nat/find where connection-mark~$markPattern]]>0) or ([:len [/ip/firewall/filter/find where connection-mark~$markPattern]]>0)) do={:error "image: shared transient connection mark"}
    :if ($action="check") do={:return true}
    :local from $normal
    :if ($action="release") do={:set from $transit}
    :local changed false
    :foreach key,tag in=$writers do={
        :local id [:toid $key]; :local current [:tostr [/ip/firewall/mangle/get $id new-connection-mark]]
        :local old ($expected->$key); :local new $transit
        :if ($action="release") do={:set old $transit; :set new ($expected->$key)}
        :if ($current!=$new) do={
            :local ok [$check $grant]
            :if (([:len [/ip/firewall/mangle/find where .id=$id and comment=$tag and new-connection-mark=$old]]!=1) or ([:len [/ip/firewall/mangle/find where comment=$tag]]!=1)) do={:error "image: open classifier identity changed"}
            :set changed true
            /ip/firewall/mangle/set $id new-connection-mark=$new
            :if ([:tostr [/ip/firewall/mangle/get $id new-connection-mark]]!=$new) do={:error "image: open classifier write unverified"}
        }
    }
    :if (($action="hold") and ([:len $writers]>0) and ($pin="")) do={
        :local ok [$check $grant]
        :if ([$keeper $tag $transit]!="") do={:error "image: transient mark reference appeared"}
        # Setting the same mark is a packet-path no-op. Keeping its
        # verified consumer active preserves the symbolic kernel identity.
        /ip/firewall/mangle/add chain=tikray-pre action=mark-connection disabled=no passthrough=yes connection-mark=$transit new-connection-mark=$transit comment=$tag
        :set pin [$keeper $tag $transit]; :if ($pin="") do={:error "image: no transient mark reference"}
    }
    :if ($changed) do={
        :delay 1s
        :foreach key,role in=$writers do={
            :local writer [:toid $key]
            :local new $transit; :if ($action="release") do={:set new ($expected->$key)}
            :if (([:tostr [/ip/firewall/mangle/get $writer new-connection-mark]]!=$new) or ([/ip/firewall/mangle/get $writer invalid]=true)) do={:error "image: classifier is not effective"}
        }
    }
    # @TIKRAY_FLOW_IDENTITY@
    :local query do={
        :local type $1; :local scope $2; :local mark $3; :local record $4
        :for n from=1 to=12 do={
            :local rows; :local ready false
            :do {
                :if ($type="marked") do={:set rows [/ip/firewall/connection/print detail as-value where src-address in $scope and (connection-mark=$mark or ($mark="tikray-open" and (connection-mark="tikray-open-udp" or connection-mark="tikray-open-runner" or connection-mark="tikray-open-wan")))]} else={
                    :if ($type="dns") do={:set rows [/ip/firewall/connection/print detail as-value where src-address in $scope and dstnat and dst-port=53 and reply-src-port=53 and (protocol=tcp or protocol=udp)]} else={
                        :local dst ($record->"dst"); :local proto ($record->"protocol")
                        :if (($proto="tcp") or ($proto="udp")) do={:local sp ($record->"sport"); :local dp ($record->"port"); :set rows [/ip/firewall/connection/print detail as-value where src-address=$scope and dst-address=$dst and protocol=$proto and src-port=$sp and dst-port=$dp]} else={
                            :set rows [/ip/firewall/connection/print detail as-value where src-address=$scope and dst-address=$dst and protocol=$proto]
                        }
                    }
                }
                :set ready true
            } on-error={}
            :if ($ready) do={:return $rows}; :delay 100ms
        }
        :error "image: open connection read unverified"
    }
    :local dnsOwned do={
        :local row $1; :local runner $2; :local hold $3; :local capture $4; :local owner $5
        :local mark [:tostr ($row->"connection-mark")]; :if (($mark!="") and ($mark!="no-mark") and ($mark!="tikray-open")) do={:return false}
        :local peer ($row->"reply-src-address"); :local router false
        :if ($hold) do={:if ($peer!=$runner) do={:return false}} else={
            :if (([:typeof $peer]!="ip") or ($peer=$runner)) do={:return false}
            :local match ("^" . [:tostr $peer] . "/")
            :foreach id in=[/ip/address/find where address~$match and !disabled] do={:local a [:tostr [/ip/address/get $id address]]; :if ([:pick $a 0 [:find $a "/"]]=[:tostr $peer]) do={:set router true}}
            :if (!$router) do={:return false}
        }
        :return (![$owner [$capture $row] $peer $router])
    }
    :local budget ($grant->"budget"); :if ([:typeof $budget]!="num") do={:set budget 15000000000}
    :local deadline ([:tonsec [/system/resource/get uptime]]+$budget)
    :local signature [:convert [:convert [:serialize to=json options=json.no-string-conversion value=$sourceRows] from=raw transform=sha512 to=hex] transform=lc]
    :local prior ($grant->"flow")
    :local cursor {"dir"=$action;"scope"=$signature;"next"=0;"done"=false}
    :if ($action="hold") do={
        :foreach role,row in=$policy do={
            :if ((($row->"menu")="/ip/firewall/nat") and (($row->"disabled")!=true)) do={:set changed true}
        }
    }
    :if ((!$changed) and (($prior->"scope")=$signature) and (($prior->"dir")=$action) and ([:typeof ($prior->"next")]="num") and (($prior->"next")>=0) and (($prior->"next")<=[:len $sourceRows])) do={:set cursor $prior}
    :local skip ($cursor->"next"); :local index 0; :local inspected 0; :local removals 0
    :foreach member,kind in=$sourceRows do={
        :if ($index>=$skip) do={
            :if (($inspected>=24) or ([:tonsec [/system/resource/get uptime]]>$deadline)) do={:return $cursor}
            :set inspected ($inspected+1)
            # The literal contains only a checked IPv4 prefix under its exact tagged role.
            :local parser [:parse (":return " . $member)]; :local prefix [$parser]
            :foreach type in={"marked";"dns"} do={
                :foreach row in=[$query $type $prefix $from] do={
                    :local captured [$capture $row]; :local owned false
                    :if ($type="marked") do={:local mark ($row->"connection-mark"); :set owned (($mark=$from) or (($from=$normal) and (($mark=$pending) or ($mark="tikray-open-runner") or ($mark="tikray-open-wan"))))} else={
                        :local primary ("tikray:dns-" . $kind . "-open-" . [:tostr ($row->"protocol")])
                        :if ((!$emergency) and (($action="hold") or ([:len [/ip/firewall/nat/find where comment=$primary and !disabled]]=1))) do={:set owned [$dnsOwned $row $runner ($action="hold") $capture $ownerDNS]}
                    }
                    :if ($owned) do={
                        :if (($removals>=8) or ([:tonsec [/system/resource/get uptime]]>$deadline)) do={:return $cursor}; :set removals ($removals+1)
                        :local ok [$check $grant]; :local matches 0; :local verified false
                        :foreach live in=[$query "exact" ($captured->"src") "" $captured] do={
                            :local same [$capture $live]
                            :if (($same->"origin")=($captured->"origin")) do={
                                :set matches ($matches+1)
                                :set verified ((($same->"flow")=($captured->"flow")) and (($same->"tuple")=($captured->"tuple")))
                            }
                        }
                        :if (($matches=1) and $verified) do={
                            :do {/ip/firewall/connection/remove [:toid ($captured->"flow")]} on-error={}
                            :local old true; :local tries 0
                            :while ($old and ($tries<40) and ([:tonsec [/system/resource/get uptime]]<=$deadline)) do={
                                :set old false; :set tries ($tries+1)
                                :foreach live in=[$query "exact" ($captured->"src") "" $captured] do={
                                    :local same [$capture $live]
                                    :if ((($same->"flow")=($captured->"flow")) and (($same->"tuple")=($captured->"tuple"))) do={:set old true}
                                }
                                :if ($old) do={:delay 100ms}
                            }
                            :if ($old) do={:return $cursor}
                        } else={:if ($matches>1) do={:error "image: ambiguous retained connection"}}
                    }
                }
            }
            # A new lifetime under a reused ID cannot be retired from an old
            # snapshot. Defer the route change until the old mark is genuinely gone.
            :if ([:len [$query "marked" $prefix $from]]!=0) do={:return $cursor}
            :set ($cursor->"next") ($index+1)
        }
        :set index ($index+1)
    }
    :if (($action="release") and ($pin!="")) do={
        :local ok [$check $grant]
        :if ([$keeper $tag $transit]!=$pin) do={:error "image: transient mark reference changed"}
        /ip/firewall/mangle/remove [:toid $pin]
        :if ([$keeper $tag $transit]!="") do={:error "image: transient mark retirement unverified"}
    }
    :set ($cursor->"done") true
    :return $cursor
}
