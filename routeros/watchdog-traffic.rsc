# Snapshot the installed aperture before changing it. A runner can answer
# ping before its xray or DNS is usable, so native check-gateway alone is
# insufficient during a replacement.
:local imageTraffic do={
    :if ($1="root") do={
        :local base $2; :local root $3; :local ownID $4
        # Removing a native row retires its extraction root. Include owner
        # mounts and ancestors of the target directory on either disk alias.
        :local disk [:pick $base 0 [:find $base "/"]]; :local volume [/disk/find where mount-point=$disk and fs="ext4"]
        :if ([:len $volume]!=1) do={:error "image: unknown container disk"}
        :local slot [:tostr [/disk/get [:pick $volume 0] slot]]; :local slash [:find $root "/"]; :local suffix [:pick $root $slash [:len $root]]
        :foreach dev in=({$disk;$slot}) do={
            :local rp ($dev . $suffix); :local expr ("^/?" . $rp . "(/|\$)")
            :foreach c in=[/container/find where root-dir~$expr] do={:if ($c!=$ownID) do={:error "image: owner shares extraction root"}}
            :if ([:len [/container/mounts/find where src~$expr]]>0) do={:error "image: owner mounts extraction root"}
            :local folder [:pick $base ([:find $base "/"]+1) [:len $base]]
            :foreach parent in=({$dev;($dev . "/" . $folder);($dev . "/" . $folder . "/containers")}) do={
                :if (([:len [/container/find where root-dir=$parent or root-dir=("/" . $parent) or root-dir=("/" . $parent . "/")]]>0) or ([:len [/container/mounts/find where src=$parent or src=("/" . $parent) or src=("/" . $parent . "/")]]>0)) do={:error "image: owner shares extraction directory"}
            }
        }
        :return true
    }
    :if ($1="archive") do={
        :local data $2; :local ref $3
        :local path ($data . "/images/" . ($ref->"component") . "-" . ($ref->"digest") . ".tar")
        :local ids [/file/find where name=$path]
        :if ([:len $ids]!=1) do={ :error "image: archive unavailable" }
        :local id [:pick $ids 0]; :local size ($ref->"size")
        :if (([/file/get $id size]!=$size) or ([/file/get $id type]="directory")) do={:error "image: archive length changed"}
        :local chain ""
        :for off from=0 to=($size-1) step=16384 do={
            :local n 16384; :if (($off+$n)>$size) do={:set n ($size-$off)}
            :local chunk ([/file/read file=$path offset=$off chunk-size=$n as-value]->"data")
            :if ([:len $chunk]!=$n) do={:error "image: incomplete archive"}
            :local h [:convert [:convert $chunk from=raw transform=sha512 to=hex] transform=lc]
            :set chain [:convert [:convert ($chain . $h) from=raw transform=sha512 to=hex] transform=lc]
        }
        :if (($chain!=($ref->"chain")) or ([/file/get $id size]!=$size) or ([:len [/file/find where .id=$id and name=$path]]!=1)) do={:error "image: archive content changed"}
        :return $path
    }
    # The Docker config digest identifies the extracted image; a display tag
    # or an incomplete extracting row cannot authorize a destructive action.
    :if ($1="row") do={
        :local p $2; :local n ($p->"name"); :local c ($p->"tag"); :local v ($p->"veth"); :local rootPath ($p->"root")
        :local rows [/container/find where name=$n or comment=$c or interface=$v or root-dir=$rootPath or root-dir=("/" . $rootPath)]
        :if ([:len $rows]=0) do={ :return [:toarray ""] }
        :if ([:len $rows]!=1) do={ :error "image: conflicting container identities" }
        :local id [:pick $rows 0]; :local row [/container/get $id]
        :local path [:tostr ($row->"root-dir")]; :if ([:pick $path 0 1]="/") do={:set path [:pick $path 1 [:len $path]]}
        :local trace ($p->"staging"); :local claim [:tostr ($row->"comment")]; :local partial false; :local archive
        :if ($claim=($trace->"candidate")) do={:set partial true; :set archive ($p->"new")}
        :if ($claim=($trace->"original")) do={:set partial true; :set archive ($p->"old")}
        :local code [:tostr ($row->"image-id")]
        :if ([:pick $code ([:len $code]-1) [:len $code]]=" ") do={:set code [:pick $code 0 ([:len $code]-1)]}
        :if ([:pick $code 0 7]="sha256:") do={:set code [:pick $code 7 [:len $code]]}
        :local expectedID $code
        :if ($partial) do={
            :set expectedID ($archive->"image_id")
            :local input [:tostr ($row->"file")]; :if ([:pick $input 0 1]="/") do={:set input [:pick $input 1 [:len $input]]}
            :if (($input!="") and ($input!=(($p->"data") . "/images/" . ($p->"component") . "-" . ($archive->"digest") . ".tar"))) do={:error "image: provisional archive changed"}
        }
        :local alternative (($rootPath . "-image-" . $expectedID)=$path)
        :if ($alternative and (($expectedID!=($p->"old"->"image_id")) and ($expectedID!=($p->"new"->"image_id")))) do={:error "image: foreign recovery root"}
        :if ((($row->"name")!=$n) or ((!$partial) and ($claim!=$c)) or ([:tostr ($row->"interface")]!=$v) or (($path!=$rootPath) and (!$alternative)) or ([:tostr ($row->"mountlists")]!=$n) or ([:tostr ($row->"envlists")]!=$n) or ([:tostr ($row->"dns")]!=[:tostr ($p->"gateway")]) or ([:len ($row->"entrypoint")]>0) or (($row->"logging")=true) or ([:len ($row->"devices")]>0) or (($row->"privileged")=true)) do={ :error "image: unverified container configuration" }
        :if (([:len ($row->"cmd")]>0) and ((($p->"component")!="tikray") or ([:tostr ($row->"cmd")]!="serve"))) do={ :error "image: owner command differs" }
        :if ((($row->"memory-high")!=($p->"high")) or (($row->"memory-max")!=($p->"max")) or ([:tostr ($row->"restart-policy")]!="on-failure") or ((!$partial) and (($row->"start-on-boot")!=true))) do={ :error "image: owner lifecycle settings differ" }
        # These are explicit native overrides. The Docker config's intrinsic
        # defaults have separate default-* fields and follow the verified bytes.
        :foreach key in={"hostname";"domain-name";"user";"workdir";"cpu-list";"env";"mount";"hosts";"tmpfs";"remote-image";"layer-dir";"healthcheck-cmd";"healthcheck-interval";"healthcheck-retries";"healthcheck-start-interval";"healthcheck-start-period";"healthcheck-timeout";"stop-signal";"shell"} do={
            :if ([:len [:tostr ($row->$key)]]>0) do={:error "image: owner execution settings differ"}
        }
        :if ((($row->"shm-size")!=67108864) or (($row->"restart-max-count")!=0) or ([:tonsec ($row->"restart-interval")]!=0) or ([:tonsec ($row->"stop-time")]!=10000000000) or (($row->"stop-on-unhealthy")=true) or (($row->"ignore-remote-image-change")=true) or (($row->"check-certificate")!=true)) do={:error "image: owner execution settings differ"}
        :return {"id"=$id;"image_id"=$code;"tag"=$claim;"partial"=$partial;"root"=$path}
    }
    :local operation $1; :local prior $2; :local peer $3; :local lan $4
    :local checkOwner $5; :local grant $6; :local emergency $7
    # @TIKRAY_IMAGE_FLOWS@
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
    :if ([:len $live]>0) do={:local checked [$openFlows "check" $live $peer $grant $checkOwner $operation $emergency]}
    :if ($operation="read") do={
        :local saved [:toarray ""]
        :foreach key,row in=$live do={ :set ($saved->$key) ($row->"disabled") }
        :return $saved
    }
    :if ([:len $prior]!=[:len $live]) do={:error "image: native policy changed during trial"}
    :foreach key,row in=$live do={:if ([:typeof ($prior->$key)]!="bool") do={:error "image: unknown native policy row"}}
    :local release ($operation="release"); :local order {"watch";"dns";"handoff";"open";"routes";"acl"}
    :if ($release) do={:set order {"acl";"dns";"routes";"open";"watch";"handoff"}}
    :local result {"dir"=$operation;"done"=true}
    :foreach group in=$order do={
        :if (($group="handoff") and ([:len $live]>0)) do={:set result [$openFlows $operation $live $peer $grant $checkOwner $operation $emergency]; :if (($result->"done")!=true) do={:return $result}}
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
    :return $result
}
