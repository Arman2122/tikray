# Build the self-contained owner import with tikray-installer -uninstall-out.
# Default keeps user data. A noninteractive owner selects purge explicitly.
{
:local uninstall do={
    :global tikrayUninstallData
    :local requested [:tostr $tikrayUninstallData]
    :set tikrayUninstallData
    :if (($requested != "") and ($requested != "keep") and ($requested != "purge")) do={ :error "tikray: select keep or purge for uninstall data" }
    :local packaged false
    # @TIKRAY_SEALED@
    :if (!$packaged) do={ :error "tikray: use the packaged uninstall.rsc" }
    # @TIKRAY_BINDING_REMOVAL@
    # @TIKRAY_DETACH@
    :local normalize do={
        :local p [:tostr $1]
        :if ([:pick $p 0 1] = "/") do={ :set p [:pick $p 1 [:len $p]] }
        :if (([:len $p] > 0) and ([:pick $p ([:len $p]-1) [:len $p]] = "/")) do={ :set p [:pick $p 0 ([:len $p]-1)] }
        :return $p
    }
    :local role do={
        :local menu $1; :local tagValue $2
        :if ([:pick $tagValue 0 7] != "tikray:") do={ :return false }
        :local roleName [:pick $tagValue 7 [:len $tagValue]]
        :if ($menu = "/system/script") do={
            :return (($roleName ~ "^(watchdog-script|emergency-off|emergency-state|api-mode (unchanged|created|access))\$") or ([:pick $roleName 0 15] = "watchdog-state ") or ([:pick $roleName 0 12] = "api-receipt ") or ([:pick $roleName 0 11] = "api-access "))
        }
        :if ($menu = "/system/scheduler") do={ :return ($roleName = "watchdog-scheduler") }
        :if ($menu = "/container") do={ :return (($roleName = "runner") or ($roleName = "tikray")) }
        :if ($menu = "/container/mounts") do={ :return ($roleName ~ "^mount-(tikray-data|runner-(run|geo|cores))\$") }
        :if ($menu = "/container/envs") do={ :return ($roleName ~ "^env-(runner|ctl)-data\$") }
        :if ($menu = "/interface/bridge") do={ :return ($roleName = "bridge") }
        :if ($menu = "/interface/veth") do={ :return ($roleName ~ "^veth-(ctl|runner)\$") }
        :if ($menu = "/interface/bridge/port") do={ :return ($roleName ~ "^port-(ctl|runner)\$") }
        :if ($menu = "/interface/bridge/host") do={ :return ($roleName ~ "^fdb-(ctl|runner)\$") }
        :if ($menu = "/ip/arp") do={ :return ($roleName ~ "^arp-(ctl|runner)\$") }
        :if ($menu = "/ip/address") do={ :return ($roleName = "addr") }
        :if ($menu = "/user") do={ :return ($roleName = "user") }
        :if ($menu = "/user/group") do={ :return ($roleName = "group") }
        :if ($menu = "/routing/table") do={ :return ($roleName ~ "^table-(open|closed)\$") }
        :if ($menu = "/ip/route") do={ :return ($roleName ~ "^route-(open|closed)-(runner|fallback)\$") }
        :if ($menu = "/tool/netwatch") do={ :return ($roleName = "runner-watch") }
        :if ($menu = "/ip/firewall/raw") do={ :return ($roleName = "acl-runner-direct") }
        :if (($menu = "/ip/firewall/address-list") or ($menu = "/ip/firewall/filter") or ($menu = "/ipv6/firewall/filter")) do={
            :if (($roleName ~ "^hold:[a-f0-9]+\$") and ([:len $roleName] = 37)) do={ :return true }
        }
        :if ($menu = "/ip/firewall/address-list") do={ :return ($roleName ~ "^(local|domestic|src-(smart|full)-(open|closed)):[0-9.]+/[0-9]+\$") }
        :if ($menu = "/ip/firewall/mangle") do={
            :if (($roleName ~ "^skip-owner-route:[a-f0-9]+\$") and ([:len $roleName] = 49)) do={ :return true }
            :return ($roleName ~ "^(jump-pre|skip-(router|local|dns-(tcp|udp))|(mss|packet|route)-(open|closed)|conn-(full|smart)-(open|closed))\$")
        }
        :if ($menu = "/ip/firewall/filter") do={ :return ($roleName ~ "^(egress-(guard|skip-local|drop-(marked|smart|full)|dns-(full|smart)-(open|closed)-(tcp|udp))|no-fasttrack|acl-(control-runner|runner-reply|established|lan-https|dns-(tcp|udp)|deny|input-(dns-(tcp|udp)|reply|api|deny|hook)|hook|wan-api))\$") }
        :if ($menu = "/ipv6/firewall/filter") do={ :return (($roleName ~ "^(acl-v6-bridge|acl-wan-api6|ipv6:(jump|host:[0-9.]+))\$") or (($roleName ~ "^ipv6:ingress:[0-9a-f]+\$") and ([:len $roleName] = 45))) }
        :if ($menu = "/ip/firewall/nat") do={ :return ($roleName ~ "^(nat-containers|preserve-(backup-)?(open|closed|dns-(smart|full)-(open|closed)-(tcp|udp))|dns-((smart|full)-(open|closed)|router-(smart|full)-open)-(tcp|udp))\$") }
        :return false
    }
    :local menus {"/system/scheduler";"/system/script";"/container";"/container/mounts";"/container/envs";"/tool/netwatch";"/ip/firewall/mangle";"/ip/firewall/nat";"/ip/firewall/filter";"/ip/firewall/raw";"/ipv6/firewall/filter";"/ip/firewall/address-list";"/ip/route";"/routing/table";"/ip/arp";"/interface/bridge/host";"/interface/bridge/port";"/ip/address";"/interface/veth";"/interface/bridge";"/user";"/user/group"}
    :local scan do={
        :local objects [:toarray ""]
        :foreach menu in=$1 do={
            :local each [:parse (":return [" . $menu . "/find where comment~\"^tikray:\"]")]
            :local label [:parse (":return [" . $menu . "/get \$1 comment]")]
            :local owned [:toarray ""]
            :foreach id in=[$each] do={
                :local c [$label $id]
                :if ([$2 $menu $c]) do={
                    :if (([:typeof ($owned->$c)] != "nothing") and ([:typeof ($owned->$c)] != "nil")) do={ :error "tikray: shared_reference_refuses; duplicate ownership tag" }
                    :if (($menu~"^/ip/firewall/") or ($menu="/ipv6/firewall/filter") or ($menu="/ip/route") or ($menu="/routing/table") or ($menu="/ip/address")) do={
                        :local readRow [:parse (":return [" . $menu . "/get \$1]")]
                        :local row [$readRow $id]
                        :if (($row->"dynamic")=true) do={ :error "tikray: shared_reference_refuses; dynamic row carries an ownership tag" }
                        :local name [:pick $c 7 [:len $c]]
                        :if ($menu="/ip/firewall/address-list") do={
                            :if ([:pick $name 0 5]="hold:") do={
                                :if ((!((($row->"list")~"^tikray-h[0-9a-f]+\$"))) or ([:len ($row->"list")]!=40)) do={ :error "tikray: shared_reference_refuses; temporary address list changed identity" }
                            } else={
                                :local sep [:find $name ":"]
                                :local member [:tostr ($row->"address")]; :if ([:typeof [:find $member "/"]]!="num") do={ :set member ($member . "/32") }
                                :if ((($row->"list")!=("tikray-" . [:pick $name 0 $sep])) or ($member!=[:pick $name ($sep+1) [:len $name]])) do={ :error "tikray: shared_reference_refuses; address-list member changed identity" }
                            }
                        }
                        :if ($menu="/ip/route") do={
                            :local tab "tikray-open"; :if ([:pick $name 0 13]="route-closed-") do={ :set tab "tikray-closed" }
                            :if (([:tostr ($row->"routing-table")]!=$tab) or ([:tostr ($row->"dst-address")]!="0.0.0.0/0")) do={ :error "tikray: shared_reference_refuses; tagged route changed identity" }
                        }
                    }
                    :set ($owned->$c) $id
                }
            }
            :if ([:len $owned] > 0) do={ :set ($objects->$menu) $owned }
        }
        :return $objects
    }
    :local inventory [$scan $menus $role]
    :local marker [/system/script/find where name="tikray-uninstall-state" or comment~"^tikray:uninstall-state "]
    :if (([:len $inventory] = 0) and ([:len $marker] = 0)) do={ :put "tikray: already uninstalled"; :return true }
    :if (($requested = "") and ([:len $marker] = 0)) do={
        :put "Keep tikray data? [Enter: keep] Press uppercase D within five seconds to purge the installation's data."
        :do {
            :local readKey [:parse ":return [/terminal/inkey timeout=5s]"]
            :local answer [$readKey]
            :if (([:tostr $answer] = "68") or ([:tostr $answer] = "D")) do={ :set requested "purge" }
        } on-error={ :set requested "keep" }
    }
    :local base ""; :local data ""; :local diskMount ""; :local diskSlot ""; :local identity ""; :local oldPin ""; :local subnet ""; :local phase "preflight"
    :local choice $requested; :if ($choice = "") do={ :set choice "keep" }
    :local markerTag "tikray:uninstall-state "
    :local meta [:toarray ""]
    :if ([:len $marker] > 0) do={
        :if (([:len $marker] != 1) or ([/system/script/get $marker name] != "tikray-uninstall-state") or ([:len [/system/script/get $marker source]] != 0) or [/system/script/get $marker dont-require-permissions]) do={ :error "tikray: shared_reference_refuses; invalid uninstall marker" }
        :foreach right in=[/system/script/get $marker policy] do={ :if (([:pick $right 0 1]!="!") and ($right!="read")) do={ :error "tikray: shared_reference_refuses; changed uninstall marker permissions" } }
        :local label [/system/script/get $marker comment]
        :if ([:pick $label 0 [:len $markerTag]] != $markerTag) do={ :error "tikray: shared_reference_refuses; invalid uninstall marker" }
        :set meta [:deserialize from=json options=json.no-string-conversion value=[:pick $label [:len $markerTag] [:len $label]]]
        :if ((($meta->"version") != 1) or ([:typeof ($meta->"service")]!="array") or ([:typeof [:find {"detach";"remove";"retire";"files";"empty"} ($meta->"phase")]] != "num") or ([:typeof [:find {"keep";"purge"} ($meta->"choice")]] != "num")) do={ :error "tikray: shared_reference_refuses; invalid uninstall journal" }
        :set choice ($meta->"choice"); :set phase ($meta->"phase"); :set data ($meta->"data"); :set identity ($meta->"installation_id"); :set oldPin ($meta->"api_pin"); :set subnet ($meta->"subnet")
        :if (($requested != "") and ($requested != $choice)) do={ :error "tikray: resume the original uninstall data choice" }
        :if ((($phase="files") or ($phase="empty")) and ([:len $inventory] != 0)) do={ :error "tikray: shared_reference_refuses; router objects reappeared after detachment" }
    }
    :local locks [/system/script/find where name="tikray-install-lock" or comment~"^tikray:install-lock "]
    :if ([:len $locks] > 0) do={
        :if (([:len $locks] != 1) or ([/system/script/get $locks name] != "tikray-install-lock") or ([:len [/system/script/get $locks source]] != 0) or [/system/script/get $locks dont-require-permissions]) do={ :error "tikray: shared_reference_refuses; invalid installer claim" }
        :local lockTag [/system/script/get $locks comment]
        :if ([:pick $lockTag 0 [:len "tikray:install-lock "]] != "tikray:install-lock ") do={ :error "tikray: shared_reference_refuses; invalid installer claim" }
        :local claim [:deserialize from=json options=json.no-string-conversion value=[:pick $lockTag [:len "tikray:install-lock "] [:len $lockTag]]]
        :local jobId [:toid ($claim->"job")]
        :if (([:typeof $jobId] != "id") or (($claim->"version") != 1) or ([:len ($claim->"started")] = 0) or ([:len ($claim->"nonce")] != 32)) do={ :error "tikray: shared_reference_refuses; invalid installer keeper" }
        :local liveJob [/system/script/job/find where .id=$jobId]
        :if ([:len $liveJob] = 1) do={ :if ([:tostr [/system/script/job/get $liveJob started]] = ($claim->"started")) do={ :error "tikray: shared_reference_refuses; installer claim is active" } }
    }
    :local mt [/container/mounts/find where comment="tikray:mount-tikray-data"]
    :if ([:len $mt] > 0) do={
        :if (([:len $mt] != 1) or ([:len [/container/mounts/find where comment="tikray:mount-tikray-data" and list="tikray" and dst="/data" and mode="rw"]] != 1)) do={ :error "tikray: shared_reference_refuses; control mount" }
        :local actual [$normalize [/container/mounts/get $mt src]]
        :if (($data != "") and ($data != $actual)) do={ :error "tikray: shared_reference_refuses; data mount changed" }
        :set data $actual
    }
    :if ($data != "") do={
        :if (!($data ~ "^[A-Za-z0-9][A-Za-z0-9_-]*/tikray(-[A-Za-z0-9_][A-Za-z0-9_-]*)?/data\$")) do={ :error "tikray: shared_reference_refuses; unsafe data root" }
        :set base [:pick $data 0 ([:len $data]-5)]; :set diskMount [:pick $base 0 [:find $base "/"]]
        :local volume [/disk/find where mount-point=$diskMount and fs="ext4"]
        :if ([:len $volume] != 1) do={ :error "tikray: shared_reference_refuses; data volume unavailable" }
        :set diskSlot [:tostr [/disk/get $volume slot]]
        :local proofFile [/file/find where name=($data . "/state/install.id")]
        :local request [/file/find where name=($data . "/install.json")]
        :if ([:len $proofFile] = 1) do={
            :local liveId [/file/get $proofFile contents]
            :if (([:len $liveId] != 32) or (!($liveId ~ "^[0-9a-f]+\$")) or (($identity != "") and ($identity != $liveId))) do={ :error "tikray: shared_reference_refuses; data identity differs" }
            :set identity $liveId
        } else={
            :if (($phase != "files") and ($phase != "empty")) do={ :error "tikray: shared_reference_refuses; data identity unavailable" }
        }
        :local state [/system/script/find where name="tikray-watchdog-state" and source="" and comment~"^tikray:watchdog-state "]
        :if ([:len $marker] = 0) do={
            :if (([:len $state] != 1) or ([:len $request] != 1)) do={ :error "tikray: shared_reference_refuses; installation proof unavailable" }
            :local c [/system/script/get $state comment]
            :local s [:deserialize from=json options=json.no-string-conversion value=[:pick $c [:len "tikray:watchdog-state "] [:len $c]]]
            :if (($s->"installation_id") != $identity) do={ :error "tikray: shared_reference_refuses; wrong installation volume" }
            :local r [:deserialize from=json options=json.no-string-conversion value=[/file/get $request contents]]
            :set oldPin ($r->"fingerprint"); :set subnet ($r->"scope"->"subnet")
        }
    } else={
        :if (($choice="purge") or ([:len ($inventory->"/container")] > 0)) do={ :error "tikray: shared_reference_refuses; data root cannot be verified" }
    }
    :local nextPhase do={
        :local current $1; :local id $2; :local target $3
        :if (([/system/script/get $id name] != "tikray-uninstall-state") or ([:len [/system/script/get $id source]] != 0) or ([/system/script/get $id comment] != ("tikray:uninstall-state " . [:serialize to=json options=json.no-string-conversion value=$current]))) do={ :error "tikray: uninstall journal changed; inspect before retry" }
        :set ($current->"phase") $target
        /system/script/set $id comment=("tikray:uninstall-state " . [:serialize to=json options=json.no-string-conversion value=$current])
        :return $current
    }
    # @TIKRAY_RESTORE_SERVICE@
    # @TIKRAY_REFERENCES@
    # @TIKRAY_CLEANUP_DATA@
    :local checked [$references $inventory $checkTable $data $diskMount $diskSlot $normalize $subnet]
    :local peerCheck [$removeBindings "inspect"]
    :local serviceCheck [$restoreService "inspect" $phase $oldPin "" "" ($meta->"service")]
    :local fileCheck [$cleanData "inspect" $choice $data $identity $phase $subnet]
    :local policyPresent false
    :foreach menu in={"/ip/firewall/mangle";"/ip/firewall/address-list";"/routing/table";"/ip/route";"/tool/netwatch"} do={ :if ([:len ($inventory->$menu)] > 0) do={ :set policyPresent true } }
    :if ($policyPresent and (($phase = "preflight") or ($phase = "detach"))) do={ :local v [$detach "inspect"] }
    # PREFLIGHT COMPLETE
    # Use the same cross-user lease as installation. A killed import can be
    # resumed when the verified old keeper expires or after a router reboot.
    # @TIKRAY_INSTALL_LOCK@
    :local lease [$acquireInstall]
    :onerror failure in={
    $requireInstall $lease
    :if ([:len $marker] = 0) do={
        :set meta {"version"=1;"phase"="detach";"choice"=$choice;"data"=$data;"installation_id"=$identity;"api_pin"=$oldPin;"subnet"=$subnet;"service"=$serviceCheck}
        /system/script/add name=tikray-uninstall-state policy=read dont-require-permissions=no source="" comment=($markerTag . [:serialize to=json options=json.no-string-conversion value=$meta])
        :set marker [/system/script/find where name="tikray-uninstall-state" and comment=($markerTag . [:serialize to=json options=json.no-string-conversion value=$meta])]
        :if ([:len $marker] != 1) do={ :error "tikray: uninstall marker changed" }
        :set phase "detach"
    }
    :set marker [:pick $marker 0]
        :local again [$references $inventory $checkTable $data $diskMount $diskSlot $normalize $subnet]
        :local restored [$restoreService "restore" $phase $oldPin $requireInstall $lease ($meta->"service")]
        :local sched [/system/scheduler/find where name="tikray-watchdog" and comment="tikray:watchdog-scheduler"]
        :if ([:len $sched] = 1) do={ /system/scheduler/disable $sched }
        :local q 0
        :while (([:len [/system/script/job/find where script="tikray-watchdog" or script="tikray-emergency-off"]] > 0) and ($q < 80)) do={ :delay 250ms; :set q ($q+1) }
        :if ($q = 80) do={ :error "tikray: watchdog or emergency operation active; retry" }
        :foreach component in={"tikray";"tikray-runner"} do={
            :local roleName "tikray:tikray"; :if ($component="tikray-runner") do={ :set roleName "tikray:runner" }
            :local id [/container/find where name=$component and comment=$roleName]
            :if ([:len $id] > 0) do={
                $requireInstall $lease
                :if ([:len $id] != 1) do={ :error "tikray: shared_reference_refuses; container identity changed" }
                /container/set $id start-on-boot=no
                :if ([:len [/container/find where name=$component and comment=$roleName and !stopped]] > 0) do={ /container/stop $id }
                :local waits 0
                :while (([:len [/container/find where name=$component and comment=$roleName and stopped and !start-on-boot]] != 1) and ($waits < 240)) do={ :delay 250ms; :set waits ($waits+1) }
                :if ($waits = 240) do={ :error "tikray: container did not stop; retry uninstall" }
            }
        }
        :if ($phase = "detach") do={
            :if ($policyPresent) do={ :local off [$detach "mutate"] }
            :set meta [$nextPhase $meta $marker "remove"]; :set phase "remove"
        }
        :local drop do={
            :local menu $1; :local all ($2->$menu); :local selected $3
            :local checkLease $4; :local claim $5
            :local lookup [:parse (":return [" . $menu . "/find where comment=\$1]")]
            :local remove [:parse ($menu . "/remove \$1")]
            :foreach c,id in=$all do={
                :local modeRecord ([:pick $c 0 [:len "tikray:api-mode "]]="tikray:api-mode ")
                :local receipt (([:pick $c 0 [:len "tikray:api-receipt "]]="tikray:api-receipt ") or ([:pick $c 0 [:len "tikray:api-access "]]="tikray:api-access "))
                :if (($selected = "all") or ($c = $selected) or (($selected="ordinary") and (!$modeRecord) and (!$receipt)) or (($selected="receipt") and $receipt) or (($selected="mode") and $modeRecord)) do={
                    $checkLease $claim
                    :local fresh [$lookup $c]
                    :if (([:len $fresh] != 1) or ([:pick $fresh 0] != $id)) do={ :error "tikray: uninstall identity changed; retry" }
                    # Tables and groups can acquire dependencies between
                    # preflight and the last operation. Both are empty now.
                    :if ($menu="/routing/table") do={
                        :local tableRefs $6; :local tab [/routing/table/get $id name]
                        :if ($tab != ("tikray-" . [:pick $c [:len "tikray:table-"] [:len $c]])) do={ :error "tikray: uninstall identity changed; retry" }
                        :local verified [$tableRefs $tab [:toarray ""]]
                    }
                    :if (($menu="/user/group") and ([:len [/user/find where group="tikray"]] != 0)) do={ :error "tikray: shared_reference_refuses; group acquired another user" }
                    :if (($menu="/interface/bridge") and ([:len [/interface/bridge/port/find where bridge="tikray"]] != 0)) do={ :error "tikray: shared_reference_refuses; bridge acquired another port" }
                    $remove $id
                }
            }
            :return true
        }
        :if ($phase = "remove") do={
            :set inventory [$scan $menus $role]
            :local rechecked [$references $inventory $checkTable $data $diskMount $diskSlot $normalize $subnet]
            # Remove the control and runner before exposing any bridge port.
            $drop "/container" $inventory "all" $requireInstall $lease
            $drop "/system/scheduler" $inventory "all" $requireInstall $lease
            $drop "/tool/netwatch" $inventory "all" $requireInstall $lease
            $drop "/ip/firewall/mangle" $inventory "all" $requireInstall $lease
            $drop "/ip/firewall/nat" $inventory "all" $requireInstall $lease
            $drop "/ip/firewall/filter" $inventory "all" $requireInstall $lease
            $drop "/ipv6/firewall/filter" $inventory "all" $requireInstall $lease
            $drop "/ip/firewall/raw" $inventory "all" $requireInstall $lease
            $drop "/ip/firewall/address-list" $inventory "all" $requireInstall $lease
            $drop "/ip/route" $inventory "all" $requireInstall $lease
            $drop "/routing/table" $inventory "all" $requireInstall $lease $checkTable
            $drop "/container/mounts" $inventory "all" $requireInstall $lease
            $drop "/container/envs" $inventory "all" $requireInstall $lease
            :local removed [$removeBindings "remove" $lease]
            $drop "/interface/bridge/port" $inventory "all" $requireInstall $lease
            $drop "/ip/address" $inventory "all" $requireInstall $lease
            $drop "/interface/veth" $inventory "all" $requireInstall $lease
            $drop "/interface/bridge" $inventory "all" $requireInstall $lease
            $drop "/user" $inventory "all" $requireInstall $lease
            $drop "/user/group" $inventory "all" $requireInstall $lease
            $drop "/system/script" $inventory "ordinary" $requireInstall $lease
            :set meta [$nextPhase $meta $marker "retire"]; :set phase "retire"
        }
        :if ($phase = "retire") do={
            :set inventory [$scan $menus $role]
            :foreach menu,items in=$inventory do={
                :if ($menu!="/system/script") do={ :error "tikray: shared_reference_refuses; resources reappeared before receipt retirement" }
                :foreach c,id in=$items do={ :if (!($c ~ "^tikray:api-(receipt|access|mode) ")) do={ :error "tikray: shared_reference_refuses; unexpected script during receipt retirement" } }
            }
            :local safe [$restoreService "restore" $phase $oldPin $requireInstall $lease ($meta->"service")]
            $drop "/system/script" $inventory "receipt" $requireInstall $lease
            $drop "/system/script" $inventory "mode" $requireInstall $lease
            :set meta [$nextPhase $meta $marker "files"]; :set phase "files"
        }
        :if (($data != "") and ($phase = "files")) do={
            :local cleaned [$cleanData "apply" $choice $data $identity $phase $subnet $requireInstall $lease]
            :set meta [$nextPhase $meta $marker "empty"]; :set phase "empty"
        }
        :if (($data != "") and ($phase = "empty") and ($choice = "purge")) do={ :local empty [$cleanData "empty" $choice $data $identity $phase $subnet $requireInstall $lease] }
        :local leftovers [$scan $menus $role]
        :if ([:len $leftovers] > 0) do={ :error "tikray: tagged resources remain; retry uninstall" }
        $requireInstall $lease
        :if ([/system/script/get $marker comment] != ($markerTag . [:serialize to=json options=json.no-string-conversion value=$meta])) do={ :error "tikray: uninstall journal changed" }
        /system/script/remove $marker
    } do={
        $releaseInstall $lease
        :if (([:pick $failure 0 7] = "tikray:") and ([:len $failure] < 180)) do={ :error $failure }
        :error "tikray: uninstall stopped; inspect ownership and retry"
    }
    $releaseInstall $lease
    :if (($choice="keep") and ($data!="")) do={ :put ("tikray: kept " . $data . "; to reuse it set tikrayReuseID=" . $identity . " before install") } else={ :put "tikray: uninstall complete" }
    :return true
}
:local finished [$uninstall]
}
