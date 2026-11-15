# RouterOS runs this independently once a minute.
{
    :local runTick do={
        :if ([:len [/system/script/job/find where script="tikray-watchdog"]] != 1) do={ :return true }
        :local suspended do={
            :if (([:len [/system/script/find where name="tikray-uninstall-state" or comment="tikray:uninstall-state"]] > 0) or ([:len [/system/script/job/find where script="tikray-emergency-off" or script="tikray-uninstall"]] > 0)) do={ :return true }
            # Restore the private return path while traffic is suspended so
            # the owner can start control and let it reconcile normally.
            :if ($1 != "bindings") do={
                :if ([:len [/system/script/find where name="tikray-emergency-state" or comment="tikray:emergency-state"]] > 0) do={ :return true }
            }
            :local lock [/system/script/find where name="tikray-install-lock" or comment~"^tikray:install-lock "]
            :if ([:len $lock] = 0) do={ :return false }
            :if ([:len $lock] != 1) do={ :return true }
            :local tag [/system/script/get $lock comment]
            :local prefix "tikray:install-lock "
            :if ([:pick $tag 0 [:len $prefix]] != $prefix) do={ :return true }
            :local active true
            :do {
                :local lease [:deserialize from=json options=json.no-string-conversion value=[:pick $tag [:len $prefix] [:len $tag]]]
                :local id [:toid ($lease->"job")]
                :if ((([:typeof $id] = "id") and (($lease->"version") = 1)) and ([:len ($lease->"started")] > 0)) do={
                    :local keeper [/system/script/job/find where .id=$id]
                    :set active false
                    :if ([:len $keeper] = 1) do={ :set active ([:tostr [/system/script/job/get $keeper started]] = ($lease->"started")) }
                }
            } on-error={ :set active true }
            :return $active
        }
        :if ([$suspended "bindings"]) do={ :return true }
        :local mounts [/container/mounts/find where comment="tikray:mount-tikray-data" and list="tikray" and dst="/data"]
        :if ([:len $mounts] != 1) do={ :return true }
        :local data [/container/mounts/get $mounts src]
        :if ([:pick $data 0 1] = "/") do={ :set data [:pick $data 1 [:len $data]] }
        # A recreated control veth can strand the very API session that
        # normally repairs these rows. Restore the verified path locally.
        :local intent [/file/find where name=($data . "/state/install.request")]
        :if (([:len $intent] != 1) or ([/file/get $intent size] > 60000)) do={ :return true }
        # @TIKRAY_WATCHDOG_BINDINGS@
        :local bindingsOK false
        :local mayBind do={ :local stopCheck $1; :if ([$stopCheck "bindings"]) do={ :error "tikray: binding repair suspended" }; :return true }
        :do {
            :local request [:deserialize from=json options=json.no-string-conversion value=[/file/get $intent contents]]
            :set bindingsOK [$bindPeers "repair" ($request->"scope"->"subnet") $mayBind $suspended]
        } on-error={ :set bindingsOK false }
        :if ($bindingsOK != true) do={ :return true }
        :local emergency ""
        :if ([$suspended "restart"]) do={
            # Emergency can finish/prepare an already requested rollback;
            # it cannot authorize a restart, new update, or traffic re-arm.
            :if ([$suspended "bindings"]) do={:return true}
            :local marker [/system/script/find where name="tikray-emergency-state" and comment="tikray:emergency-state" and source=""]
            :if (([:len $marker]!=1) or ([:len [/file/find where name=($data . "/state/image-update.request")]]=0)) do={:return true}
            :set emergency [:tostr [:pick $marker 0]]
        }
        :local ready [/file/find where name=($data . "/state/install.ready")]
        :if ([:len $ready] != 1) do={ :return true }
        :local readyStamp [/file/get $ready contents]
        :if (([:len $readyStamp] != 64) or (!($readyStamp ~ "^[0-9a-f]+\$"))) do={ :return true }
        :local bridgeAddr [/ip/address/find where interface="tikray" and comment="tikray:addr" and !disabled]
        :if ([:len $bridgeAddr] != 1) do={ :return true }
        :local cidr [:tostr [/ip/address/get $bridgeAddr address]]
        :local gateway [:toip [:pick $cidr 0 [:find $cidr "/"]]]
        :local ctlIP ($gateway + 1)
        :local runnerIP ($gateway + 2)
        # @TIKRAY_WATCHDOG_STEP@
        # @TIKRAY_WATCHDOG_STATE@
        :local savedState [$wdState "read"]
        :local controlOK do={
            :local ctlIP $1; :local gateway $2; :local savedState $3; :local healthy false
            # @TIKRAY_WATCHDOG_HEALTH@
            :return $healthy
        }
        # @TIKRAY_WATCHDOG_IMAGE@
        :local updating "all"
        :do { :set updating [$wdImage $data ($savedState->"installation_id") $gateway $controlOK $suspended $emergency] } on-error={
            # Even when a target archive is missing or its row was retagged,
            # a verified independent sibling can still need a basic restart.
            :do {
                :local reqs [/file/find where name=($data . "/state/image-update.request")]
                :if (([:len $reqs]=1) and ([/file/get $reqs size]<=4096)) do={
                    :local req [:deserialize from=json options=json.no-string-conversion value=[/file/get $reqs contents]]
                    :if (($req->"installation_id")=($savedState->"installation_id")) do={
                        :if (($req->"component")="tikray") do={:set updating "tikray"}
                        :if (($req->"component")="runner") do={:set updating "tikray-runner"}
                    }
                }
            } on-error={}
            :log warning "tikray: image operation needs verification"
        }
        :if ($emergency!="") do={:return true}
        :foreach component in={"tikray-runner";"tikray"} do={
            :if (($component!=$updating) and ($updating!="all")) do={
            :local ownedTag "tikray:tikray"
            :local vethName "tikray-ctl"
            :if ($component = "tikray-runner") do={ :set ownedTag "tikray:runner"; :set vethName "tikray-runner" }
            :local verified do={
                :local ids [/container/find where name=$1 or comment=$2 or interface=$3]
                :local owned [/container/find where name=$1 and comment=$2 and interface=$3]
                :return (([:len $ids] = 1) and ([:len $owned] = 1) and ([:tostr $owned] = [:tostr $ids]))
            }
            :if ([$verified $component $ownedTag $vethName]) do={
                :do {
                    :local id [/container/find where name=$component and comment=$ownedTag and interface=$vethName]
                    :local healthy false
                    :if ([:len [/container/find where .id=$id and running]] = 1) do={
                        :if ($component = "tikray-runner") do={
                            :do { :set healthy ([/ping address=$runnerIP src-address=$gateway count=1 interval=400ms] = 1) } on-error={ :set healthy false }
                        } else={
                            :set healthy [$controlOK $ctlIP $gateway $savedState]
                        }
                    }
                    :local uptime ([:tonsec [/system/resource/get uptime]] / 1000000000)
                    :local prior ($savedState->$component)
                    :if ([:typeof $prior] != "array") do={ :set prior [:toarray ""] } else={
                        :if (($uptime < ($prior->"at")) or ((($prior->"miss") < 3) and ($uptime > (($prior->"at") + 120))) or ((($prior->"miss") = 3) and ($uptime > (($prior->"due") + 120)))) do={ :set prior [:toarray ""] }
                    }
                    :local state [$wdStep $prior $healthy $uptime]
                    :if ([$wdState "save" $component $state $uptime] != true) do={ :error "tikray: watchdog state unverified" }
                    :if (($state->"restart") and (![$suspended "restart"]) and ([$verified $component $ownedTag $vethName])) do={
                        :if ([:len [/container/find where .id=$id and running]] = 1) do={
                            /container/stop $id
                            :local waits 0
                            :while (([:len [/container/find where .id=$id and stopped]] = 0) and ($waits < 40)) do={ :delay 250ms; :set waits ($waits+1) }
                        }
                        :if ((![$suspended "restart"]) and ([$verified $component $ownedTag $vethName]) and ([:len [/container/find where .id=$id and name=$component and comment=$ownedTag and stopped]] = 1)) do={
                            /container/start $id
                            :log warning ("tikray: watchdog restarted " . $component)
                        }
                    }
                } on-error={ :log warning ("tikray: watchdog could not complete check for " . $component) }
            } else={
                # An absent or foreign sibling cannot disable recovery of the other component.
                :local clear [$wdState "save" $component ({"miss"=0;"delay"=1;"due"=0}) 0]
            }
            }
        }
        :return true
    }
    :local finished [$runTick]
}
