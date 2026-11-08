# RouterOS runs this independently once a minute. Never write runtime counters to flash.
{
    :if ([:len [/system/script/job/find where script="tikray-watchdog"]] != 1) do={ :return }
    :local suspended do={
        :if (([:len [/system/script/find where name="tikray-emergency-state" or comment="tikray:emergency-state" or comment="tikray:uninstall-state"]] > 0) or ([:len [/system/script/job/find where script="tikray-emergency-off" or script="tikray-uninstall"]] > 0)) do={ :return true }
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
    :global tikrayWatchdogState
    :if ([$suspended]) do={ :set tikrayWatchdogState [:toarray ""]; :return }
    :local mounts [/container/mounts/find where comment="tikray:mount-tikray-data" and list="tikray" and dst="/data"]
    :if ([:len $mounts] != 1) do={ :return }
    :local data [/container/mounts/get $mounts src]
    :if ([:pick $data 0 1] = "/") do={ :set data [:pick $data 1 [:len $data]] }
    :local ready [/file/find where name=($data . "/state/install.ready")]
    :if ([:len $ready] != 1) do={ :return }
    :local pin [/file/get $ready contents]
    :if (([:len $pin] != 64) or ($pin !~ "^[0-9a-f]+\$")) do={ :return }
    :local bridgeAddr [/ip/address/find where interface="tikray" and comment="tikray:addr" and !disabled]
    :if ([:len $bridgeAddr] != 1) do={ :return }
    :local cidr [:tostr [/ip/address/get $bridgeAddr address]]
    :local gateway [:toip [:pick $cidr 0 [:find $cidr "/"]]]
    :local ctlIP ($gateway + 1)
    :local runnerIP ($gateway + 2)
    # @TIKRAY_WATCHDOG_STEP@
    :if ([:typeof $tikrayWatchdogState] != "array") do={ :set tikrayWatchdogState [:toarray ""] }
    :foreach component in={"tikray-runner";"tikray"} do={
        :local ownedTag "tikray:tikray"
        :local vethName "tikray-ctl"
        :if ($component = "tikray-runner") do={ :set ownedTag "tikray:runner"; :set vethName "tikray-runner" }
        :local verified do={
            :local ids [/container/find where name=$1 or comment=$2 or interface=$3]
            :local owned [/container/find where name=$1 and comment=$2 and interface=$3]
            :return (([:len $ids] = 1) and ([:len $owned] = 1) and ([:tostr $owned] = [:tostr $ids]))
        }
        :if (![$verified $component $ownedTag $vethName]) do={ :return }
        :local id [/container/find where name=$component and comment=$ownedTag and interface=$vethName]
        :local healthy false
        :if ([:len [/container/find where .id=$id and running]] = 1) do={
            :if ($component = "tikray-runner") do={
                :set healthy ([/ping address=$runnerIP src-address=$gateway count=1 interval=400ms] = 1)
            } else={
                # @TIKRAY_WATCHDOG_HEALTH@
            }
        }
        :local uptime ([:tonsec [/system/resource/get uptime]] / 1000000000)
        :local prior ($tikrayWatchdogState->$component)
        :if ([:typeof $prior] != "array") do={ :set prior [:toarray ""] }
        :local state [$wdStep $prior $healthy $uptime]
        :set ($tikrayWatchdogState->$component) $state
        :if (($state->"restart") and (![$suspended]) and ([$verified $component $ownedTag $vethName])) do={
            :if ([:len [/container/find where .id=$id and running]] = 1) do={
                /container/stop $id
                :local waits 0
                :while (([:len [/container/find where .id=$id and stopped]] = 0) and ($waits < 40)) do={ :delay 250ms; :set waits ($waits+1) }
            }
            :if ((![$suspended]) and ([$verified $component $ownedTag $vethName]) and ([:len [/container/find where .id=$id and name=$component and comment=$ownedTag and stopped]] = 1)) do={ /container/start $id }
        }
    }
}
