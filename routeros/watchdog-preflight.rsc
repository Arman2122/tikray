    :local readWatchID do={
        :local rows [/file/find where name=($1 . "/state/install.id")]
        :if ([:len $rows] != 1) do={ :error "tikray: check the control volume installation ID" }
        :local value [/file/get [:pick $rows 0] contents]
        :if (([:len $value] != 32) or (!($value ~ "^[0-9a-f]+\$"))) do={ :error "tikray: invalid control volume installation ID" }
        :return $value
    }
    :if ([:typeof ($watchStateCheck->"installation_id")] = "str") do={
        :if ([$readWatchID $data] != ($watchStateCheck->"installation_id")) do={ :error "tikray: watchdog installation ID conflict" }
    }
    :local provisionWatch do={
        :local apply [:tobool $1]
        :local body $2
        :local checkPolicy do={
            :local count 0
            :foreach right in=$1 do={
                :if ([:pick $right 0 1] != "!") do={
                    :if (($right != "read") and ($right != "write") and ($right != "test")) do={ :error "tikray: unexpected watchdog privileges" }
                    :set count ($count + 1)
                }
            }
            :if ($count != 3) do={ :error "tikray: watchdog permissions conflict" }
            :return true
        }
        :local scripts [/system/script/find where name="tikray-watchdog" or comment="tikray:watchdog-script"]
        :local ticks [/system/scheduler/find where name="tikray-watchdog" or comment="tikray:watchdog-scheduler"]
        :if ([:len $scripts] > 0) do={
            :if (([:len $scripts] != 1) or ([:len [/system/script/find where name="tikray-watchdog" and comment="tikray:watchdog-script" and !dont-require-permissions]] != 1)) do={ :error "tikray: watchdog script ownership conflict" }
            $checkPolicy [/system/script/get $scripts policy]
            :local saved [/system/script/get $scripts source]
            :if (($saved != $body) and ($saved != ($body . "\r\n")) and ($saved != ($body . "\n"))) do={ :error "tikray: watchdog script has changed; inspect before proceeding" }
        }
        :if ([:len $ticks] > 0) do={
            :if (([:len $ticks] != 1) or ([:len [/system/scheduler/find where name="tikray-watchdog" and comment="tikray:watchdog-scheduler" and on-event="tikray-watchdog" and interval=1m]] != 1)) do={ :error "tikray: watchdog scheduler ownership conflict" }
            $checkPolicy [/system/scheduler/get $ticks policy]
        }
        :if ($apply) do={
            :if ([:len $scripts] = 0) do={ /system/script/add name=tikray-watchdog comment="tikray:watchdog-script" policy=read,write,test dont-require-permissions=no source=$body }
            :if ([:len $ticks] = 0) do={ /system/scheduler/add name=tikray-watchdog comment="tikray:watchdog-scheduler" policy=read,write,test interval=1m start-time=startup on-event=tikray-watchdog } else={
                :if ([/system/scheduler/get $ticks disabled]) do={ /system/scheduler/enable $ticks }
            }
        }
        :return true
    }
    :local watchOK [$provisionWatch false $watchBody]
    :if ($watchOK != true) do={ :error "tikray: watchdog preflight failed" }
