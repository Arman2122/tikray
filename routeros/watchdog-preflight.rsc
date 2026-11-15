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
        # Migration is restricted to the shipped M3a/Task 5 source with its
        # original exact rights. Never overwrite a modified owner script.
        :local legacyBody do={
            :local h [:convert [:convert $1 from=raw transform=sha512 to=hex] transform=lc]
            :return ([:typeof [:find {"7fad8d703957f8bb406b97d0b89643833c209e77ef0ff062f7a6ad8eccc1761e932356f0e86271cc88715222b6edf3c6dd045d21af003cbb42b4f8bcc3078356";"6df7eedf47af34e4eb622c85376450179a98d18a6d3032b31657bad0f1ee85985ff819f6a15d41f0f8750ee63485f9d92f0c41950f3622ac3d75f0805e7ea845";"616ab4fcc900e3e5b331adda302ee096a451e07bef925f6eb86a995dcfb58f3ee38a179c284b226a42cbe1011f7998ce1645b5382adf5feb39bfb53ed253c1db"} $h]]="num")
        }
        :local checkPolicy do={
            :local count 0; :local ftp false
            :foreach right in=$1 do={
                :if ([:pick $right 0 1] != "!") do={
                    :if (($right != "read") and ($right != "write") and ($right != "test") and ($right!="ftp")) do={ :error "tikray: unexpected watchdog privileges" }
                    :if ($right="ftp") do={ :set ftp true }
                    :set count ($count + 1)
                }
            }
            :if (($count=3) and (!$ftp)) do={ :return "prior" }
            :if (($count=4) and $ftp) do={ :return "current" }
            :error "tikray: watchdog permissions conflict"
        }
        :local migrate false; :local oldSchedule false
        :local scripts [/system/script/find where name="tikray-watchdog" or comment="tikray:watchdog-script"]
        :local ticks [/system/scheduler/find where name="tikray-watchdog" or comment="tikray:watchdog-scheduler"]
        :if ([:len $scripts] > 0) do={
            :if (([:len $scripts] != 1) or ([:len [/system/script/find where name="tikray-watchdog" and comment="tikray:watchdog-script" and !dont-require-permissions]] != 1)) do={ :error "tikray: watchdog script ownership conflict" }
            :local rights [$checkPolicy [/system/script/get $scripts policy]]
            :local saved [/system/script/get $scripts source]
            :if (($saved != $body) and ($saved != ($body . "\r\n")) and ($saved != ($body . "\n"))) do={
                :if (($rights!="prior") or (![$legacyBody $saved])) do={ :error "tikray: watchdog script has changed; inspect before proceeding" }
                :set migrate true
            } else={ :if ($rights!="current") do={ :error "tikray: watchdog permissions conflict" } }
        }
        :if ([:len $ticks] > 0) do={
            :if (([:len $ticks] != 1) or ([:len [/system/scheduler/find where name="tikray-watchdog" and comment="tikray:watchdog-scheduler" and on-event="tikray-watchdog" and interval=1m]] != 1)) do={ :error "tikray: watchdog scheduler ownership conflict" }
            :local rights [$checkPolicy [/system/scheduler/get $ticks policy]]
            :set oldSchedule ($rights="prior")
            :if ($oldSchedule and ([:len $scripts]!=1)) do={ :error "tikray: orphan watchdog permissions conflict" }
        }
        :if ($apply) do={
            :if ($migrate) do={ /system/script/set [:pick $scripts 0] policy=read,write,test,ftp source=$body }
            :if ($oldSchedule) do={ /system/scheduler/set [:pick $ticks 0] policy=read,write,test,ftp }
            :if ([:len $scripts] = 0) do={ /system/script/add name=tikray-watchdog comment="tikray:watchdog-script" policy=read,write,test,ftp dont-require-permissions=no source=$body }
            :if ([:len $ticks] = 0) do={ /system/scheduler/add name=tikray-watchdog comment="tikray:watchdog-scheduler" policy=read,write,test,ftp interval=1m start-time=startup on-event=tikray-watchdog } else={
                :if ([/system/scheduler/get $ticks disabled]) do={ /system/scheduler/enable $ticks }
            }
        }
        :return true
    }
    :local watchOK [$provisionWatch false $watchBody]
    :if ($watchOK != true) do={ :error "tikray: watchdog preflight failed" }
