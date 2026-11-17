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
        :local body $2; :local traffic $3
        # Migration is restricted to the shipped M3a/Task 5 source with its
        # original exact rights. Never overwrite a modified owner script.
        :local legacyBody do={
            :local h [:convert [:convert $1 from=raw transform=sha512 to=hex] transform=lc]
            :return ([:typeof [:find {"7fad8d703957f8bb406b97d0b89643833c209e77ef0ff062f7a6ad8eccc1761e932356f0e86271cc88715222b6edf3c6dd045d21af003cbb42b4f8bcc3078356";"6df7eedf47af34e4eb622c85376450179a98d18a6d3032b31657bad0f1ee85985ff819f6a15d41f0f8750ee63485f9d92f0c41950f3622ac3d75f0805e7ea845";"616ab4fcc900e3e5b331adda302ee096a451e07bef925f6eb86a995dcfb58f3ee38a179c284b226a42cbe1011f7998ce1645b5382adf5feb39bfb53ed253c1db"} $h]]="num")
        }
        # An earlier image watchdog has the current rights but a different
        # verifier and traffic helper. Match the two exact previous programs.
        :local previousImage do={
            :local kind $1
            :local h [:convert [:convert $2 from=raw transform=sha512 to=hex] transform=lc]
            :local shapes {"watchdog"={"cbcae0d08decb712899d1bb5fafffbfd3b5987ae020ea8fc65801d896d5e315853064a01e465c382e5f4b064f21f4510265d459ac19c8a6babdae62d6c0d5622";"39bebb67fa22f17a99afbcf3433657329fb7cbd9614e93fb9e9610bf4516eb7e5f6cc23adbac2d18b118978e80bdfa905f8ca6d329e6839444ef11b60e13570f";"3962a31257cc486f499b19d783fedd7b7dd180a82364dbb1fb599666da296bc7453693bf37e42301f8d10945e4cc101515f0fd2cc2a0e155cfb2c79cd20b4fe0";"97658184c2b4ba7bfe8c8fb0d7c29e0d8d96d246577ca54c74e5fc36670463f88ef83e368d487d3eab4dcc1d67755786a17a113f3fcf6f716319682a71e0a944"};"traffic"={"5fe76c3a2362dc534e2818f2a6c8807b67185b06e267dec60d0a32b1ad558c8f506e63d552fe1bc601dd21185108958c21c3913b9044a4e1598a60c1fdc15696";"592fdc06a8c5851dc3b24650bf7dba685a43a36bb5540960afc32c9c7f9fba153b5dfd4749880d29a60514751c7b8377cb5925d35eda0d4c162ba9d8acffb150";"b20e21eeec706a8296cdd9ad52d7a62835edd3c0900e8bfd317fc2cc6056db89fb3b5d74b2ccdb257a885861125dd1b9639574a35fc6ff23a7cc4df0eb983a59";"fbbdefadf8f743d44369f73e2ea0b3c847446dbe13d65bdbffc46fffb75af68055d9427540df8bc86b6c243347f12a7a46e133c6b9b703535fdffb91d47c4094"}}
            :return ([:typeof [:find ($shapes->$kind) $h]]="num")
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
        :local migrateHelper false
        :local helpers [/system/script/find where name="tikray-watchdog-traffic" or comment="tikray:watchdog-traffic"]
        :if ([:len $helpers]>0) do={
            :if (([:len $helpers]!=1) or ([:len [/system/script/find where name="tikray-watchdog-traffic" and comment="tikray:watchdog-traffic" and !dont-require-permissions]]!=1)) do={:error "tikray: watchdog helper ownership conflict"}
            :local helperID [:pick $helpers 0]; :local sourceText [/system/script/get $helperID source]; :local count 0
            :foreach perm in=[/system/script/get $helperID policy] do={:if ([:pick $perm 0 1]!="!") do={:if ($perm!="read") do={:error "tikray: watchdog helper privileges conflict"}; :set count ($count+1)}}
            :if ($count!=1) do={:error "tikray: watchdog helper privileges conflict"}
            :if (($sourceText!=$traffic) and ($sourceText!=($traffic . "\n")) and ($sourceText!=($traffic . "\r\n"))) do={
                :if (![$previousImage "traffic" $sourceText]) do={:error "tikray: watchdog helper has changed"}
                :set migrateHelper true
            }
        }
        :local migrate false; :local oldSchedule false
        :local scripts [/system/script/find where name="tikray-watchdog" or comment="tikray:watchdog-script"]
        :local ticks [/system/scheduler/find where name="tikray-watchdog" or comment="tikray:watchdog-scheduler"]
        :if ([:len $scripts] > 0) do={
            :if (([:len $scripts] != 1) or ([:len [/system/script/find where name="tikray-watchdog" and comment="tikray:watchdog-script" and !dont-require-permissions]] != 1)) do={ :error "tikray: watchdog script ownership conflict" }
            :local rights [$checkPolicy [/system/script/get $scripts policy]]
            :local saved [/system/script/get $scripts source]
            :if (($saved != $body) and ($saved != ($body . "\r\n")) and ($saved != ($body . "\n"))) do={
                :if (!(($rights="prior" and [$legacyBody $saved]) or ($rights="current" and [$previousImage "watchdog" $saved]))) do={ :error "tikray: watchdog script has changed; inspect before proceeding" }
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
            :if ([:len $helpers]=0) do={ /system/script/add name=tikray-watchdog-traffic comment="tikray:watchdog-traffic" policy=read dont-require-permissions=no source=$traffic }
            :if ($migrateHelper) do={ /system/script/set [:pick $helpers 0] source=$traffic }
            :if ($migrate) do={ /system/script/set [:pick $scripts 0] policy=read,write,test,ftp source=$body }
            :if ($oldSchedule) do={ /system/scheduler/set [:pick $ticks 0] policy=read,write,test,ftp }
            :if ([:len $scripts] = 0) do={ /system/script/add name=tikray-watchdog comment="tikray:watchdog-script" policy=read,write,test,ftp dont-require-permissions=no source=$body }
            :if ([:len $ticks] = 0) do={ /system/scheduler/add name=tikray-watchdog comment="tikray:watchdog-scheduler" policy=read,write,test,ftp interval=1m start-time=startup on-event=tikray-watchdog } else={
                :if ([/system/scheduler/get $ticks disabled]) do={ /system/scheduler/enable $ticks }
            }
        }
        :return true
    }
    :local watchOK [$provisionWatch false $watchBody $trafficBody]
    :if ($watchOK != true) do={ :error "tikray: watchdog preflight failed" }
