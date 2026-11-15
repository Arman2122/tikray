# The service publishes one immutable, authenticated request. Only this owner
# scheduler operates the container; its native phase survives either image.
:local wdImage do={
    :local data $1; :local identity $2; :local gateway $3
    :local controlOK $4; :local stopCheck $5; :local emergency $6
    :local pending ($data . "/state/image-update.request")
    :local phaseName "tikray-image-transition"; :local prefix "tikray:image-transition "
    :local files [/file/find where name=$pending]
    :local journals [/system/script/find where name=$phaseName or comment~"^tikray:image-transition "]
    :if ([:len [/file/find where name=($data . "/state/image-update.json")]]>0) do={:error "image: legacy transition requires owner inspection"}
    :if (([:len $files]=0) and ([:len $journals]=0)) do={ :return "" }
    :if (([:len [/ip/firewall/mangle/find where comment~"^tikray:image-mark:"]]>0) and ([:len $journals]!=1)) do={:error "image: orphan native flow reference"}
    :foreach legacy in={"image-update.json";"image-probe.json";"image-bootstrap.json";"image-tikray.json";"image-runner.json"} do={:if ([:len [/file/find where name=($data . "/state/" . $legacy)]]>0) do={:error "image: legacy receipts require owner inspection"}}
    :local hexOK do={
        :return (([:typeof $1]="str") and ([:len $1]=$2) and ($1~"^[0-9a-f]+\$"))
    }
    :local jsonFile do={
        :local bound 4096; :if ($2=60000) do={:set bound 60000}
        :local rows [/file/find where name=$1]
        :if ([:len $rows]!=1) do={ :error "image: missing proof" }
        :local id [:pick $rows 0]
        :if (([/file/get $id size]>$bound) or ([/file/get $id type]="directory")) do={ :error "image: invalid proof" }
        :return [:deserialize from=json options=json.no-string-conversion value=[/file/get $id contents]]
    }
    :local readJournal do={
        :local id $1; :local pref $2
        :local row [/system/script/get $id]; :local comment ($row->"comment")
        :if ((($row->"name")!="tikray-image-transition") or ([:pick $comment 0 [:len $pref]]!=$pref) or ([:len ($row->"source")]!=0) or ($row->"dont-require-permissions") or ([:len $comment]>4096)) do={ :error "image: foreign transition state" }
        :local readOnly false
        :foreach p in=($row->"policy") do={ :if ([:pick $p 0 1]!="!") do={ :if ($p!="read") do={:error "image: foreign transition permissions"}; :set readOnly true } }
        :if (!$readOnly) do={ :error "image: foreign transition permissions" }
        :return [:deserialize from=json options=json.no-string-conversion value=[:pick $comment [:len $pref] [:len $comment]]]
    }
    :local j [:toarray ""]
    :local jid
    :if ([:len $journals]>0) do={
        :if ([:len $journals]!=1) do={ :error "image: ambiguous transition" }
        :set jid [:pick $journals 0]; :set j [$readJournal $jid $prefix]
        :if ((($j->"v")!=1) or (($j->"install")!=$identity) or (![$hexOK ($j->"nonce") 32]) or ((($j->"component")!="runner") and (($j->"component")!="tikray"))) do={ :error "image: transition identity changed" }
    }
    :if ([:len $files]=0) do={
        :if ((($j->"phase")="committed") or (($j->"phase")="reverted")) do={
            :if (![$stopCheck "restart"]) do={ /system/script/remove $jid }
            :return ""
        }
        :error "image: request missing during transition"
    }
    :local req [$jsonFile $pending]; :local rid [:pick $files 0]; :local requestText [/file/get $rid contents]
    :local component ($req->"component"); :local nonce ($req->"nonce")
    :local requestHash [:convert [:convert $requestText from=raw transform=sha512 to=hex] transform=lc]
    :local original ($req->"previous"); :local candidate ($req->"candidate")
    :local validRef do={
        :local ref $1; :local hex $2
        :return (([:typeof $ref]="array") and ([:len $ref]=5) and (($ref->"component")=$3) and ([$hex ($ref->"digest") 64]) and ([$hex ($ref->"image_id") 64]) and ([$hex ($ref->"chain") 128]) and ([:typeof ($ref->"size")]="num") and (($ref->"size")>0) and (($ref->"size")<=134217728))
    }
    :local sameRef do={
        :foreach field in={"component";"digest";"image_id";"chain";"size"} do={:if (($1->$field)!=($2->$field)) do={:return false}}
        :return true
    }
    :local offline (([:typeof ($req->"offline_rollback")]="bool") and (($req->"offline_rollback")=true))
    :if ((([:len $req]!=10) and (!($offline and ([:len $req]=11) and ($component="runner")))) or (($req->"version")!=1) or (($req->"phase")!="requested") or (($req->"installation_id")!=$identity) or (![$hexOK $nonce 32]) or (![$hexOK ($req->"selection_digest") 64]) or (($component!="tikray") and ($component!="runner")) or ([:typeof ($req->"started")]!="num") or (($req->"started")<=0) or ([:typeof ($req->"deadline")]!="num") or ((($req->"deadline")-($req->"started"))!=300)) do={ :error "image: invalid request" }
    :if ((![$validRef $original $hexOK $component]) or (![$validRef $candidate $hexOK $component]) or (($candidate->"digest")=($original->"digest")) or (($candidate->"image_id")=($original->"image_id"))) do={ :error "image: invalid archive identities" }
    :if ((!($data~"^[A-Za-z0-9][A-Za-z0-9_-]*/tikray(-[A-Za-z0-9_][A-Za-z0-9_-]*)?/data\$")) or ([:len [/file/find where name=($data . "/state/install.id") and contents=$identity]]!=1)) do={ :error "image: control volume changed" }
    :local staging {"target"=$component;"nonce"=$nonce;"original"=("tikray:image-import:" . $nonce . ":old");"candidate"=("tikray:image-import:" . $nonce . ":new");"emergency"=$emergency}
    :local checkMounts do={
        :local data $1; :local install $2; :local operation $3
        :if ([:len [/file/find where name=($data . "/state/install.id") and contents=$install]]!=1) do={:error "image: control volume changed"}
        :local norm do={
            :local n [:tostr $1]
            :if ([:pick $n 0 1]="/") do={:set n [:pick $n 1 [:len $n]]}
            :if ([:pick $n ([:len $n]-1) [:len $n]]="/") do={:set n [:pick $n 0 ([:len $n]-1)]}
            :return $n
        }
        :local disk [:pick $data 0 [:find $data "/"]]; :local vol [/disk/find where mount-point=$disk and fs="ext4"]
        :if ([:len $vol]!=1) do={:error "image: unknown container disk"}
        :local drive [:tostr [/disk/get [:pick $vol 0] slot]]
        :if (!($drive~"^[A-Za-z0-9][A-Za-z0-9_-]*\$")) do={:error "image: unknown disk alias"}
        :local suff [:pick $data [:find $data "/"] [:len $data]]
        :local envs [/container/envs/find where list="tikray" or list="tikray-runner" or comment="tikray:env-ctl-data" or comment="tikray:env-runner-data"]
        :if (([:len $envs]!=2) or ([:len [/container/envs/find where comment="tikray:env-ctl-data" and list="tikray" and key="TIKRAY_DATA" and value="/data"]]!=1) or ([:len [/container/envs/find where comment="tikray:env-runner-data" and list="tikray-runner" and key="TIKRAY_DATA" and value="/data"]]!=1)) do={:error "image: private environment changed"}
        :local owned [:toarray ""]
        :foreach part in={"data";"run";"cores";"geo"} do={
            :local ref "tikray:mount-tikray-data"; :local listName "tikray"; :local dst "/data"; :local from $data; :local mode "rw"
            :if ($part!="data") do={
                :set ref ("tikray:mount-runner-" . $part); :set listName "tikray-runner"; :set dst ("/data/" . $part); :set from ($data . "/" . $part)
                :if ($part!="run") do={:set mode "ro"}
            }
            :local all [/container/mounts/find where comment=$ref]; :if ([:len $all]!=1) do={:error "image: private mount changed"}
            :local id [:pick $all 0]; :local row [/container/mounts/get $id]
            :if ((($row->"list")!=$listName) or (($row->"dst")!=$dst) or ([$norm ($row->"src")]!=$from) or ([:tostr ($row->"mode")]!=$mode)) do={:error "image: private mount changed"}
            :set ($owned->[:tostr $id]) true
        }
        :foreach id in=[/container/mounts/find where list="tikray" or list="tikray-runner"] do={:if (($owned->[:tostr $id])!=true) do={:error "image: shared private mount"}}
        :foreach dev in=({$disk;$drive}) do={
            :local directory ($dev . $suff); :local base [:pick $directory 0 ([:len $directory]-5)]
            :local expr ("^/?" . $directory . "(/|\$)")
            :foreach id in=[/container/mounts/find where src~$expr] do={:if (($owned->[:tostr $id])!=true) do={:error "image: shared private mount"}}
            :if ([:len [/container/find where root-dir~$expr]]!=0) do={:error "image: private data exposed in a container root"}
            :foreach ancestor in=({$dev;$base}) do={
                :if (([:len [/container/mounts/find where src=$ancestor or src=("/" . $ancestor) or src=("/" . $ancestor . "/")]]>0) or ([:len [/container/find where root-dir=$ancestor or root-dir=("/" . $ancestor) or root-dir=("/" . $ancestor . "/")]]>0)) do={:error "image: shared private mount"}
            }
        }
        :foreach c in=[/container/find where mountlists~"tikray" or envlists~"tikray"] do={
            :local row [/container/get $c]; :local lists (($row->"mountlists"),($row->"envlists"))
            :foreach listName in=$lists do={
                :if (($listName="tikray") or ($listName="tikray-runner")) do={
                    :local expected "tikray:tikray"; :local port "tikray-ctl"
                    :if ($listName="tikray-runner") do={:set expected "tikray:runner"; :set port "tikray-runner"}
                    :local transient (($row->"comment")=($operation->"candidate") or ($row->"comment")=($operation->"original"))
                    :if (($listName="tikray") and (($operation->"target")!="tikray")) do={:set transient false}
                    :if (($listName="tikray-runner") and (($operation->"target")!="runner")) do={:set transient false}
                    :if ((($row->"name")!=$listName) or ((($row->"comment")!=$expected) and (!$transient)) or ([:tostr ($row->"interface")]!=$port)) do={:error "image: shared private mount"}
                }
            }
        }
        :return true
    }
    :local scopeVerified [$checkMounts $data $identity $staging]
    :local arch [/system/resource/get architecture-name]; :if ($arch="x86_64") do={:set arch "amd64"}
    :local boot [$jsonFile ($data . "/state/image-bootstrap.receipt")]
    :if ((($boot->"version")!=1) or (($boot->"arch")!=$arch) or (![$validRef ($boot->$component) $hexOK $component])) do={ :error "image: bootstrap proof unavailable" }
    :local statePath ($data . "/state/image-" . $component . ".receipt")
    :local states [/file/find where name=$statePath]
    :if (([:len $states]!=1) or ([/file/get [:pick $states 0] type]="directory") or ([/file/get [:pick $states 0] size]>4096)) do={:error "image: current receipt unavailable"}
    :local stateFile [:pick $states 0]; :local oldState [/file/get $stateFile contents]
    :local installed; :local retained; :local currentOK false
    :do {
        :local state [$jsonFile $statePath]; :local prior ($state->"previous")
        :local lineage false
        :if (([:typeof $prior]="nil") or ([:typeof $prior]="nothing")) do={:set lineage [$sameRef ($state->"active") ($boot->$component)]} else={
            :set lineage (([$validRef $prior $hexOK $component]) and (($prior->"digest")!=($state->"active"->"digest")) and (($prior->"image_id")!=($state->"active"->"image_id")))
        }
        :if (([:len $state]=4) and (($state->"version")=1) and (($state->"installation_id")=$identity) and ([$validRef ($state->"active") $hexOK $component]) and $lineage) do={
            :set installed ($state->"active"); :set retained $prior; :set currentOK true
        }
    } on-error={}
    # The receipt is never removed during commit. Only its verified ID in
    # our write-ahead decision can authorize repairing a torn in-place write.
    :if (!$currentOK) do={
        :if ((($j->"nonce")!=$nonce) or (($j->"receipt")!=[:tostr $stateFile]) or ((($j->"phase")!="commit") and (($j->"phase")!="restore") and (($j->"phase")!="recover") and (($j->"phase")!="reverted"))) do={:error "image: invalid current receipt"}
        :set installed $original
    }
    :local base [:pick $data 0 ([:len $data]-5)]
    :local targetName "tikray"; :local side "control"; :local ownerTag "tikray:tikray"; :local iface "tikray-ctl"
    :local high 134217728; :local limit 201326592
    :if ($component="runner") do={ :set targetName "tikray-runner"; :set side "runner"; :set ownerTag "tikray:runner"; :set iface "tikray-runner"; :set high 201326592; :set limit 268435456 }
    :local root ($base . "/containers/" . $side)
    :local profile {"component"=$component;"name"=$targetName;"tag"=$ownerTag;"veth"=$iface;"root"=$root;"gateway"=$gateway;"high"=$high;"max"=$limit;"old"=$original;"new"=$candidate;"staging"=$staging;"data"=$data;"seed"=($boot->$component);"platform"=$arch}
    # Container-store children are hidden from /file/find. Native add never
    # replaces an existing child. An exact read, including the next possible
    # byte, rejects a foreign file that merely starts with the expected tag.
    :local imageRootWitness do={
        :if ($1="create") do={:do {/file/add name=$2 type=file contents=$3} on-error={}}
        :local value ""
        :do {:set value ([/file/read file=$2 offset=0 chunk-size=([:len $3]+1) as-value]->"data")} on-error={}
        :return (([:len $value]=[:len $3]) and ($value=$3))
    }
    :local witnessPath ("/tikray-import-" . $nonce . ".receipt")
    # Use only time spent on a boot. Repeated manual ticks within one
    # second add nothing. A lower uptime starts a new boot; a greater
    # uptime gives a safe lower bound even if the wall clock was changed.
    :local advanceAge do={
        :local elapsed ($3-$2)
        :if (($elapsed<0) or (($elapsed=0) and ($4=true))) do={
            :set elapsed $3
            :if (($4=true) and ($elapsed<1)) do={:set elapsed 1}
        }
        :local age ($1+$elapsed)
        :if ($age>300) do={:set age 300}
        :return $age
    }
    # @TIKRAY_WATCHDOG_TRAFFIC@
    :local grant {"paused"=$stopCheck;"p"=$pending;"id"=$rid;"text"=$requestText;"data"=$data;"identity"=$identity;"mounts"=$checkMounts;"staging"=$staging}
    :local checkGrant do={
        :local g $1; :local check ($g->"paused"); :local path ($g->"p"); :local id ($g->"id"); :local token ($g->"staging")
        :local pause "restart"; :if ([:len ($token->"emergency")]>0) do={:set pause "bindings"; :if ([:tostr [:pick [/system/script/find where name="tikray-emergency-state" and comment="tikray:emergency-state" and source=""] 0]]!=($token->"emergency")) do={:error "image: emergency state changed"}}
        :local mounts ($g->"mounts")
        :if ((![$mounts ($g->"data") ($g->"identity") $token]) or ([$check $pause]) or ([:len [/file/find where name=$path and .id=$id]]!=1) or ([/file/get $id contents]!=($g->"text"))) do={:error "image: request changed"}
        :return true
    }
    :local trafficLAN ""
    :if ($component="runner") do={
        :local in [$jsonFile ($data . "/state/install.request") 60000]
        :set trafficLAN ($in->"scope"->"lan_list")
        :if (([:typeof $trafficLAN]!="str") or (!($trafficLAN~"^[A-Za-z0-9_][A-Za-z0-9_.-]*\$"))) do={:error "image: unknown managed LAN"}
    }
    :local clockAlive do={
        :if ([:typeof ($1->"job")]!="str") do={:return false}
        :local id [:toid ($1->"job")]; :if ([:typeof $id]!="id") do={:return false}
        :local found [/system/script/job/find where .id=$id]
        :if ([:len $found]!=1) do={:return false}
        :return ([:tostr [/system/script/job/get $id started]]=($1->"born"))
    }
    :local makeClock do={
        # A fixed delay job has no router authority. Its ID and start value
        # distinguish equal-uptime ticks on separate boots, like install-lock.
        :local id [:execute {:delay 10m}]
        :return {"job"=[:tostr $id];"born"=[:tostr [/system/script/job/get $id started]]}
    }
    :local now ([:tonsec [/system/resource/get uptime]]/1000000000)
    :if ([:len $journals]=0) do={
        :if (![$sameRef $installed $original]) do={:error "image: stale previous selection"}
        :local live [$imageTraffic "row" $profile]
        :if ((($live->"image_id")!=($original->"image_id")) or ($live->"partial")) do={:error "image: installed bytes differ"}
        :if ($offline and (([:typeof $retained]!="array") or (![$sameRef $candidate $retained]))) do={:error "image: unverified offline rollback"}
        :local stopped ($offline and ([:len [/container/find where .id=($live->"id") and stopped]]=1))
        :local a [$imageTraffic "archive" $data $original]
        :local firstPhase "prepare"
        :if ([:len $emergency]>0) do={:set firstPhase "recover"}
        :do { :local b [$imageTraffic "archive" $data $candidate] } on-error={ :set firstPhase "recover"; :log warning "tikray: candidate image integrity refused" }
        :local f [$checkGrant $grant]
        :set now ([:tonsec [/system/resource/get uptime]]/1000000000)
        :set j {"v"=1;"install"=$identity;"nonce"=$nonce;"component"=$component;"request"=$requestHash;"phase"=$firstPhase;"age"=0;"seen"=$now;"old"=$oldState;"receipt"=[:tostr $stateFile];"retry"=1;"next"=0}
        :set ($j->"baseline") [:tostr ($live->"id")]; :set ($j->"offline") $stopped; :set ($j->"fenced") false
        :if (($component="runner") and ($firstPhase="prepare")) do={:set ($j->"traffic") [$imageTraffic "read" [:toarray ""] ($gateway+2) $trafficLAN $checkGrant $grant ([:len $emergency]>0)]}
        /system/script/add name=$phaseName source="" policy=read dont-require-permissions=no comment=($prefix . [:serialize to=json options=json.no-string-conversion value=$j])
        :set journals [/system/script/find where name=$phaseName]
        :if ([:len $journals]!=1) do={:error "image: transition publication failed"}
        :set jid [:pick $journals 0]; :set j [$readJournal $jid $prefix]
    }
    :if (($j->"nonce")!=$nonce) do={
        # A new request may land just after retirement of the previous file.
        :if ((($j->"phase")="committed") or (($j->"phase")="reverted")) do={ /system/script/remove $jid; :return $targetName }
        :error "image: other transition active"
    }
    :if ((($j->"component")!=$component) or (($j->"request")!=$requestHash)) do={ :error "image: request changed" }
    :local save do={
        :local data $1; :local id $2; :local pre $3; :local old $4
        :if (([/system/script/get $id name]!="tikray-image-transition") or ([:len [/system/script/get $id source]]!=0) or ([/system/script/get $id comment]!=$old)) do={:error "image: transition was changed"}
        :local replacement ($pre . [:serialize to=json options=json.no-string-conversion value=$data])
        /system/script/set $id comment=$replacement
        :if ([/system/script/get $id comment]!=$replacement) do={:error "image: transition not persisted"}
        :return $replacement
    }
    :local saved [/system/script/get $jid comment]; :local phase ($j->"phase")
    :if ([:typeof [:find {"prepare";"replace";"verify";"restore";"recover";"commit";"committed";"reverted"} $phase]]!="num") do={:error "image: invalid transition phase"}
    :if (([:typeof ($j->"age")]!="num") or (($j->"age")<0) or (($j->"age")>300) or ([:typeof ($j->"seen")]!="num") or (($j->"seen")<0)) do={:error "image: invalid native timer"}
    :if (($phase="replace") or ($phase="verify")) do={
        :local newBoot (![$clockAlive ($j->"clock")])
        :local age [$advanceAge ($j->"age") ($j->"seen") $now $newBoot]
        :if ($newBoot) do={:set ($j->"clock") [$makeClock]}
        :set ($j->"age") $age; :set ($j->"seen") $now
        :if ($age>=300) do={:set phase "restore"; :set ($j->"phase") $phase}
        :set saved [$save $j $jid $prefix $saved]
    }
    # If the last boot died between the durable verdict and retiring the
    # request, require fresh health again before exposing a terminal result.
    :if ($phase="committed") do={:set phase "commit"}
    :if ($phase="reverted") do={:set phase "recover"}
    :if (([:len $emergency]>0) and (($phase="prepare") or ($phase="replace") or ($phase="verify") or ($phase="commit"))) do={
        :local current [$imageTraffic "row" $profile]
        :if ((($current->"image_id")=($candidate->"image_id")) and ([:len [/container/find where .id=($current->"id") and running]]=1)) do={:set phase "verify"} else={:set phase "restore"}
        :set ($j->"phase") $phase; :set saved [$save $j $jid $prefix $saved]
    }
    :local restoring (($phase="restore") or ($phase="recover") or ($phase="reverted"))
    :local want $candidate; :local other $original
    :if ($restoring) do={:set want $original; :set other $candidate}
    :local mayRemoveStopped ($offline and ($component="runner") and (($j->"offline")=true) and ([:typeof $retained]="array") and ([$sameRef $candidate $retained]))
    :if ($phase="prepare") do={
        :local originalRow [$imageTraffic "row" $profile]
        :if (([:tostr ($originalRow->"id")]!=($j->"baseline")) or (($originalRow->"image_id")!=($original->"image_id")) or ($originalRow->"partial") or (![$sameRef $installed $original]) or ($oldState!=($j->"old")) or ([:tostr $stateFile]!=($j->"receipt"))) do={:error "image: preparing baseline changed"}
        :if (($j->"offline")=true) do={:if ((!$mayRemoveStopped) or ([:len [/container/find where .id=($originalRow->"id") and stopped]]!=1)) do={:error "image: offline rollback baseline changed"}}
        :if ((!$mayRemoveStopped) and ([:len [/container/find where .id=($originalRow->"id") and running]]!=1)) do={:set ($j->"phase") "recover"; :set saved [$save $j $jid $prefix $saved]; :return $targetName}
    }
    :local healthy false; :local canRestart true
    :if (($component="runner") and ([:len $emergency]=0) and ($phase="prepare") and (($j->"fenced")!=true)) do={:set ($j->"fenced") true; :set saved [$save $j $jid $prefix $saved]}
    :set ($grant->"flow") ($j->"flow"); :set ($grant->"budget") 15000000000
    :local releasing ((($j->"flow"->"dir")="release") and ((($j->"phase")="committed") or (($j->"phase")="reverted")))
    :if ((($j->"fenced")=true) and (!$releasing) and ([:len $emergency]=0)) do={
        :local began [:tonsec [/system/resource/get uptime]]
        :local held [$imageTraffic "hold" ($j->"traffic") ($gateway+2) $trafficLAN $checkGrant $grant false]
        :local left (15000000000-([:tonsec [/system/resource/get uptime]]-$began)); :if ($left<0) do={:set left 0}
        :set ($grant->"budget") $left
        :set ($j->"flow") $held; :set saved [$save $j $jid $prefix $saved]; :set ($grant->"flow") $held
        :if (($held->"done")!=true) do={:return $targetName}
    }
    :if (($phase="prepare") or ($phase="replace") or ($phase="restore")) do={
        :local path ""
        :do { :set path [$imageTraffic "archive" $data $want] } on-error={
            :if ($restoring) do={ :error "image: restoration archive unavailable" }
            :set ($j->"phase") "restore"; :set saved [$save $j $jid $prefix $saved]
            :return $targetName
        }
        :local live [$imageTraffic "row" $profile]
        :if (([:len $live]>0) and (($live->"image_id")!=($want->"image_id"))) do={
            :local mine ($live->"partial")
            :local expected ($staging->"candidate"); :if (!$restoring) do={:set expected ($staging->"original")}
            :if ($mine and (($live->"tag")!=$expected)) do={
                # An interrupted restoration can itself leave a provisional
                # row without an image ID. Give a live extraction two minutes.
                # After a reboot or timeout retry only our nonce-bound row,
                # with the original signed archive and a bounded backoff.
                :if ((!$restoring) or (($live->"tag")!=($staging->"original"))) do={:return $targetName}
                :if (([$clockAlive ($j->"clock")]) and ($now>=($j->"added")) and ($now<(($j->"added")+120))) do={:return $targetName}
                :if (([$clockAlive ($j->"clock")]) and ($now<($j->"next"))) do={:return $targetName}
                :local delay ($j->"retry"); :if (([:typeof $delay]!="num") or ($delay<1) or ($delay>15)) do={:error "image: invalid retry clock"}
                :if (![$clockAlive ($j->"clock")]) do={:set ($j->"clock") [$makeClock]}
                :set ($j->"next") ($now+60*$delay); :set delay ($delay*2); :if ($delay>15) do={:set delay 15}; :set ($j->"retry") $delay
                :set saved [$save $j $jid $prefix $saved]
            }
            :if ((!$mine) and (($live->"image_id")!=($other->"image_id"))) do={ :error "image: container content differs" }
            :if (([:len $emergency]>0) and ([:len [/container/find where .id=($live->"id") and running]]=1)) do={:return $targetName}
            # A verified fallback must be available before stopping a working image.
            :if (!$restoring) do={:local backup [$imageTraffic "archive" $data $original]}
            :local rootChecked [$imageTraffic "root" $base ($live->"root") ($live->"id")]
            :local f [$checkGrant $grant]
            :local id ($live->"id"); :local oldTag ($live->"tag"); :local oldCode ($live->"image_id"); :set live [$imageTraffic "row" $profile]
            :if ((($live->"id")!=$id) or (($live->"tag")!=$oldTag) or (($live->"image_id")!=$oldCode)) do={:error "image: target changed before stop"}
            # Arm only after every preparatory batch and both archive checks.
            # This write-ahead decision covers the first stop, any cut during
            # extraction, and the candidate trial across subsequent boots.
            :if ($phase="prepare") do={
                :if (([:tostr $id]!=($j->"baseline")) or ($oldCode!=($original->"image_id")) or ((!$mayRemoveStopped) and ([:len [/container/find where .id=$id and running]]!=1)) or ($mayRemoveStopped and ([:len [/container/find where .id=$id and stopped]]!=1)) or ([/file/get $stateFile contents]!=($j->"old"))) do={:error "image: preparing baseline changed"}
                :set phase "replace"; :set ($j->"phase") $phase; :set ($j->"age") 0; :set ($j->"clock") [$makeClock]
                :set ($j->"seen") ([:tonsec [/system/resource/get uptime]]/1000000000); :set saved [$save $j $jid $prefix $saved]
                :set f [$checkGrant $grant]
            }
            :local offlineBase (($j->"offline")=true and (!$restoring) and (!$mine) and ([:tostr $id]=($j->"baseline")))
            :if ($offlineBase) do={
                :if ((!$mayRemoveStopped) or ([:len [/container/find where .id=$id and stopped]]!=1) or ([/file/get $stateFile contents]!=($j->"old"))) do={:error "image: offline rollback baseline changed"}
            } else={:if ([:len [/container/find where .id=$id and running]]=1) do={ /container/stop $id }}
            :local wait 0
            :while (([:len [/container/find where .id=$id and stopped]]=0) and ($wait<40)) do={:delay 250ms; :set wait ($wait+1)}
            :if (($wait=40) and (!$mine)) do={ :return $targetName }
            :set f [$checkGrant $grant]; :set live [$imageTraffic "row" $profile]
            :if ((($live->"id")!=$id) or (($live->"tag")!=$oldTag) or (($live->"image_id")!=$oldCode)) do={:error "image: target changed before removal"}
            :set rootChecked [$imageTraffic "root" $base ($live->"root") $id]
            # Removing a partial native row can also remove its live root.
            # After a reboot a directory recreated at the same path has no
            # association with the extraction. Require our root canary while
            # this incomplete row still refers to an existing directory.
            :if ($mine and ($oldCode="") and ([:len [/file/find where name=($live->"root")]]>0)) do={
                :if (![$imageRootWitness "read" (($live->"root") . $witnessPath) $oldTag]) do={:error "image: incomplete root ownership unknown"}
            }
            :if ($offlineBase and (([:len [/container/find where .id=$id and stopped]]!=1) or ([/file/get $stateFile contents]!=($j->"old")))) do={:error "image: offline rollback baseline changed"}
            /container/remove $id
            :set live [$imageTraffic "row" $profile]
        }
        :if ([:len $live]=0) do={
            # Re-read the selected bytes immediately before import, including
            # when the router restarted after removing the old native row.
            :set path [$imageTraffic "archive" $data $want]
            :local wait 0
            :while (([:len [/file/find where name=$root]]>0) and ($wait<16)) do={:delay 250ms; :set wait ($wait+1)}
            :if ([:len [/file/find where name=$root]]>0) do={
                # During an interrupted import a directory may outlive its
                # native row. Preserve it. Use only the absent, checked
                # alternative derived from the verified Docker config ID.
                :set root ($root . "-image-" . ($want->"image_id"))
                :if ([:len [/file/find where name=$root]]>0) do={:error "image: both extraction roots occupied"}
            }
            :local f [$checkGrant $grant]
            :if ([:len [$imageTraffic "row" $profile]]!=0) do={:error "image: slot acquired another container"}
            :local rootChecked [$imageTraffic "root" $base $root ""]
            :local importing ($staging->"candidate"); :if ($restoring) do={:set importing ($staging->"original")}
            :set ($j->"added") ([:tonsec [/system/resource/get uptime]]/1000000000)
            :set saved [$save $j $jid $prefix $saved]
            /container/add name=$targetName comment=$importing interface=$iface file=$path root-dir=$root mountlists=$targetName envlists=$targetName dns=$gateway memory-high=$high memory-max=$limit restart-policy=on-failure logging=no start-on-boot=no
            # A crash before this witness exists cannot authorize deletion of
            # an ambiguous surviving directory. An absent root is safe.
            :local n 0; :while (([:len [/file/find where name=$root]]=0) and ($n<20)) do={:delay 100ms; :set n ($n+1)}
            :if ([:len [/file/find where name=$root]]=1) do={
                :local claim [$imageTraffic "row" $profile]
                :if ((($claim->"tag")!=$importing) or (($claim->"root")!=$root)) do={:error "image: import identity changed"}
                :if (![$imageRootWitness "create" ($root . $witnessPath) $importing]) do={:error "image: incomplete root ownership unknown"}
            }
            :set wait 0
            # Extraction is neither running nor stopped. Query the two
            # independent flags just as the installer does.
            :while (([:len [/container/find where name=$targetName and comment=$importing and running]]=0) and ([:len [/container/find where name=$targetName and comment=$importing and stopped]]=0) and ($wait<120)) do={:delay 500ms; :set wait ($wait+1)}
            :if ($wait=120) do={ :return $targetName }
            :set live [$imageTraffic "row" $profile]
        }
        :if (($live->"image_id")!=($want->"image_id")) do={:error "image: import did not produce expected config ID"}
        :local id ($live->"id"); :local f [$checkGrant $grant]
        :if ([:len $emergency]=0) do={
            :if (($live->"partial")=true) do={ /container/set $id comment=$ownerTag start-on-boot=yes }
            :if ([:len [/container/find where .id=$id and stopped]]=1) do={
                :if ($component="tikray") do={ /container/unset $id cmd }
                /container/start $id
            }
        }
        :set phase "verify"; :if ($restoring) do={:set phase "recover"}
        :set ($j->"phase") $phase; :set saved [$save $j $jid $prefix $saved]
        :return $targetName
    }
    :if (($phase="verify") or ($phase="recover") or ($phase="commit")) do={
        :local live [$imageTraffic "row" $profile]
        :if (([:len $live]=0) and ($phase="recover")) do={
            # A reboot can interrupt extraction or remove a row before it
            # becomes usable. Retry from the original verified tar; never
            # remove an unexpected root to make room for the retry.
            :if (($now>=($j->"next")) or ($now<($j->"seen"))) do={
                :set ($j->"phase") "restore"; :set saved [$save $j $jid $prefix $saved]
            }
            :return $targetName
        }
        :if (($live->"image_id")!=($want->"image_id")) do={ :error "image: trial row changed" }
        :if ([:len [/container/find where .id=($live->"id") and running]]=1) do={
            :if ($component="tikray") do={
                :set healthy [$controlOK ($gateway+1) $gateway ({"installation_id"=$identity})]
            } else={
                :do { :set healthy ([/ping address=($gateway+2) src-address=$gateway count=1 interval=400ms]=1) } on-error={:set healthy false}
                :if ($healthy) do={
                    :set canRestart [$controlOK ($gateway+1) $gateway ({"installation_id"=$identity})]
                    # A matching echo is valid only for this running native
                    # row, request and archive. Never reuse a pre-reboot proof.
                    :local challenge [:rndstr length=32 from="0123456789abcdef"]
                    :local probe ($data . "/state/image-probe.request")
                    :local proof ($data . "/state/image-proved")
                    :local msg [:serialize to=json options=json.no-string-conversion value={"version"=1;"nonce"=$nonce;"digest"=($want->"digest");"challenge"=$challenge}]
                    :local pf [/file/find where name=$probe]
                    :if ([:len $pf]=0) do={ /file/add name=$probe type=file contents=$msg } else={
                        :if (([:len $pf]!=1) or ([/file/get $pf type]="directory")) do={:error "image: invalid probe file"}
                        /file/set [:pick $pf 0] contents=$msg
                    }
                    :set healthy false; :local wait 0
                    :local answer ($nonce . " " . ($want->"digest") . " " . $challenge)
                    :while ((!$healthy) and ($wait<25)) do={
                        :local ack [/file/find where name=$proof]
                        :if (([:len $ack]=1) and ([/file/get [:pick $ack 0] size]=[:len $answer])) do={:set healthy ([/file/get [:pick $ack 0] contents]=$answer)}
                        :if (!$healthy) do={ :delay 1s; :set wait ($wait+1) }
                    }
                }
            }
        }
        :if (!$healthy) do={
            # A partially rearmed image has lost positive health. Restore the
            # native cutoff before doing any further rollback or restart work.
            :if ($releasing and ([:len $emergency]=0)) do={
                :set ($j->"phase") "restore"; :set ($j->"flow") [:toarray ""]
                :set saved [$save $j $jid $prefix $saved]; :set ($grant->"flow") ($j->"flow")
                :local held [$imageTraffic "hold" ($j->"traffic") ($gateway+2) $trafficLAN $checkGrant $grant false]
                :set ($j->"flow") $held; :set saved [$save $j $jid $prefix $saved]; :return $targetName
            }
            :if ($phase="commit") do={:set ($j->"phase") "restore"; :set saved [$save $j $jid $prefix $saved]}
            # A previously verified image can also fail. Keep both archives
            # and the request, backing off between attempts on this one row.
            :if ($canRestart and ([:len $emergency]=0) and ($phase="recover") and (($now>=($j->"next")) or ($now<($j->"seen")))) do={
                :local retry ($j->"retry"); :if (([:typeof $retry]!="num") or ($retry<1) or ($retry>15)) do={:error "image: invalid recovery backoff"}
                :set ($j->"seen") $now; :set ($j->"next") ($now+($retry*60)); :set retry ($retry*2)
                :if ($retry>15) do={:set retry 15}; :set ($j->"retry") $retry
                :set saved [$save $j $jid $prefix $saved]
                :local f [$checkGrant $grant]; :local id ($live->"id")
                :if ([:len [/container/find where .id=$id and running]]=1) do={/container/stop $id}
                :local waited 0; :while (([:len [/container/find where .id=$id and stopped]]=0) and ($waited<40)) do={ :delay 250ms; :set waited ($waited+1) }
                :set f [$checkGrant $grant]; :local retryRow [$imageTraffic "row" $profile]
                :if ((($retryRow->"id")=$id) and (($retryRow->"image_id")=($want->"image_id")) and ([:len [/container/find where .id=$id and stopped]]=1)) do={/container/start $id}
            }
            :return $targetName
        }
        :local again [$imageTraffic "row" $profile]; :local f [$checkGrant $grant]
        :if ((($live->"id")!=($again->"id")) or (($again->"image_id")!=($want->"image_id")) or ([:len [/container/find where .id=($again->"id") and running]]!=1)) do={:error "image: trial identity changed"}
        :if ($again->"partial") do={
            # While suspended the owner explicitly started this verified row.
            # Only after positive health restore its normal identity.
            /container/set ($again->"id") comment=$ownerTag start-on-boot=yes
        }
        :if ($restoring) do={:set phase "reverted"} else={:set phase "commit"}
        :set ($j->"phase") $phase; :set saved [$save $j $jid $prefix $saved]
    }
    :if ($phase="commit") do={
        :local body [:serialize to=json options=json.no-string-conversion value={"version"=1;"installation_id"=$identity;"active"=$candidate;"previous"=$original}]
        :if ((![$sameRef $installed $original]) and (![$sameRef $installed $candidate])) do={:error "image: committed lineage changed"}
        :if (([:len [/file/find where name=$statePath and .id=$stateFile]]!=1) or ([/file/get $stateFile contents]!=$oldState)) do={:error "image: committed lineage changed"}
        :if ($oldState!=$body) do={ /file/set $stateFile contents=$body }
        :local state [$jsonFile $statePath]
        :if ((![$sameRef ($state->"active") $candidate]) or (![$sameRef ($state->"previous") $original])) do={:error "image: commit readback failed"}
        :set ($j->"phase") "committed"; :set saved [$save $j $jid $prefix $saved]; :set phase "committed"
    }
    :if (($phase="committed") or ($phase="reverted")) do={
        :local live [$imageTraffic "row" $profile]
        :if (($live->"image_id")!=($want->"image_id")) do={:error "image: completion identity changed"}
        :local f [$checkGrant $grant]
        :if (($phase="reverted") and ($oldState!=($j->"old"))) do={
            :if (($currentOK and (![$sameRef $installed $candidate])) or ([:len [/file/find where name=$statePath and .id=$stateFile]]!=1) or ([/file/get $stateFile contents]!=$oldState)) do={:error "image: rollback lineage changed"}
            /file/set $stateFile contents=($j->"old")
            :if ([/file/get $stateFile contents]!=($j->"old")) do={:error "image: cannot verify restored lineage"}
        }
        :if (($j->"fenced")=true) do={:local released [$imageTraffic "release" ($j->"traffic") ($gateway+2) $trafficLAN $checkGrant $grant ([:len $emergency]>0)]
            :set ($j->"flow") $released; :set saved [$save $j $jid $prefix $saved]
            :if (($released->"done")!=true) do={:return $targetName}
        }
        :foreach item in={"image-probe.request";"image-proved"} do={
            :local proofPath ($data . "/state/" . $item); :local proofID [/file/find where name=$proofPath]
            :if ([:len $proofID]=1) do={
                :local owned false
                :if ([/file/get $proofID size]<=4096) do={
                    :local value [/file/get $proofID contents]
                    :if ($item="image-proved") do={:set owned ([:pick $value 0 33]=($nonce . " "))} else={
                        :do { :local parsed [:deserialize from=json options=json.no-string-conversion value=$value]; :set owned (($parsed->"nonce")=$nonce) } on-error={}
                    }
                }
                :if ($owned) do={/file/remove [:pick $proofID 0]}
            }
        }
        :set f [$checkGrant $grant]
        /file/remove $rid
        :if ([:len [/file/find where name=$pending and .id=$rid]]!=0) do={:error "image: completion not persisted"}
        :if ([$clockAlive ($j->"clock")]) do={/system/script/job/remove [:toid ($j->"clock"->"job")]}
        :if ([/system/script/get $jid comment]=$saved) do={ /system/script/remove $jid }
        :log info ("tikray: image " . $phase . " " . $targetName)
    }
    :return $targetName
}
