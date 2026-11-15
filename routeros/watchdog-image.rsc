# The service publishes one immutable, authenticated request. Only this owner
# scheduler operates the container; its native phase survives either image.
:local wdImage do={
    :local data $1; :local identity $2; :local gateway $3
    :local controlOK $4; :local stopCheck $5
    :local pending ($data . "/state/image-update.json")
    :local phaseName "tikray-image-transition"; :local prefix "tikray:image-transition "
    :local files [/file/find where name=$pending]
    :local journals [/system/script/find where name=$phaseName or comment~"^tikray:image-transition "]
    :if (([:len $files]=0) and ([:len $journals]=0)) do={ :return "" }
    :local hexOK do={
        :return (([:typeof $1]="str") and ([:len $1]=$2) and ($1~"^[0-9a-f]+\$"))
    }
    :local jsonFile do={
        :local rows [/file/find where name=$1]
        :if ([:len $rows]!=1) do={ :error "image: missing proof" }
        :local id [:pick $rows 0]
        :if (([/file/get $id size]>4096) or ([/file/get $id type]="directory")) do={ :error "image: invalid proof" }
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
    :if (([:len $req]!=10) or (($req->"version")!=1) or (($req->"phase")!="requested") or (($req->"installation_id")!=$identity) or (![$hexOK $nonce 32]) or (![$hexOK ($req->"selection_digest") 64]) or (($component!="tikray") and ($component!="runner")) or ([:typeof ($req->"started")]!="num") or (($req->"started")<=0) or ([:typeof ($req->"deadline")]!="num") or ((($req->"deadline")-($req->"started"))!=300)) do={ :error "image: invalid request" }
    :if ((![$validRef $original $hexOK $component]) or (![$validRef $candidate $hexOK $component]) or (($candidate->"digest")=($original->"digest")) or (($candidate->"image_id")=($original->"image_id"))) do={ :error "image: invalid archive identities" }
    :if ((!($data~"^[A-Za-z0-9][A-Za-z0-9_-]*/tikray(-[A-Za-z0-9_][A-Za-z0-9_-]*)?/data\$")) or ([:len [/file/find where name=($data . "/state/install.id") and contents=$identity]]!=1)) do={ :error "image: control volume changed" }
    :local checkMounts do={
        :local data $1; :local install $2
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
                    :if ((($row->"name")!=$listName) or (($row->"comment")!=$expected) or ([:tostr ($row->"interface")]!=$port)) do={:error "image: shared private mount"}
                }
            }
        }
        :return true
    }
    :local scopeVerified [$checkMounts $data $identity]
    :local arch [/system/resource/get architecture-name]; :if ($arch="x86_64") do={:set arch "amd64"}
    :local boot [$jsonFile ($data . "/state/image-bootstrap.json")]
    :if ((($boot->"version")!=1) or (($boot->"arch")!=$arch) or (![$validRef ($boot->$component) $hexOK $component])) do={ :error "image: bootstrap proof unavailable" }
    :local statePath ($data . "/state/image-" . $component . ".json")
    :local states [/file/find where name=$statePath]
    :if (([:len $states]!=1) or ([/file/get [:pick $states 0] type]="directory") or ([/file/get [:pick $states 0] size]>4096)) do={:error "image: current receipt unavailable"}
    :local stateFile [:pick $states 0]; :local oldState [/file/get $stateFile contents]
    :local installed; :local currentOK false
    :do {
        :local state [$jsonFile $statePath]; :local prior ($state->"previous")
        :if ((($state->"version")=1) and (($state->"installation_id")=$identity) and ([$validRef ($state->"active") $hexOK $component]) and (([:typeof $prior]="nil") or ([:typeof $prior]="nothing") or ([$validRef $prior $hexOK $component]))) do={
            :set installed ($state->"active"); :set currentOK true
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
    :local profile {"component"=$component;"name"=$targetName;"tag"=$ownerTag;"veth"=$iface;"root"=$root;"gateway"=$gateway;"high"=$high;"max"=$limit}
    :local checkRoot do={
        :local base $1; :local root $2; :local ownID $3
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
    # The Docker config digest identifies the extracted image; a display tag
    # or an incomplete extracting row cannot authorize a destructive action.
    :local rowOf do={
        :local p $1; :local n ($p->"name"); :local c ($p->"tag"); :local v ($p->"veth"); :local rootPath ($p->"root")
        :local rows [/container/find where name=$n or comment=$c or interface=$v or root-dir=$rootPath or root-dir=("/" . $rootPath)]
        :if ([:len $rows]=0) do={ :return [:toarray ""] }
        :if ([:len $rows]!=1) do={ :error "image: conflicting container identities" }
        :local id [:pick $rows 0]; :local row [/container/get $id]
        :local path [:tostr ($row->"root-dir")]; :if ([:pick $path 0 1]="/") do={:set path [:pick $path 1 [:len $path]]}
        :if ((($row->"name")!=$n) or (($row->"comment")!=$c) or ([:tostr ($row->"interface")]!=$v) or ($path!=$rootPath) or ([:tostr ($row->"mountlists")]!=$n) or ([:tostr ($row->"envlists")]!=$n) or ([:tostr ($row->"dns")]!=[:tostr ($p->"gateway")]) or ([:len ($row->"entrypoint")]>0) or (($row->"logging")=true) or ([:len ($row->"devices")]>0) or (($row->"privileged")=true)) do={ :error "image: unverified container configuration" }
        :if (([:len ($row->"cmd")]>0) and ((($p->"component")!="tikray") or ([:tostr ($row->"cmd")]!="serve"))) do={ :error "image: owner command differs" }
        :if ((($row->"memory-high")!=($p->"high")) or (($row->"memory-max")!=($p->"max")) or ([:tostr ($row->"restart-policy")]!="on-failure") or (($row->"start-on-boot")!=true)) do={ :error "image: owner lifecycle settings differ" }
        :local code [:tostr ($row->"image-id")]; :if ([:pick $code ([:len $code]-1) [:len $code]]=" ") do={:set code [:pick $code 0 ([:len $code]-1)]}; :if ([:pick $code 0 7]="sha256:") do={:set code [:pick $code 7 [:len $code]]}
        :return {"id"=$id;"image_id"=$code}
    }
    :local checkArchive do={
        :local path ($1 . "/images/" . ($2->"component") . "-" . ($2->"digest") . ".tar")
        :local ids [/file/find where name=$path]
        :if ([:len $ids]!=1) do={ :error "image: archive unavailable" }
        :local id [:pick $ids 0]; :local size ($2->"size")
        :if (([/file/get $id size]!=$size) or ([/file/get $id type]="directory")) do={:error "image: archive length changed"}
        :local chain ""
        :for off from=0 to=($size-1) step=16384 do={
            :local n 16384; :if (($off+$n)>$size) do={:set n ($size-$off)}
            :local chunk ([/file/read file=$path offset=$off chunk-size=$n as-value]->"data")
            :if ([:len $chunk]!=$n) do={:error "image: incomplete archive"}
            :local h [:convert [:convert $chunk from=raw transform=sha512 to=hex] transform=lc]
            :set chain [:convert [:convert ($chain . $h) from=raw transform=sha512 to=hex] transform=lc]
        }
        :if (($chain!=($2->"chain")) or ([/file/get $id size]!=$size) or ([:len [/file/find where .id=$id and name=$path]]!=1)) do={:error "image: archive content changed"}
        :return $path
    }
    :local fence do={
        :local paused $1; :local path $2; :local id $3
        :local mounts $5
        :if ((![$mounts $6 $7]) or ([$paused "restart"]) or ([:len [/file/find where name=$path and .id=$id]]!=1) or ([/file/get $id contents]!=$4)) do={ :error "image: update request changed" }
        :return true
    }
    # Use only time spent on a boot. Repeated manual ticks within one
    # second add nothing. A lower uptime starts a new boot; a greater
    # uptime gives a safe lower bound even if the wall clock was changed.
    :local advanceAge do={
        :local elapsed ($3-$2)
        :if ($elapsed<0) do={:set elapsed $3}
        :local age ($1+$elapsed)
        :if ($age>300) do={:set age 300}
        :return $age
    }
    :local now ([:tonsec [/system/resource/get uptime]]/1000000000)
    :if ([:len $journals]=0) do={
        :if (![$sameRef $installed $original]) do={:error "image: stale previous selection"}
        :local live [$rowOf $profile]
        :if (($live->"image_id")!=($original->"image_id")) do={:error "image: installed bytes differ"}
        :local a [$checkArchive $data $original]
        :local firstPhase "replace"
        :do { :local b [$checkArchive $data $candidate] } on-error={ :set firstPhase "recover"; :log warning "tikray: candidate image integrity refused" }
        :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
        :set now ([:tonsec [/system/resource/get uptime]]/1000000000)
        :set j {"v"=1;"install"=$identity;"nonce"=$nonce;"component"=$component;"request"=$requestHash;"phase"=$firstPhase;"age"=0;"seen"=$now;"old"=$oldState;"receipt"=[:tostr $stateFile];"retry"=1;"next"=0}
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
    :if ([:typeof [:find {"replace";"verify";"restore";"recover";"commit";"committed";"reverted"} $phase]]!="num") do={:error "image: invalid transition phase"}
    :if (([:typeof ($j->"age")]!="num") or (($j->"age")<0) or (($j->"age")>300) or ([:typeof ($j->"seen")]!="num") or (($j->"seen")<0)) do={:error "image: invalid native timer"}
    :if (($phase="replace") or ($phase="verify")) do={
        :local age [$advanceAge ($j->"age") ($j->"seen") $now]
        :set ($j->"age") $age; :set ($j->"seen") $now
        :if ($age>=300) do={:set phase "restore"; :set ($j->"phase") $phase}
        :set saved [$save $j $jid $prefix $saved]
    }
    # If the last boot died between the durable verdict and retiring the
    # request, require fresh health again before exposing a terminal result.
    :if ($phase="committed") do={:set phase "commit"}
    :if ($phase="reverted") do={:set phase "recover"}
    :local restoring (($phase="restore") or ($phase="recover") or ($phase="reverted"))
    :local want $candidate; :local other $original
    :if ($restoring) do={:set want $original; :set other $candidate}
    :local healthy false
    :if (($phase="replace") or ($phase="restore")) do={
        :local path ""
        :do { :set path [$checkArchive $data $want] } on-error={
            :if ($restoring) do={ :error "image: restoration archive unavailable" }
            :set ($j->"phase") "restore"; :set saved [$save $j $jid $prefix $saved]
            :return $targetName
        }
        :local live [$rowOf $profile]
        :if (([:len $live]>0) and (($live->"image_id")!=($want->"image_id"))) do={
            :if (($live->"image_id")!=($other->"image_id")) do={ :error "image: container content differs" }
            # A verified fallback must be available before stopping a working image.
            :if (!$restoring) do={:local backup [$checkArchive $data $original]}
            :local rootChecked [$checkRoot $base $root ($live->"id")]
            :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
            :local id ($live->"id"); :set live [$rowOf $profile]
            :if ((($live->"id")!=$id) or (($live->"image_id")!=($other->"image_id"))) do={:error "image: target changed before stop"}
            :if ([:len [/container/find where .id=$id and running]]=1) do={ /container/stop $id }
            :local wait 0
            :while (([:len [/container/find where .id=$id and stopped]]=0) and ($wait<40)) do={:delay 250ms; :set wait ($wait+1)}
            :if ($wait=40) do={ :return $targetName }
            :set f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]; :set live [$rowOf $profile]
            :if ((($live->"id")!=$id) or (($live->"image_id")!=($other->"image_id"))) do={:error "image: target changed before removal"}
            :set rootChecked [$checkRoot $base $root $id]
            /container/remove $id
            :set live [$rowOf $profile]
        }
        :if ([:len $live]=0) do={
            # Re-read the selected bytes immediately before import, including
            # when the router restarted after removing the old native row.
            :set path [$checkArchive $data $want]
            :local wait 0
            :while (([:len [/file/find where name=$root]]>0) and ($wait<40)) do={:delay 250ms; :set wait ($wait+1)}
            :if ($wait=40) do={ :error "image: extraction root did not retire" }
            :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
            :if ([:len [$rowOf $profile]]!=0) do={:error "image: slot acquired another container"}
            :local rootChecked [$checkRoot $base $root ""]
            /container/add name=$targetName comment=$ownerTag interface=$iface file=$path root-dir=$root mountlists=$targetName envlists=$targetName dns=$gateway memory-high=$high memory-max=$limit restart-policy=on-failure logging=no start-on-boot=yes
            :set wait 0
            # Extraction is neither running nor stopped. Query the two
            # independent flags just as the installer does.
            :while (([:len [/container/find where name=$targetName and comment=$ownerTag and running]]=0) and ([:len [/container/find where name=$targetName and comment=$ownerTag and stopped]]=0) and ($wait<120)) do={:delay 500ms; :set wait ($wait+1)}
            :if ($wait=120) do={ :return $targetName }
            :set live [$rowOf $profile]
        }
        :if (($live->"image_id")!=($want->"image_id")) do={:error "image: import did not produce expected config ID"}
        :local id ($live->"id"); :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
        :if ($component="tikray") do={ /container/unset $id cmd }
        :if ([:len [/container/find where .id=$id and stopped]]=1) do={ /container/start $id }
        :set phase "verify"; :if ($restoring) do={:set phase "recover"}
        :set ($j->"phase") $phase; :set saved [$save $j $jid $prefix $saved]
        :return $targetName
    }
    :if (($phase="verify") or ($phase="recover") or ($phase="commit")) do={
        :local live [$rowOf $profile]
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
                    # A matching echo is valid only for this running native
                    # row, request and archive. Never reuse a pre-reboot proof.
                    :local challenge [:rndstr length=32 from="0123456789abcdef"]
                    :local probe ($data . "/state/image-probe.json")
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
            :if ($phase="commit") do={:set ($j->"phase") "restore"; :set saved [$save $j $jid $prefix $saved]}
            # A previously verified image can also fail. Keep both archives
            # and the request, backing off between attempts on this one row.
            :if (($phase="recover") and (($now>=($j->"next")) or ($now<($j->"seen")))) do={
                :local retry ($j->"retry"); :if (([:typeof $retry]!="num") or ($retry<1) or ($retry>15)) do={:error "image: invalid recovery backoff"}
                :set ($j->"seen") $now; :set ($j->"next") ($now+($retry*60)); :set retry ($retry*2)
                :if ($retry>15) do={:set retry 15}; :set ($j->"retry") $retry
                :set saved [$save $j $jid $prefix $saved]
                :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]; :local id ($live->"id")
                :if ([:len [/container/find where .id=$id and running]]=1) do={/container/stop $id}
                :local waited 0; :while (([:len [/container/find where .id=$id and stopped]]=0) and ($waited<40)) do={ :delay 250ms; :set waited ($waited+1) }
                :set f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]; :local retryRow [$rowOf $profile]
                :if ((($retryRow->"id")=$id) and (($retryRow->"image_id")=($want->"image_id")) and ([:len [/container/find where .id=$id and stopped]]=1)) do={/container/start $id}
            }
            :return $targetName
        }
        :local again [$rowOf $profile]; :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
        :if ((($live->"id")!=($again->"id")) or (($again->"image_id")!=($want->"image_id")) or ([:len [/container/find where .id=($again->"id") and running]]!=1)) do={:error "image: trial identity changed"}
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
        :local live [$rowOf $profile]
        :if (($live->"image_id")!=($want->"image_id")) do={:error "image: completion identity changed"}
        :local f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
        :if (($phase="reverted") and ($oldState!=($j->"old"))) do={
            :if (($currentOK and (![$sameRef $installed $candidate])) or ([:len [/file/find where name=$statePath and .id=$stateFile]]!=1) or ([/file/get $stateFile contents]!=$oldState)) do={:error "image: rollback lineage changed"}
            /file/set $stateFile contents=($j->"old")
            :if ([/file/get $stateFile contents]!=($j->"old")) do={:error "image: cannot verify restored lineage"}
        }
        :foreach item in={"image-probe.json";"image-proved"} do={
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
        :set f [$fence $stopCheck $pending $rid $requestText $checkMounts $data $identity]
        /file/remove $rid
        :if ([:len [/file/find where name=$pending and .id=$rid]]!=0) do={:error "image: completion not persisted"}
        :if ([/system/script/get $jid comment]=$saved) do={ /system/script/remove $jid }
        :log info ("tikray: image " . $phase . " " . $targetName)
    }
    :return $targetName
}
