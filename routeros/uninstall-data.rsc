:local cleanData do={
    :local op $1; :local choice $2; :local data $3; :local identity $4; :local phase $5; :local subnet $6; :local checkLease $7; :local lease $8
    :if ($data = "") do={ :if ($choice="purge") do={ :error "tikray: shared_reference_refuses; purge root absent" }; :return true }
    :local prefix ($data . "/")
    :if (!($data ~ "^[A-Za-z0-9][A-Za-z0-9_-]*/tikray(-[A-Za-z0-9_][A-Za-z0-9_-]*)?/data\$") or ([:len $identity] != 32) or (!($identity ~ "^[0-9a-f]+\$"))) do={ :error "tikray: shared_reference_refuses; unverified data path" }
    :local root [/file/find where name=$data]; :local body ($data . "/state/install.id")
    :if ([:len $root] = 0) do={ :if (($phase = "empty") and ($choice="purge")) do={ :return true }; :error "tikray: shared_reference_refuses; data root missing" }
    :if (([:len $root] != 1) or ([/file/get $root type] != "directory")) do={ :error "tikray: shared_reference_refuses; data root changed" }
    :local original [/file/find where name=$body]
    :if ([:len $original] = 1) do={ :if ([/file/get $original contents] != $identity) do={ :error "tikray: shared_reference_refuses; data root identity changed" } } else={
        :if (($phase != "files") and ($phase != "empty")) do={ :error "tikray: shared_reference_refuses; original data marker missing" }
    }
    :local kept ($data . "/install.retained"); :local retained [/file/find where name=$kept]
    :local contents [:serialize to=json options=json.no-string-conversion value={"version"=1;"data"=$data;"installation_id"=$identity;"subnet"=$subnet}]
    :if (([:len $retained] > 0) and (([:len $retained] != 1) or ([/file/get $retained contents] != $contents))) do={ :error "tikray: shared_reference_refuses; retention identity differs" }
    :if ($choice="keep") do={
        :if (([:len $original]=0) and ([:len $retained]=0)) do={ :error "tikray: shared_reference_refuses; missing retained-data proof" }
        # The two current-image receipts bind the initial publisher
        # handoff to this installation. Refuse unrelated or conflicting files.
        # @TIKRAY_IMAGE_REFERENCE@
        :local readRecord do={
            :local recPath $1; :local found [/file/find where name=$recPath]
            :if ([:len $found]=0) do={:return [:toarray ""]}
            :if (([:len $found]!=1) or ([/file/get $found type]="directory") or ([/file/get $found size]>4096) or ([/file/get $found name]!=$recPath)) do={:error "tikray: shared_reference_refuses; image receipt conflict"}
            :return {"id"=[:pick $found 0];"path"=$recPath;"text"=[/file/get $found contents]}
        }
        :local parseRecord do={
            :local p; :do {:set p [:deserialize from=json options=json.no-string-conversion value=($1->"text")]} on-error={:error "tikray: shared_reference_refuses; image receipt conflict"}
            :return $p
        }
        :local bootFile [$readRecord ($prefix . "state/image-bootstrap.receipt")]; :local boot
        :if ([:len $bootFile]>0) do={
            :set boot [$parseRecord $bootFile]
            :local arch [/system/resource/get architecture-name]; :if ($arch="x86_64") do={:set arch "amd64"}
            :local pub ($boot->"publisher"); :local der ""
            :if (([:typeof $pub]="str") and ([:len $pub]=124)) do={:do {:set der [:convert [:convert $pub from=base64 to=hex] transform=lc]} on-error={}}
            :if (([:len $boot]!=5) or (($boot->"version")!=1) or (($boot->"arch")!=$arch) or ([:len $der]!=182) or ([:pick $der 0 54]!="3059301306072a8648ce3d020106082a8648ce3d03010703420004") or (![$validRef ($boot->"tikray") "tikray"]) or (![$validRef ($boot->"runner") "runner"])) do={:error "tikray: shared_reference_refuses; image bootstrap conflict"}
        }
        :local records [:toarray ""]
        :local resuming (([:len $retained]=1) and (($phase="files") or ($phase="empty")))
        :foreach side in={"tikray";"runner"} do={
            :local file [$readRecord ($prefix . "state/image-" . $side . ".receipt")]
            :if ([:len $file]>0) do={
                :local row [$parseRecord $file]; :local active ($row->"active"); :local prior ($row->"previous")
                :if (([:len $bootFile]=0) or ([:len $row]!=4) or (($row->"version")!=1) or (($row->"installation_id")!=$identity) or (![$validRef $active $side])) do={:error "tikray: shared_reference_refuses; image receipt conflict"}
                :if (([:typeof $prior]="nil") or ([:typeof $prior]="nothing")) do={
                    :local seed ($boot->$side)
                    :foreach key in={"component";"digest";"chain";"size";"image_id"} do={:if (($active->$key)!=($seed->$key)) do={:error "tikray: shared_reference_refuses; image receipt conflict"}}
                } else={
                    :if ((![$validRef $prior $side]) or (($prior->"digest")=($active->"digest")) or (($prior->"image_id")=($active->"image_id"))) do={:error "tikray: shared_reference_refuses; image receipt conflict"}
                }
                :set ($records->$side) $file
            } else={:if (([:len $bootFile]>0) and (!$resuming)) do={:error "tikray: shared_reference_refuses; image receipt missing"}}
        }
        :if ($op="apply") do={
            :if ([:len $retained] = 0) do={ $checkLease $lease; /file/add name=$kept type=file contents=$contents }
            :if ([:len [/file/find where name=$kept and contents=$contents]] != 1) do={ :error "tikray: could not verify retention receipt" }
            # Keep the bootstrap anchor until all of its dependent receipts
            # are retired. A resumed keep can still authenticate either side.
            :local retire do={
                :local snap $1; :local check $2; :local id ($snap->"id"); :local recPath ($snap->"path")
                $check $3
                :if (([:len [/file/find where name=$recPath and .id=$id]]!=1) or ([/file/get $id size]>4096) or ([/file/get $id contents]!=($snap->"text"))) do={:error "tikray: shared_reference_refuses; image receipt changed"}
                /file/remove $id
            }
            :foreach side,snap in=$records do={$retire $snap $checkLease $lease}
            :if ([:len $bootFile]>0) do={$retire $bootFile $checkLease $lease}
            # Only installation admission and RouterOS identity are retired;
            # the owner's configuration, account, core and TLS identity remain.
            :foreach rel in={"install.check";"install.json";"state/install.checked";"state/install.attempt";"state/install.ready";"state/router-policy.json";"state/routeros.json";"state/install.request";"state/install.id"} do={
                :local fn ($prefix . $rel); :local ids [/file/find where name=$fn]
                :if ([:len $ids] > 0) do={ :if (([:len $ids] != 1) or ([/file/get $ids type]="directory") or ([/file/get $ids name] != $fn)) do={ :error "tikray: shared_reference_refuses; installer record changed" }; $checkLease $lease; /file/remove [:pick $ids 0] }
            }
        }
        :return true
    }
    # Work by verified names and native IDs from a fixed root. Never issue a
    # recursive removal of a populated directory, a drive, or a mount point.
    :local collect do={
        :local dir $1; :local proof $2
        :local allowed [:toarray ""]
        :foreach id in=[/file/find where name~("^" . $dir . "/")] do={
            :local fn [/file/get $id name]; :local kind [/file/get $id type]; :local start ($dir . "/")
            :if (([:pick $fn 0 [:len $start]] != $start) or ([:typeof [:find ($fn . "/") "/../"]] = "num") or ([:typeof [:find ($fn . "/") "/./"]] = "num") or ([:typeof [:find $fn "//"]] = "num") or ([:len $fn] > 1024) or ($kind="disk") or ($kind~"link") or ($kind~"mount")) do={ :error "tikray: shared_reference_refuses; unsafe data entry" }
            :if ($fn != $proof) do={ :set ($allowed->[:len $allowed]) {"id"=$id;"name"=$fn;"type"=$kind} }
        }
        :return $allowed
    }
    :foreach mount in=[/disk/find] do={
        :local p [:tostr [/disk/get $mount mount-point]]
        :if (($p=$data) or ([:pick $p 0 [:len $prefix]]=$prefix)) do={ :error "tikray: shared_reference_refuses; nested disk" }
    }
    :local entries [$collect $data $body]
    :if ([:len $original] = 0) do={
        :foreach item in=$entries do={ :if ((($item->"name") != ($data . "/state")) or (($item->"type") != "directory")) do={ :error "tikray: shared_reference_refuses; data reappeared without identity" } }
        # A killed purge may already have removed the proof. Owner-created
        # replacement directories at the same path cannot then be identified.
        :if ($phase!="empty") do={ :error "tikray: shared_reference_refuses; purge identity disappeared" }
        :if ($op="empty") do={ :put "tikray: data proof retired; preserved unverified empty directories"; :return true }
    }
    :if ($op="inspect") do={ :return true }
    :if ($op="apply") do={
        :for depth from=0 to=63 do={
            :local changed false; :local left 0
            :set entries [$collect $data $body]
            :foreach item in=$entries do={
                :local id ($item->"id"); :local fn ($item->"name"); :local kind ($item->"type")
                :if (($fn != ($data . "/state")) or ($kind != "directory")) do={
                    :set left ($left+1)
                    :local safe true
                    :if ($kind="directory") do={
                        :foreach child in=$entries do={ :if ([:pick ($child->"name") 0 ([:len $fn]+1)] = ($fn . "/")) do={ :set safe false } }
                    }
                    :if ($safe) do={
                        :local live [/file/find where name=$fn]
                        :if (([:len $live] != 1) or ([:pick $live 0] != $id) or ([/file/get $id type] != $kind) or ([/file/get $original contents] != $identity)) do={ :error "tikray: shared_reference_refuses; purge file changed" }
                        :if ($kind="directory") do={
                            :foreach c in=[/file/find where name~("^" . $data . "/")] do={ :if ([:pick [/file/get $c name] 0 ([:len $fn]+1)] = ($fn . "/")) do={ :error "tikray: directory changed during purge" } }
                        }
                        $checkLease $lease; /file/remove $id; :set changed true
                    }
                }
            }
            :if ($left=0) do={ :return true }
            :if (!$changed) do={ :error "tikray: cannot verify empty directory" }
        }
        :error "tikray: data depth exceeds uninstall limit"
    }
    :if ($op="empty") do={
        :foreach item in=$entries do={ :if ((($item->"name") != ($data . "/state")) or (($item->"type") != "directory")) do={ :error "tikray: shared_reference_refuses; unexpected data after purge" } }
        :if ([:len $original] = 1) do={ :if ([/file/get $original contents] != $identity) do={ :error "tikray: purge identity changed" }; $checkLease $lease; /file/remove $original }
        :local st [/file/find where name=($data . "/state") and type=directory]
        :if ([:len $st] = 1) do={
            :if ([:len [/file/find where name~("^" . $data . "/state/")]] > 0) do={ :error "tikray: data changed" }
            $checkLease $lease; /file/remove $st
        }
        :if (([:len [/file/find where name~("^" . $data . "/")]] > 0) or ([:len [/file/find where name=$data and type=directory]] != 1)) do={ :error "tikray: data changed" }
        $checkLease $lease; /file/remove $root
        :return true
    }
    :error "tikray: invalid data operation"
}
