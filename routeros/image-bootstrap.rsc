    # The package pins the public verifier and original tar, chunk-chain and
    # Docker config digests. Never infer a previous version from a live name.
    :local imageBaseline do={
        :local publish [:tobool $1]; :local data $2; :local base $3; :local arch $4; :local verify $5; :local checkLease $6; :local lease $7
        # @TIKRAY_IMAGE_CONSTANTS@
        :if (([:len [/file/find where name=($data . "/state/image-update.request")]]>0) or ([:len [/system/script/find where name="tikray-image-transition" or comment~"^tikray:image-transition"]] > 0)) do={ :error "tikray: image transition active; retry after watchdog recovery" }
        :local bundle [:deserialize from=json options=json.no-string-conversion value=$bootstrap]
        :local state ($data . "/state/")
        # Earlier development builds used protected JSON inputs. Leave any
        # such proof intact for the owner and refuse mixed image lineages.
        :foreach legacy in={"image-update.json";"image-bootstrap.json";"image-tikray.json";"image-runner.json";"image-probe.json"} do={
            :if ([:len [/file/find where name=($state . $legacy)]]>0) do={:error "tikray: prior image handoff present; inspect before retry"}
        }
        :local pinned [/file/find where name=($state . "image-bootstrap.receipt")]
        :if ([:len $pinned]>0) do={
            :if (([:len $pinned]!=1) or ([/file/get $pinned size]!=[:len $bootstrap]) or ([/file/get $pinned contents]!=$bootstrap)) do={ :error "tikray: installed image publisher or baseline differs" }
        }
        :local identity ""
        :local ids [/file/find where name=($state . "install.id")]
        :if ([:len $ids] = 1) do={ :set identity [/file/get [:pick $ids 0] contents] }
        :if (($publish or ([:len $pinned]>0)) and (([:len $identity]!=32) or (!($identity~"^[0-9a-f]+\$")))) do={ :error "tikray: cannot bind image state to this installation" }
        :local slots ($data . "/images")
        :if ($publish) do={
            :local dirs [/file/find where name=$slots]
            :if ([:len $dirs]=0) do={ $checkLease $lease; /file/add name=$slots type=directory }
            :if ([:len [/file/find where name=$slots and type=directory]]!=1) do={ :error "tikray: image slot directory conflict" }
        }
        :local validRef do={
            :local record $1
            :if (([:typeof $record]!="array") or ([:len $record]!=5) or (($record->"component")!=$2) or ([:typeof ($record->"size")]!="num") or (($record->"size")<1) or (($record->"size")>134217728)) do={:return false}
            :foreach field in={"image_id";"digest";"chain"} do={
                :local n 64; :if ($field="chain") do={:set n 128}
                :local v ($record->$field)
                :if (([:typeof $v]!="str") or ([:len $v]!=$n) or (!($v~"^[0-9a-f]+\$"))) do={:return false}
            }
            :return true
        }
        :foreach role in={"tikray";"runner"} do={
            :local componentName "tikray"; :if ($role="runner") do={ :set componentName "tikray-runner" }
            :local ref ($bundle->$role)
            :local current ($state . "image-" . $role . ".receipt")
            :local records [/file/find where name=$current]
            :local expectedID ($ref->"image_id")
            # Store a compact JSON string. RouterOS may serialize its native
            # array keys in another order, so inspect established receipts by field.
            :local initial ("{\"version\":1,\"installation_id\":\"" . $identity . "\",\"active\":" . [:serialize to=json options=json.no-string-conversion value=$ref] . ",\"previous\":null}")
            :if ([:len $pinned]>0) do={
                :if (([:len $records]!=1) or ([/file/get $records size]>4096)) do={ :error "tikray: installed image receipt missing; inspect before retry" }
                :local receipt [:deserialize from=json options=json.no-string-conversion value=[/file/get $records contents]]
                :local active ($receipt->"active"); :local prior ($receipt->"previous")
                :if (([:len $receipt]!=4) or (($receipt->"version")!=1) or (($receipt->"installation_id")!=$identity) or (![$validRef $active $role])) do={ :error "tikray: installed image receipt conflict" }
                :if (([:typeof $prior]="nil") or ([:typeof $prior]="nothing")) do={
                    # Only the first signed pair can have no predecessor.
                    :foreach field in={"component";"image_id";"digest";"chain";"size"} do={
                        :if (($active->$field)!=($ref->$field)) do={:error "tikray: installed image receipt conflict"}
                    }
                } else={
                    :if ((![$validRef $prior $role]) or (($prior->"image_id")=($active->"image_id")) or (($prior->"digest")=($active->"digest"))) do={:error "tikray: installed image receipt conflict"}
                }
                :set expectedID ($active->"image_id")
            } else={
                :if ([:len $records]>0) do={
                    :if (([:len $records]!=1) or ($identity="") or ([/file/get $records contents]!=$initial)) do={ :error "tikray: partial image baseline conflict" }
                }
            }
            :local ownedTag "tikray:tikray"; :if ($role="runner") do={ :set ownedTag "tikray:runner" }
            :local containers [/container/find where name=$componentName or comment=$ownedTag]
            :if ($publish or ([:len $pinned]>0) or ([:len $containers]>0)) do={
                :local owned [/container/find where name=$componentName and comment=$ownedTag]
                :if (([:len $owned]!=1) or ([:tostr $containers]!=[:tostr $owned])) do={ :error "tikray: image baseline container ownership conflict" }
                :local imageID [:tostr [/container/get [:pick $owned 0] image-id]]
                :if ([:pick $imageID 0 7]="sha256:") do={ :set imageID [:pick $imageID 7 [:len $imageID]] }
                :if (($imageID!=$expectedID) and ($imageID!=($expectedID . " "))) do={ :error "tikray: live image differs from verified archive" }
            }
            :if ($publish) do={
                :local path ($slots . "/" . $role . "-" . ($ref->"digest") . ".tar")
                :local destination [/file/find where name=$path]
                :if ([:len $destination]=0) do={
                    :local original ($base . "/images/" . $componentName . "-" . $arch . ".tar")
                    :local originalID [/file/find where name=$original]
                    :if ([:len $originalID]!=1) do={ :error "tikray: original image archive missing" }
                    :local incoming ($slots . "/initial-" . ($lease->"nonce") . "-" . $role . ".tar")
                    $checkLease $lease
                    :if ([:len [/file/find where name=$incoming]]!=0) do={ :error "tikray: image copy staging conflict" }
                    /file/copy [:pick $originalID 0] name=$incoming
                    :if ([$verify $componentName $incoming]!=true) do={ :error "tikray: copied initial image failed verification" }
                    :local copied [/file/find where name=$incoming]
                    $checkLease $lease
                    :if (([:len $copied]!=1) or ([:len [/file/find where name=$path]]!=0)) do={ :error "tikray: initial image changed during copy" }
                    /file/set [:pick $copied 0] name=$path
                }
                :if ([$verify $componentName $path]!=true) do={ :error "tikray: initial image archive is unverified" }
                :local sigPath ($path . ".sig")
                :local sig [$signatureFor $role]
                :if ([:len [/file/find where name=$sigPath]]=0) do={ $checkLease $lease; /file/add name=$sigPath type=file contents=$sig }
                :local signed [/file/find where name=$sigPath]
                :if (([:len $signed]!=1) or ([/file/get $signed contents]!=$sig)) do={ :error "tikray: initial image signature conflict" }
                :if ([:len $records]=0) do={ $checkLease $lease; /file/add name=$current type=file contents=$initial; :if ([/file/get [find where name=$current] contents]!=$initial) do={ :error "tikray: initial image receipt could not be verified" } }
            }
        }
        :if ($publish and ([:len $pinned]=0)) do={
            $checkLease $lease
            /file/add name=($state . "image-bootstrap.receipt") type=file contents=$bootstrap
            :if ([/file/get [find where name=($state . "image-bootstrap.receipt")] contents]!=$bootstrap) do={ :error "tikray: image trust could not be verified" }
        }
        :return true
    }
