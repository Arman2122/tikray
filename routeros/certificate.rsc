# Arguments: apply, router address, control address. A receipt never conveys
# ownership by certificate name alone. The proof precedes service attachment.
:local tls do={
    :local apply $1
    :local router $2
    :local control $3
    :local svc [/ip/service/find where name="api-ssl" and !dynamic]
    :if ([:len $svc] != 1) do={ :error "tikray: inspect api-ssl service before installation" }
    :set svc [:pick $svc 0]
    # Service readback can spell a single-host prefix with or without its
    # suffix. RouterOS can reorder entries. Keep original spelling for teardown
    # and compare the full set of grants, including IPv6, on retries.
    :local allowedList do={
        :local canonical [:toarray ""]
        :foreach item in=$1 do={
            :local entry [:tostr $item]
            :if (([:len $entry] != 0) and ([:typeof [:find $entry "/"]] != "num")) do={
                :if ([:typeof [:find $entry ":"]] != "num") do={ :set entry ($entry . "/32") } else={ :set entry ($entry . "/128") }
            }
            :if ([:len $entry] != 0) do={ :set ($canonical->$entry) true }
        }
        :return [:tostr $canonical]
    }
    # The field-level getter can give an empty address while the same native
    # service row contains live grants. Demand agreement with an independent
    # filtered print on the same static row before using any access setting.
    :local readService do={
        :local serviceId $1; :local canonicalize $2
        :local entire [/ip/service/get $serviceId]
        :if (([:typeof ($entire->"port")] != "num") or (($entire->"port") < 1) or (($entire->"port") > 65535) or ([:typeof ($entire->"disabled")] != "bool")) do={ :error "tikray: cannot verify api-ssl port or enabled state" }
        # CLI print calls the same field available-from. get calls it address.
        :local projected [/ip/service/print as-value where name="api-ssl" and !dynamic]
        :if ([:len $projected] != 1) do={ :error "tikray: cannot verify original api-ssl settings" }
        :local view [:pick $projected 0]
        :local grants ($view->"available-from"); :local usingAlias true
        :if (([:typeof $grants] = "nothing") or ([:typeof $grants] = "nil")) do={ :set usingAlias false; :set grants ($view->"address") }
        :if (([:typeof ($entire->"address")] != "array") or ([:typeof $grants] != "array")) do={ :error "tikray: cannot verify original api-ssl grant fields" }
        :if (([:tostr ($view->".id")] != [:tostr $serviceId]) or (($entire->"name") != "api-ssl") or ([:tostr ($entire->"port")] != [:tostr ($view->"port")]) or ([:tostr ($entire->"certificate")] != [:tostr ($view->"certificate")]) or ([:tostr ($entire->"disabled")] != [:tostr ($view->"disabled")]) or ([$canonicalize ($entire->"address")] != [$canonicalize $grants])) do={ :error "tikray: cannot verify original api-ssl settings" }
        :if ([:len ($entire->"address")] = 0) do={
            :local empty
            :if ($usingAlias) do={ :set empty [/ip/service/find where name="api-ssl" and !dynamic and available-from=""] } else={ :set empty [/ip/service/find where name="api-ssl" and !dynamic and address=""] }
            :if (([:len $empty] != 1) or ([:tostr [:pick $empty 0]] != [:tostr $serviceId])) do={ :error "tikray: cannot prove unrestricted api-ssl baseline" }
        }
        :return $entire
    }
    :local original [$readService $svc $allowedList]
    :local oldCert [:tostr ($original->"certificate")]
    :local oldDisabled ($original->"disabled")
    :local oldAddresses ($original->"address")
    :local port ($original->"port")
    :local alias "tikray-api"
    :local proofName "tikray-api-receipt"
    :local accessName "tikray-api-access"
    :local proofTag "tikray:api-receipt "
    :local accessTag "tikray:api-access "
    :local receipts [/system/script/find where name=$proofName or name=$accessName or comment~"^tikray:api-(receipt|access) "]
    :local baseline {"version"=1;"disabled"=$oldDisabled;"certificate"=$oldCert;"address"=[:tostr $oldAddresses];"original-addresses"=$oldAddresses;"port"=$port}
    :local desired $oldAddresses
    :local allowed ([:len $oldAddresses] = 0 and !$oldDisabled)
    :foreach prefix in=$oldAddresses do={
        :local s [:tostr $prefix]
        :if ([:typeof [:find $s ":"]] != "num") do={
            :local n 32; :local pos [:find $s "/"]
            :if ([:typeof $pos] = "num") do={ :set n [:tonum [:pick $s ($pos+1) [:len $s]]]; :set s [:pick $s 0 $pos] }
            :local m (255.255.255.255 << (32-$n))
            :if (([:toip $s] & $m) = ($control & $m)) do={ :set allowed true }
        }
    }
    :if (!$allowed) do={ :set desired ($oldAddresses,($control . "/32")) }
    :set ($baseline->"grant") [:tostr $desired]
    :set ($baseline->"addresses") $desired
    :local cert $oldCert
    :local created false
    :local incomplete false
    :local token $proofTag
    :local receiptName $proofName
    :local suitable do={
        :local id $1
        :if (([:typeof $id] != "id") and ([:len $id] != 1)) do={ :return false }
        :local c [/certificate/get $id]
        :return ((($c->"private-key") = true) and (($c->"expired") != true) and (($c->"revoked") != true) and ([:typeof [:find [:tostr ($c->"key-usage")] "tls-server"]] = "num") and ([:len ($c->"fingerprint")] = 64))
    }
    :if ([:len $receipts] > 1) do={ :error "tikray: inspect conflicting api-ssl receipts" }
    :if ([:len $receipts] = 1) do={
        :local id [:pick $receipts 0]
        :set created ([/system/script/get $id name] = $proofName)
        :if (!$created) do={ :set token $accessTag; :set receiptName $accessName }
        :local text [/system/script/get $id comment]
        :if (([/system/script/get $id name] != $receiptName) or ([:pick $text 0 [:len $token]] != $token) or ([:len [/system/script/get $id source]] > 0)) do={ :error "tikray: conflicting api-ssl receipt; inspect ownership" }
        :set baseline [:deserialize from=json value=[:pick $text [:len $token] [:len $text]] options=json.no-string-conversion]
        :if ((($baseline->"version") != 1) or (($baseline->"port") != $port)) do={ :error "tikray: api-ssl receipt no longer matches service" }
        :if ($created) do={ :set cert ($baseline->"name") } else={
            :if ((([:typeof ($baseline->"name")] != "nothing") and ([:typeof ($baseline->"name")] != "nil")) or (([:typeof ($baseline->"fingerprint")] != "nothing") and ([:typeof ($baseline->"fingerprint")] != "nil"))) do={ :error "tikray: invalid service access grant" }
            :set cert $oldCert
            :if (![$suitable [/certificate/find where name=$cert]]) do={
                :set cert ""
                :foreach candidate in=[/certificate/find] do={
                    :if ([$suitable $candidate]) do={
                        :if ($cert != "") do={ :error "tikray: choose an api-ssl certificate before installing" }
                        :set cert [/certificate/get $candidate name]
                    }
                }
            }
            :if ($cert = "") do={ :error "tikray: shared_reference_refuses; restore service certificate" }
        }
        :set desired ($baseline->"addresses")
        :local isOriginal (($oldCert = ($baseline->"certificate")) and ($oldDisabled = ($baseline->"disabled")) and ([:tostr $oldAddresses] = ($baseline->"address")))
        :local isInstalled (($oldCert = $cert) and (!$oldDisabled) and (([:tostr $oldAddresses] = ($baseline->"grant")) or ([$allowedList $oldAddresses] = [$allowedList $desired])))
        :if (!$isOriginal and !$isInstalled) do={ :error "tikray: shared_reference_refuses; api-ssl was changed by its owner" }
        :if ($created) do={
            :if ($cert != $alias) do={ :error "tikray: invalid certificate receipt" }
            :set incomplete ([:len ($baseline->"fingerprint")] = 0)
        }
        :if ($incomplete) do={
            :if ([:len [/certificate/find where name=$cert]] > 0) do={ :error "tikray: shared_reference_refuses; inspect certificate lacking completed fingerprint proof" }
        } else={
            :local id [/certificate/find where name=$cert]
            :if (![$suitable $id]) do={ :error "tikray: shared_reference_refuses; certificate identity changed" }
            :if ($created and ([/certificate/get $id fingerprint] != ($baseline->"fingerprint"))) do={ :error "tikray: shared_reference_refuses; certificate identity changed" }
        }
    } else={
        :if (![$suitable [/certificate/find where name=$cert]]) do={
            :if ((!$oldDisabled) and ($oldCert != "") and ($oldCert != "none")) do={ :error "tikray: repair the active api-ssl certificate before installing" }
            :set cert ""
            :foreach id in=[/certificate/find] do={
                :if ([$suitable $id]) do={
                    :if ($cert != "") do={ :error "tikray: choose an api-ssl certificate before installing" }
                    :set cert [/certificate/get $id name]
                }
            }
            :if ($cert = "") do={
                :if ([:len [/certificate/find where name=$alias]] > 0) do={ :error "tikray: reserved certificate name belongs to owner" }
                :set created true; :set incomplete true; :set cert $alias
            }
        }
        :if ($created) do={ :set ($baseline->"name") $cert; :set ($baseline->"fingerprint") "" } else={
            :set receiptName $accessName; :set token $accessTag
        }
        :if ($apply and ($created or $oldDisabled or ($cert != $oldCert) or ([:tostr $oldAddresses] != [:tostr $desired]))) do={
            /system/script/add name=$receiptName source="" policy=read comment=($token . [:serialize to=json options=json.no-string-conversion value=$baseline])
            :set receipts [/system/script/find where name=$receiptName]
        }
    }
    :if (!$apply) do={
        :if ($incomplete) do={ :return "" }
        :return [/certificate/get [:pick [/certificate/find where name=$cert] 0] fingerprint]
    }
    :if ($incomplete) do={
        /certificate/add name=$cert common-name=$cert subject-alt-name=("IP:" . $router) key-size=prime256v1 days-valid=3650 key-usage=key-cert-sign,digital-signature,tls-server
        /certificate/sign $cert
        :local id [/certificate/find where name=$cert]
        :if (![$suitable $id]) do={ :error "tikray: inspect certificate signing; api-ssl is unchanged" }
        :set ($baseline->"fingerprint") [/certificate/get $id fingerprint]
        /system/script/set $receipts comment=($token . [:serialize to=json options=json.no-string-conversion value=$baseline])
    }
    :local selected [/certificate/find where name=$cert]
    :if (![$suitable $selected]) do={ :error "tikray: shared_reference_refuses; certificate identity changed" }
    :local selectedId [:pick $selected 0]
    :local pin [/certificate/get $selectedId fingerprint]
    :if (($created and ($pin != ($baseline->"fingerprint"))) or (([:len $4] > 0) and ($pin != $4))) do={ :error "tikray: shared_reference_refuses; certificate identity changed" }
    :if (($oldCert != $cert) or $oldDisabled or ([$allowedList $oldAddresses] != [$allowedList $desired])) do={
        :local fresh [$readService $svc $allowedList]
        :if ((($fresh->"port") != $port) or ([:tostr ($fresh->"certificate")] != $oldCert) or (($fresh->"disabled") != $oldDisabled) or ([$allowedList ($fresh->"address")] != [$allowedList $oldAddresses])) do={ :error "tikray: shared_reference_refuses; api-ssl changed during installation" }
        /ip/service/set $svc certificate=$cert address=$desired disabled=no
        :local checked [$readService $svc $allowedList]
        :if (([:tostr ($checked->"certificate")] != $cert) or (($checked->"disabled") = true) or ([$allowedList ($checked->"address")] != [$allowedList $desired])) do={ :error "tikray: shared_reference_refuses; verify api-ssl service grants" }
    }
    :local after [/certificate/find where name=$cert]
    :if (([:len $after] != 1) or ([:pick $after 0] != $selectedId) or ([/certificate/get $selectedId fingerprint] != $pin)) do={ :error "tikray: shared_reference_refuses; certificate identity changed" }
    :return $pin
}
