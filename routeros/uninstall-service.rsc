:local restoreService do={
    :local op $1; :local stage $2; :local installedPin $3; :local checkLease $4; :local lease $5
    # @TIKRAY_SERVICE_READ@
    :local found [/system/script/find where name="tikray-api-receipt" or name="tikray-api-access" or comment~"^tikray:api-(receipt|access) "]
    :local journal $6
    :local late (($stage="retire") or ($stage="files") or ($stage="empty"))
    :local modes [/system/script/find where name="tikray-api-mode" or comment~"^tikray:api-mode "]
    :local mode ""
    :if ([:len $modes] = 1) do={
        :local m [:pick $modes 0]; :local c [/system/script/get $m comment]; :local prefix "tikray:api-mode "
        :set mode [:pick $c [:len $prefix] [:len $c]]
        :if (([/system/script/get $m name]!="tikray-api-mode") or ($c!=($prefix . $mode)) or ([:len [/system/script/get $m source]]!=0) or [/system/script/get $m dont-require-permissions]) do={ :error "tikray: shared_reference_refuses; invalid API service mode proof" }
        :local reads 0
        :foreach r in=[/system/script/get $m policy] do={ :if ([:pick $r 0 1]!="!") do={ :if ($r!="read") do={ :error "tikray: shared_reference_refuses; API service mode permissions" }; :set reads ($reads+1) } }
        :if ($reads!=1) do={ :error "tikray: shared_reference_refuses; API service mode permissions" }
    } else={
        :if (([:len $modes]!=0) or (!$late) or ([:len $found]!=0)) do={ :error "tikray: shared_reference_refuses; API service mode proof missing or ambiguous" }
        :set mode ($journal->"mode")
    }
    :if (([:typeof [:find {"created";"access";"unchanged"} $mode]]!="num") or (($stage!="preflight") and (($journal->"mode")!=$mode))) do={ :error "tikray: shared_reference_refuses; unknown API service mode" }
    :if ($mode="unchanged") do={
        :if ([:len $found]!=0) do={ :error "tikray: shared_reference_refuses; unexpected API-SSL receipt" }
        :return {"mode"="unchanged"}
    }
    :if ([:len $found]=0) do={
        :if (!$late) do={ :error "tikray: shared_reference_refuses; required API-SSL receipt missing" }
        # Only the retirement phase may have deleted a receipt. The journal
        # retains its original, nonsecret settings and the successful restore.
        :local srv [/ip/service/find where name="api-ssl" and !dynamic]
        :if (([:len $srv]!=1) or ([:typeof ($journal->"disabled")]!="bool") or ([:typeof ($journal->"addresses")]!="array")) do={ :error "tikray: shared_reference_refuses; invalid retired service proof" }
        :local live [$readService [:pick $srv 0] $allowedList]
        :local active [:tostr ($live->"certificate")]; :if ($active="") do={ :set active "none" }
        :if ((($live->"port")!=($journal->"port")) or (($live->"disabled")!=($journal->"disabled")) or ($active!=($journal->"certificate")) or ([$allowedList ($live->"address")]!=[$allowedList ($journal->"addresses")])) do={ :error "tikray: shared_reference_refuses; restored API-SSL settings changed" }
        :if (($mode="created") and ([:len [/certificate/find where name="tikray-api"]]!=0)) do={ :error "tikray: shared_reference_refuses; retired certificate name reused" }
        :return $journal
    }
    :if ([:len $found] != 1) do={ :error "tikray: shared_reference_refuses; multiple certificate receipts" }
    :local proof [:pick $found 0]; :local proofName [/system/script/get $proof name]
    :local created ($proofName = "tikray-api-receipt"); :local prefix "tikray:api-receipt "
    :if (($mode="created")!=$created) do={ :error "tikray: shared_reference_refuses; wrong API-SSL receipt class" }
    :if (!$created) do={ :set prefix "tikray:api-access "; :if ($proofName != "tikray-api-access") do={ :error "tikray: shared_reference_refuses; invalid service receipt" } }
    :local label [/system/script/get $proof comment]
    :if (([:pick $label 0 [:len $prefix]] != $prefix) or ([:len [/system/script/get $proof source]] > 0) or [/system/script/get $proof dont-require-permissions]) do={ :error "tikray: shared_reference_refuses; invalid service receipt" }
    :foreach right in=[/system/script/get $proof policy] do={ :if (([:pick $right 0 1] != "!") and ($right != "read")) do={ :error "tikray: shared_reference_refuses; service receipt permissions" } }
    :local saved [:deserialize from=json options=json.no-string-conversion value=[:pick $label [:len $prefix] [:len $label]]]
    :local original ($saved->"original-addresses")
    :if ((($saved->"version") != 1) or ([:typeof ($saved->"disabled")] != "bool") or ([:typeof ($saved->"port")] != "num") or ([:typeof $original] != "array") or ([:typeof ($saved->"addresses")] != "array") or ([:tostr $original] != ($saved->"address")) or ([:tostr ($saved->"addresses")] != ($saved->"grant"))) do={ :error "tikray: shared_reference_refuses; incomplete original service settings" }
    :local nameFromReceipt [:tostr ($saved->"name")]; :local fingerprint [:tostr ($saved->"fingerprint")]
    :if ($created and (($nameFromReceipt != "tikray-api") or ([:len $fingerprint] != 64) or (!($fingerprint ~ "^[0-9A-Fa-f]+\$")) or (($installedPin != "") and ($fingerprint != $installedPin)))) do={ :error "tikray: shared_reference_refuses; incomplete certificate ownership proof" }
    :if ((!$created) and (($nameFromReceipt != "") or ($fingerprint != ""))) do={ :error "tikray: shared_reference_refuses; invalid access grant receipt" }
    :local svc [/ip/service/find where name="api-ssl" and !dynamic]
    :if ([:len $svc] != 1) do={ :error "tikray: shared_reference_refuses; static service unavailable" }
    :set svc [:pick $svc 0]
    :local live [$readService $svc $allowedList]
    :local old [:tostr ($saved->"certificate")]; :if ($old="") do={ :set old "none" }
    :local attested {"mode"=$mode;"certificate"=$old;"disabled"=($saved->"disabled");"port"=($saved->"port");"addresses"=$original}
    :if ($created) do={ :set ($attested->"created-fingerprint") $fingerprint }
    :if (($stage!="preflight") and ([:serialize to=json options=json.no-string-conversion value=$attested]!=[:serialize to=json options=json.no-string-conversion value=$journal])) do={ :error "tikray: shared_reference_refuses; API-SSL proof changed during uninstall" }
    :local current [:tostr ($live->"certificate")]; :if ($current="") do={ :set current "none" }
    :if ((($saved->"port") != ($live->"port")) or (($old != "none") and ([:len [/certificate/find where name=$old]] != 1))) do={ :error "tikray: shared_reference_refuses; original service unavailable" }
    :local restored (($old = $current) and (($live->"disabled") = ($saved->"disabled")) and ([$allowedList ($live->"address")] = [$allowedList $original]))
    :local installed ((!($live->"disabled")) and ([$allowedList ($live->"address")] = [$allowedList ($saved->"addresses")]))
    :local cid [/certificate/find where name=$nameFromReceipt]
    :if ($created) do={
        :if (($old = $nameFromReceipt) or (([:len $cid] = 0) and (($stage = "preflight") or (!$restored))) or ([:len $cid] > 1)) do={ :error "tikray: shared_reference_refuses; owned certificate unavailable" }
        :if ([:len $cid] = 1) do={ :if ([/certificate/get $cid fingerprint] != $fingerprint) do={ :error "tikray: shared_reference_refuses; certificate fingerprint changed" } }
        :set installed ($installed and ($current = $nameFromReceipt))
    } else={
        :if (!$restored) do={
            :local used [/certificate/find where name=$current]
            :if (([:len $used] != 1) or ($installedPin = "") or ([/certificate/get $used fingerprint] != $installedPin)) do={ :error "tikray: shared_reference_refuses; reused certificate changed" }
        }
    }
    :if (!$installed and !$restored) do={ :error "tikray: shared_reference_refuses; API-SSL has owner changes" }
    :local checkCertUsers do={
        :local c $1
        :if ([:len [/ip/service/find where name!="api-ssl" and !dynamic and certificate=$c]] > 0) do={ :error "tikray: shared_reference_refuses; another service uses the certificate" }
        :if ([:tostr [/interface/sstp-server/server/get certificate]]=$c) do={ :error "tikray: shared_reference_refuses; SSTP uses the certificate" }
        :foreach pair in={"interface/sstp-client:certificate";"interface/ovpn-client:certificate";"interface/ovpn-server/server:certificate";"ip/hotspot/profile:ssl-certificate";"ip/ipsec/identity:certificate";"ip/ipsec/identity:remote-certificate";"radius:certificate";"tool/netwatch:certificate";"certificate/scep-server:ca-cert";"interface/dot1x/client:certificate"} do={
            :local sep [:find $pair ":"]; :local menu [:pick $pair 0 $sep]; :local attr [:pick $pair ($sep+1) [:len $pair]]
            :local findRef [:parse (":return [/" . $menu . "/find where " . $attr . "=\$1]")]
            :if ([:len [$findRef $c]] != 0) do={ :error "tikray: shared_reference_refuses; owner TLS dependency" }
        }
        # A self-signed API certificate can also be used as a signing CA.
        :local parent [/certificate/find where name=$c]
        :if ([:len $parent] = 1) do={
            :local skid [:tostr [/certificate/get $parent skid]]
            :if ([:len $skid] > 0) do={ :if ([:len [/certificate/find where name!=$c and akid=$skid]] > 0) do={ :error "tikray: shared_reference_refuses; certificate has issued children" } }
        }
        :return true
    }
    :if ($created and ([:len $cid] > 0)) do={ :local safe [$checkCertUsers $nameFromReceipt] }
    :if ($op = "inspect") do={ :return $attested }
    :if ($op != "restore") do={ :error "tikray: invalid service operation" }
    :if (!$restored) do={
        :local fresh [$readService $svc $allowedList]
        :if ((($fresh->"port") != ($live->"port")) or ([:tostr ($fresh->"certificate")] != [:tostr ($live->"certificate")]) or (($fresh->"disabled") != ($live->"disabled")) or ([$allowedList ($fresh->"address")] != [$allowedList ($live->"address")]) or ([/system/script/get $proof comment]!=$label)) do={ :error "tikray: shared_reference_refuses; service changed during removal" }
        $checkLease $lease
        /ip/service/set $svc certificate=$old address=$original disabled=($saved->"disabled")
    }
    :local after [$readService $svc $allowedList]; :local selected [:tostr ($after->"certificate")]; :if ($selected="") do={ :set selected "none" }
    :if (($selected != $old) or (($after->"disabled") != ($saved->"disabled")) or ([$allowedList ($after->"address")] != [$allowedList $original])) do={ :error "tikray: original API-SSL settings could not be verified" }
    :if ($created and ([:len $cid] = 1)) do={
        :local safe [$checkCertUsers $nameFromReceipt]
        :local fresh [/certificate/find where name=$nameFromReceipt]
        :if (([:len $fresh] != 1) or ([:pick $fresh 0] != [:pick $cid 0]) or ([/certificate/get $fresh fingerprint] != $fingerprint) or ([/system/script/get $proof comment] != $label) or ([:len [/ip/service/find where !dynamic and certificate=$nameFromReceipt]] > 0)) do={ :error "tikray: shared_reference_refuses; certificate changed during removal" }
        $checkLease $lease
        /certificate/remove [:pick $fresh 0]
    }
    :return $attested
}
