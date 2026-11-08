# One cross-user lease covers the mutating phase even when imports use
# different filenames. The inert script name is unique on the router. A real
# job ID and its start timestamp let a retry disprove a stale lease after
# reboot. A killed foreground import can leave its keeper for at most 30 min.
:local acquireInstall do={
    :local lockName "tikray-install-lock"
    :local prefix "tikray:install-lock "
    :local prior [/system/script/find where name=$lockName or comment~"^tikray:install-lock "]
    :if ([:len $prior] > 1) do={ :error "tikray: object conflict in install lock" }
    :if ([:len $prior] = 1) do={
        :local id [:pick $prior 0]
        :local claimText [/system/script/get $id comment]
        :if (([/system/script/get $id name] != $lockName) or ([:pick $claimText 0 [:len $prefix]] != $prefix) or ([:len [/system/script/get $id source]] > 0) or [/system/script/get $id dont-require-permissions]) do={ :error "tikray: object conflict in install lock" }
        :local meta
        :onerror e in={ :set meta [:deserialize from=json options=json.no-string-conversion value=[:pick $claimText [:len $prefix] [:len $claimText]]] } do={ :error "tikray: object conflict in install lock" }
        :if ((($meta->"version") != 1) or ([:len ($meta->"started")] = 0) or ([:len ($meta->"nonce")] != 32) or ([:typeof [:toid ($meta->"job")]] != "id")) do={ :error "tikray: object conflict in install lock" }
        :foreach j in=[/system/script/job/find] do={
            :if (([:tostr $j] = ($meta->"job")) and ([:tostr [/system/script/job/get $j started]] = ($meta->"started"))) do={ :error "tikray: another installer is active; retry when it completes" }
        }
        :if (([/system/script/get $id comment] != $claimText) or ([/system/script/get $id name] != $lockName)) do={ :error "tikray: install lock changed" }
        /system/script/remove $id
    }
    :local keeper [:execute {:delay 30m}]
    :local started [:tostr [/system/script/job/get $keeper started]]
    :if ([:len $started] = 0) do={ /system/script/job/remove $keeper; :error "tikray: could not establish installer job" }
    :local meta {"version"=1;"job"=[:tostr $keeper];"started"=$started;"nonce"=[:rndstr length=32 from="0123456789abcdef"]}
    :local claimText ($prefix . [:serialize to=json options=json.no-string-conversion value=$meta])
    :onerror e in={ /system/script/add name=$lockName comment=$claimText source="" policy=read dont-require-permissions=no } do={
        /system/script/job/remove $keeper
        :error "tikray: another installer claimed this router"
    }
    :local own [/system/script/find where name=$lockName and comment=$claimText and source=""]
    :if ([:len $own] != 1) do={ /system/script/job/remove $keeper; :error "tikray: install lock changed" }
    :return {"id"=[:pick $own 0];"comment"=$claimText;"job"=$keeper;"started"=$started}
}
:local requireInstall do={
    :local lease $1
    :local id ($lease->"id")
    :local job ($lease->"job")
    :local verified false
    :onerror e in={
        :set verified (([/system/script/get $id name] = "tikray-install-lock") and ([/system/script/get $id comment] = ($lease->"comment")) and ([:tostr [/system/script/job/get $job started]] = ($lease->"started")))
    } do={ :set verified false }
    :if (!$verified) do={ :error "tikray: installation lease expired; retry import" }
}
:local releaseInstall do={
    :local lease $1
    :if ([:len ($lease->"comment")] = 0) do={ :return true }
    # Only the exact ID/claim and the keeper started by this invocation may
    # be removed. A competing owner could already have replaced a stale row.
    :local id ($lease->"id"); :local job ($lease->"job")
    :onerror e in={
        :if (([/system/script/get $id name] = "tikray-install-lock") and ([/system/script/get $id comment] = ($lease->"comment")) and ([:len [/system/script/get $id source]] = 0)) do={ /system/script/remove $id }
    } do={}
    :onerror e in={ :if ([:tostr [/system/script/job/get $job started]] = ($lease->"started")) do={ /system/script/job/remove $job } } do={}
}
