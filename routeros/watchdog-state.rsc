# Scheduler jobs do not reliably retain globals. The inert receipt changes
# only on a new miss, restart deadline, or recovery, never on a healthy tick.
:local wdState do={
    :local op $1
    :local key $2
    :local next $3
    :local seconds $4
    :local label "tikray-watchdog-state"
    :local prefix "tikray:watchdog-state "
    :local rows [/system/script/find where name=$label or comment~"^tikray:watchdog-state "]
    :if (([:len $rows] = 0) and ($op = "inspect")) do={ :return {"version"=1} }
    :if (([:len $rows] = 0) and ($op = "init")) do={
        /system/script/add name=$label comment=($prefix . "{\"version\":1}") policy=read dont-require-permissions=no source=""
        :set rows [/system/script/find where name=$label or comment~"^tikray:watchdog-state "]
    }
    :if ([:len $rows] != 1) do={ :error "tikray: watchdog state ownership conflict" }
    :local rid [:pick $rows 0]
    :local tag [/system/script/get $rid comment]
    :if (([/system/script/get $rid name] != $label) or ([:pick $tag 0 [:len $prefix]] != $prefix) or ([:len [/system/script/get $rid source]] != 0) or [/system/script/get $rid dont-require-permissions]) do={ :error "tikray: watchdog state identity conflict" }
    :local readable false
    :foreach right in=[/system/script/get $rid policy] do={
        :if ([:pick $right 0 1] != "!") do={
            :if ($right != "read") do={ :error "tikray: watchdog state permissions conflict" }
            :set readable true
        }
    }
    :if (!$readable) do={ :error "tikray: watchdog state permissions conflict" }
    :local values [:deserialize from=json options=json.no-string-conversion value=[:pick $tag [:len $prefix] [:len $tag]]]
    :if (($values->"version") != 1) do={ :error "tikray: unknown watchdog state" }
    :foreach field,record in=$values do={
        :if ($field != "version") do={
            :if (($field != "tikray") and ($field != "tikray-runner")) do={ :error "tikray: unexpected watchdog state" }
            :foreach prop in={"miss";"delay";"due";"at"} do={
                :if ([:typeof ($record->$prop)] != "num") do={ :error "tikray: unreadable watchdog state" }
            }
            :if ((($record->"miss") < 0) or (($record->"miss") > 3) or (($record->"delay") < 1) or (($record->"delay") > 15) or (($record->"at") < 0) or (($record->"due") < 0) or (($record->"due") > (($record->"at") + 900))) do={ :error "tikray: invalid watchdog deadline" }
        }
    }
    :if (($op = "read") or ($op = "init") or ($op = "inspect")) do={ :return $values }
    :if (($op != "save") or (($key != "tikray") and ($key != "tikray-runner"))) do={ :error "tikray: invalid watchdog transition" }
    :local old ($values->$key)
    :if (([:typeof $old] != "array") and (($next->"miss") = 0)) do={ :return true }
    :if ([:typeof $old] = "array") do={
        :if ((($old->"miss") = ($next->"miss")) and (($old->"delay") = ($next->"delay")) and (($old->"due") = ($next->"due")) and ((($old->"at") <= $seconds) or (($next->"miss") = 0))) do={ :return true }
    }
    :if (($next->"miss") = 0) do={ :set seconds 0 }
    :set ($values->$key) {"miss"=($next->"miss");"delay"=($next->"delay");"due"=($next->"due");"at"=$seconds}
    :if (([/system/script/get $rid name] != $label) or ([/system/script/get $rid comment] != $tag) or ([:len [/system/script/get $rid source]] != 0)) do={ :error "tikray: watchdog state changed" }
    /system/script/set $rid comment=($prefix . [:serialize to=json options=json.no-string-conversion value=$values])
    :return true
}
