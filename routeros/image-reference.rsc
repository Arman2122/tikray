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
