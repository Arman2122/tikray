# A runner may forward through its main default before PID 1. Both forward
# hooks see only outside-source traffic from the private bridge. A legitimate
# reply returns to the owner's firewall only through its enrolled LAN prefix.
:local transitGuard do={
    :local op $1; :local net [:tostr $2]; :local lan [:tostr $3]; :local check $4; :local claim $5; :local networks $6
    :local chainName "tikray-transit"; :local egress "tikray:acl-runner-transit"; :local hook "tikray:acl-runner-transit-dst"
    :local deny "tikray:acl-transit-deny"; :local backup "tikray:acl-transit-deny-backup"; :local prefix "tikray:acl-transit-lan:"
    :local shape [:toarray ""]
    :set ($shape->$egress) {"chain"="forward";"action"="drop";"in-interface"="tikray";"src-address"=("!" . $net);"out-interface-list"=("!" . $lan)}
    :set ($shape->$hook) {"chain"="forward";"action"="jump";"in-interface"="tikray";"src-address"=("!" . $net);"jump-target"=$chainName}
    :set ($shape->$deny) {"chain"=$chainName;"action"="drop"}; :set ($shape->$backup) ($shape->$deny)
    :foreach entry in=$networks do={
        :local addr [:tostr ($entry->"prefix")]; :local cut [:find $addr "/"]
        :if (([:typeof $cut]!="num") or (!($addr~"^[0-9.]+/[0-9]+\$"))) do={:error "tikray: shared_reference_refuses; invalid runner return LAN"}
        :local ip [:toip [:pick $addr 0 $cut]]; :local bits [:tonum [:pick $addr ($cut+1) [:len $addr]]]
        :if (([:typeof $ip]!="ip") or ([:typeof $bits]!="num") or ($bits<1) or ($bits>32) or (($ip & (255.255.255.255 << (32-$bits)))!=$ip) or (([:tostr $ip] . "/" . $bits)!=$addr)) do={:error "tikray: shared_reference_refuses; invalid runner return LAN"}
        :set ($shape->($prefix . $addr)) {"chain"=$chainName;"action"="return";"dst-address"=$addr;"out-interface-list"=$lan}
    }
    :local exact do={
        :local row $1; :local props $2
        :if (([:typeof $props]!="array") or (($row->"dynamic")=true) or (($row->"log")=true) or ([:len ($row->"log-prefix")]>0)) do={:error "tikray: shared_reference_refuses; runner transit guard changed"}
        :foreach k,v in=$props do={
            :local actual [:tostr ($row->$k)]
            :if (($k="dst-address") and ([:typeof [:find $actual "/"]]!="num") and ([:typeof [:toip $actual]]="ip")) do={:set actual ($actual . "/32")}
            :if ($actual!=[:tostr $v]) do={:error "tikray: shared_reference_refuses; runner transit guard changed"}
        }
        :foreach k,v in=$row do={
            :if (([:typeof ($props->$k)]!="str") and ([:typeof [:find {".id";".nextid";"comment";"disabled";"invalid";"dynamic";"log";"log-prefix";"packets";"bytes"} $k]]!="num")) do={:error "tikray: shared_reference_refuses; extra runner transit condition"}
        }
        :return true
    }
    :local inspect do={
        :local desired $1; :local verify $2; :local found [:toarray ""]
        :if ([:len [/ip/firewall/address-list/find where comment~"^tikray:acl-transit-lan:"]]>0) do={:error "tikray: shared_reference_refuses; incompatible runner transit ownership"}
        :local ids [/ip/firewall/filter/find where chain="tikray-transit" or jump-target="tikray-transit" or comment="tikray:acl-runner-transit" or comment="tikray:acl-runner-transit-dst" or comment="tikray:acl-transit-deny" or comment="tikray:acl-transit-deny-backup" or comment~"^tikray:acl-transit-lan:"]
        :foreach id in=$ids do={
            :local row [/ip/firewall/filter/get $id]; :local tag [:tostr ($row->"comment")]
            :if ([:typeof ($desired->$tag)]!="array") do={:error "tikray: shared_reference_refuses; owner uses private runner transit chain"}
            :if ([:typeof ($found->$tag)]="id") do={:error "tikray: shared_reference_refuses; ambiguous runner transit guard"}
            :local ok [$verify $row ($desired->$tag)]; :set ($found->$tag) $id
        }
        :return $found
    }
    :local got [$inspect $shape $exact]
    :if ($op="check") do={:return ($got->$egress)}
    :if ((($op!="place") and ($op!="repair")) or ([:len $shape]<=4) or ([:len $shape]>132) or ([:len [/interface/bridge/find where name="tikray" and comment="tikray:bridge" and !disabled]]!=1) or ([:len [/interface/list/find where name=$lan]]!=1)) do={:error "tikray: runner transit scope unavailable"}
    :local addr [/ip/address/find where interface=tikray and comment="tikray:addr" and !disabled and !dynamic]
    :if ([:len $addr]!=1) do={:error "tikray: runner transit bridge subnet unavailable"}
    :local native [:tostr [/ip/address/get $addr address]]
    :if (([:tostr [/ip/address/get $addr network]] . [:pick $native [:find $native "/"] [:len $native]])!=$net) do={:error "tikray: runner transit bridge subnet changed"}
    # Keep verified restrictions and the native FastTrack accounting dummy
    # ahead of our hooks. Never jump past a dynamic permitting predecessor.
    :local position do={
        :local role $1; :local props $2; :local found $3; :local own ($found->$role)
        :if (($props->"chain")="tikray-transit") do={
            :if (($props->"action")="drop") do={:return $own}
            :foreach id in=[/ip/firewall/filter/find where chain="tikray-transit" and (comment=$role or comment="tikray:acl-transit-deny" or comment="tikray:acl-transit-deny-backup")] do={
                :if (($id=$own) or ($id=($found->"tikray:acl-transit-deny")) or ($id=($found->"tikray:acl-transit-deny-backup"))) do={:return $id}
            }
            :return ""
        }
        :local restricted ([:len [/ip/firewall/filter/find where chain="tikray-egress" and !disabled and action!="drop" and action!="reject" and action!="return"]]=0)
        :foreach id in=[/ip/firewall/filter/find where chain=forward] do={
            :if ($id=$own) do={:return $id}
            :local row [/ip/firewall/filter/get $id]; :local tag [:tostr ($row->"comment")]; :local act ($row->"action")
            :local safe (($id=($found->"tikray:acl-runner-transit")) or ($id=($found->"tikray:acl-runner-transit-dst")) or ((($row->"dynamic")=true) and ($act="passthrough")) or (([:pick $tag 0 12]="tikray:hold:") and (($act="drop") or ($act="reject"))))
            :if (($tag~"^tikray:udp-guard-(legacy|pending|runner|wan)\$") and ($act="drop")) do={:set safe true}
            :if (($tag="tikray:egress-guard") and ($act="jump") and (($row->"jump-target")="tikray-egress") and $restricted) do={:set safe true}
            :if (!$safe) do={:if (($row->"dynamic")=true) do={:error "tikray: cannot protect runner ahead of dynamic forward rule"}; :return $id}
        }
        :return ""
    }
    :local order [:toarray ""]
    :foreach tag in=({$egress;$deny;$backup}) do={:set ($order->[:len $order]) $tag}
    :foreach tag,props in=$shape do={:if (($props->"action")="return") do={:set ($order->[:len $order]) $tag}}
    :foreach tag in=({$deny;$backup;$hook}) do={:set ($order->[:len $order]) $tag}
    # Build the private chain completely before attaching the destination
    # jump. A return never accepts a packet on behalf of the owner.
    :local priming true; :local writes 0; :local deadline ([:tonsec [/system/resource/get uptime]]+15000000000)
    :foreach tag in=$order do={
        :local specs ($shape->$tag); :local id ($got->$tag); :local anchor [$position $tag $specs $got]
        :if (($specs->"action")="return") do={:set priming false}
        # Append missing terminal drops at the tail immediately. An existing
        # disabled one may be above working returns; enable it only on the
        # second pass, when every enrolled return is already above it.
        :local deferEnable ($priming and (($tag=$deny) or ($tag=$backup)))
        :local exists ([:typeof $id]="id"); :local change (!$exists)
        :if ($exists) do={:set change (($id!=$anchor) or ((!$deferEnable) and ([/ip/firewall/filter/get $id disabled]=true)))}
        :if ($change) do={
            :if (($op="repair") and (($writes>=16) or ([:tonsec [/system/resource/get uptime]]>$deadline))) do={:error "tikray: runner return LAN repair pending"}
            $check $claim; :local live [$inspect $shape $exact]
            :if (([:tostr ($live->$tag)]!=[:tostr $id]) or ([:tostr [$position $tag $specs $live]]!=[:tostr $anchor])) do={:error "tikray: runner transit ownership changed"}
            :if (!$exists) do={
                :local cmd "/ip/firewall/filter/add comment=\$1"
                :foreach k,v in=$specs do={:set cmd ($cmd . " " . $k . "=(\$2->\"" . $k . "\")")}
                :if ([:len [:tostr $anchor]]>0) do={:set cmd ($cmd . " place-before=\$3")}
                :local add [:parse $cmd]; $add $tag $specs $anchor
            } else={
                :if ($id!=$anchor) do={/ip/firewall/filter/move $id destination=$anchor}
                :if ((!$deferEnable) and ([/ip/firewall/filter/get $id disabled]=true)) do={/ip/firewall/filter/enable $id}
            }
            :set writes ($writes+1); :set got [$inspect $shape $exact]
            :if ($exists and (($got->$tag)!=$id)) do={:error "tikray: runner transit identity changed"}
            :set id ($got->$tag)
        }
        :if (([:typeof $id]!="id") or ((!$deferEnable) and ([/ip/firewall/filter/get $id disabled]=true)) or ([$position $tag $specs $got]!=$id)) do={:error "tikray: runner transit placement unverified"}
        :if ((!$deferEnable) or ([/ip/firewall/filter/get $id disabled]!=true)) do={
            :local tries 0; :while (([/ip/firewall/filter/get $id invalid]=true) and ($tries<20)) do={:delay 200ms; :set tries ($tries+1)}
            :if ([/ip/firewall/filter/get $id invalid]=true) do={:error "tikray: runner transit validity unverified"}
        }
    }
    :local complete [$inspect $shape $exact]
    :if ([:len $complete]!=[:len $shape]) do={:error "tikray: runner return LANs unverified"}
    :foreach tag,id in=$got do={:if ((($complete->$tag)!=$id) or ([/ip/firewall/filter/get $id disabled]=true) or ([$position $tag ($shape->$tag) $complete]!=$id)) do={:error "tikray: runner transit state changed"}}
    :return ($complete->$egress)
}
