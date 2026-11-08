# Keep counters in RAM. Reboot starts a fresh three-probe grace period.
:local wdStep do={
    :local state $1
    :local healthy $2
    :local now $3
    :if (($healthy) or ([:typeof ($state->"miss")] != "num") or ([:typeof ($state->"due")] != "num")) do={
        :set state {"miss"=0;"delay"=1;"due"=0;"restart"=false}
    }
    :set ($state->"restart") false
    :if (!$healthy) do={
        :if (($state->"miss") < 3) do={ :set ($state->"miss") (($state->"miss")+1) }
        :if ((($state->"miss") >= 3) and ($now >= ($state->"due"))) do={
            :set ($state->"restart") true
            :set ($state->"due") ($now + (60 * ($state->"delay")))
            :local next (($state->"delay") * 2)
            :if ($next > 15) do={ :set next 15 }
            :set ($state->"delay") $next
        }
    }
    :return $state
}
