# tikray M0 hardware benchmark (throwaway). Edit the values below, upload
# this file, setup.rsc, the image tar, the xray binary and xray-client.json
# as README.md describes, then run:  /import bench.rsc
#
# To remove everything tikray added, set tikrayBenchUninstall to true and
# import this file again.

:global tikrayBenchUninstall false

:global tikrayLanClient "192.168.88.100"
:global tikrayWanIf "ether1"
:global tikrayWanGw "CHANGE-ME"
:global tikrayArch "arm64"
:global tikrayApiPass "CHANGE-ME-TOO"
:global tikrayXrayVersion "26.10.21"

:if ($tikrayBenchUninstall) do={
  :foreach c in=[/container/find where comment~"^tikray:"] do={ /container/stop $c }
  :delay 10s
  /container/remove [find where comment~"^tikray:"]
  /container/mounts/remove [find where comment~"^tikray:"]
  /container/envs/remove [find where comment~"^tikray:"]
  /ip/firewall/nat/remove [find where comment~"^tikray:"]
  /ip/firewall/filter/remove [find where comment~"^tikray:"]
  /ip/firewall/mangle/remove [find where comment~"^tikray:"]
  /ip/route/remove [find where comment~"^tikray:"]
  /routing/table/remove [find where comment~"^tikray:"]
  /ip/firewall/address-list/remove [find where comment~"^tikray:"]
  /ip/address/remove [find where comment~"^tikray:"]
  /interface/bridge/port/remove [find where comment~"^tikray:"]
  /interface/veth/remove [find where comment~"^tikray:"]
  /interface/bridge/remove [find where comment~"^tikray:"]
  /user/remove [find where comment~"^tikray:"]
  /user/group/remove [find where comment~"^tikray:"]
  /certificate/remove [find where name="tikray-api"]
  :put "tikray: removed"
} else={
  :if ($tikrayWanGw = "CHANGE-ME") do={ :error "bench.rsc: set tikrayWanGw to your WAN gateway first" }
  /import setup.rsc
  :put "tikray: installed; start the containers with /container/start [find where comment~\"^tikray:\"]"
}
