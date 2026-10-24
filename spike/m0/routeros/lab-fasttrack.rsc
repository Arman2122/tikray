# Lab baseline (lab: objects): what a typical user's router already has
# before tikray: a FastTrack rule, LAN masquerade, and upstream DNS servers.
/ip/firewall/filter/add chain=forward action=fasttrack-connection connection-state=established,related comment=lab:fasttrack
/ip/firewall/filter/add chain=forward action=accept connection-state=established,related comment=lab:est
/ip/firewall/nat/add chain=srcnat src-address=192.168.88.0/24 out-interface=ether1 action=masquerade comment=lab:nat-lan
/ip/dns/set servers=203.0.113.54
