# 2026-10-14 22:50:31 by RouterOS 7.14.3
# software id = EXMP-0001
# model = RB4011iGS+
# serial number = EXAMPLE0001
/interface bridge
add name=bridge-lan
/ip address
add address=10.0.1.2/30 interface=ether1
add address=10.10.20.1/24 interface=bridge-lan
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=accept chain=input protocol=icmp
add action=accept chain=input dst-port=22 protocol=tcp src-address=10.0.9.0/24
add action=drop chain=input comment="drop all else"
/ip service
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set ssh port=22
/system identity
set name=edge-rtr02
/system ntp client
set enabled=yes
/user
add group=full name=netops password="EXAMPLEPASSWORD1"
add group=full name=support password="EXAMPLEPASSWORD2"
