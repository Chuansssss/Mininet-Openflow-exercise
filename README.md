# Mininet-Openflow-exercise

This project is to follow the [Mininet Openflow tutorial](https://github.com/mininet/openflow-tutorial/wiki) and implement the switch, router and firewall functions.

The SDN is defined and built in the Mininet Linux system, which is included in the tutorial.

# How to run the project

## Act like a switch

1.of_tutorial_flow_mod.py, act_like_switch code file, implements flow mode to send the packet, saved in folder /pox/pox/misc

2.of_tutorial._resend.py act_like_switch code file, implements resend to send the packet, saved in folder /pox/pox/misc

Run:
	1. In a mininet terminal run the following command
		sudo mn --topo single,3 --mac --switch ovsk --controller remote
	2.In another mininet terminal run the following command
    cd pox
    ./pox.py log.level --DEBUG misc.of_tutorial_flow_mod

    Or

    cd pox
    ./pox.py log.level --DEBUG misc.of_tutorial_resend


## Act like a router in simple topology

1.part1_flow_mod.py, router exercise code file, implements flow mode to send IPv4 packet, saved in folder /pox/pox/misc.

2.part1_pkt_out.py, router exercise code file, implements packet out mode to send the IPv4 packet saved in folder /pox/pox/misc.

3.topo1.py, the topology file of this exercise, saved in folder ~/mininet/custom.

Run:
	1. In a mininet terminal run the following command
		cd ~/mininet/custom
		sudo mn --custom topo1.py --topo mytopo --mac

	2.In another mininet terminal run the following command
		cd pox
    ./pox.py log.level --DEBUG part1_flow_mod misc.full_payload

    Or

    cd pox
    ./pox.py log.level --DEBUG misc.part1_pkt_out misc.full_payload
        
## Act like a router in advanced topology
 
1.part2_flow_mod.py, advanced topology code file, implements flow mode to send IPv4 packet, saved in folder /pox/pox/misc.

2.part2_pkt_out.py, advanced topology code file, implements packet out mode to send the IPv4 packet, saved in folder /pox/pox/misc.

3.part2_flow_mod_fw.py, advanced topology code file, implements flow mode to send IPv4 packet, implements firewall to block packets sent to h2, saved in folder /pox/pox/misc.

4.topo2.py, the topology file of this exercise, saved in folder ~/mininet/custom.

Run:
  1.In a mininet terminal run the following command
		cd ~/mininet/custom
		sudo mn --custom topo2.py --topo mytopo --mac

	2.In another mininet terminal run the following command
		cd pox
    ./pox.py log.level --DEBUG part2_flow_mod misc.full_payload

    Or

    cd pox
    ./pox.py log.level --DEBUG misc.part2_pkt_out misc.full_payload

    Or

    cd pox
    ./pox.py log.level --DEBUG misc.part2_flow_mod_fw misc.full_payload
    
## Bonus: more subnets

1.bonus_flow_mod.py, router exercise code file, implements flow mode to send IPv4 packet, saved in folder /pox/pox/misc.

2.bonus_pkt_out.py, router exercise code file, implements packet out mode to send the IPv4 packet saved in folder /pox/pox/misc.

3.topo_bonus.py, the topology file of this exercise, saved in folder ~/mininet/custom.

Run:

1.In a mininet terminal run the following command
	cd ~/mininet/custom
	sudo mn --custom topo_bonus.py --topo mytopo --mac

2.In another mininet terminal run the following command
	cd pox
  ./pox.py log.level --DEBUG misc.bonus_flow_mod misc.full_payload

  Or

  cd pox
  ./pox.py log.level --DEBUG misc.bonus_pkt_out misc.full_payload

## Attention

1.If there is error in the controller terminal indicating that the port is already in use, please run the following command before another attempt:
	sudo fuser -k 6633/tcp
		
2.Sometimes after the connections are established, the first attempt of "pingall" will not reach h2. But this will automatically fixed if you run the command "pingall" once again.
    
 
