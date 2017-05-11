# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from  pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
log = core.getLogger()



class RouterExercise (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port1 = {}
    self.mac_to_port2 = {}
    # routing table to save ip with network prefix, ip of host, interface name, interface address, switch port
    self.network1 = {"10.0.1.2":[1, '00:00:00:00:00:01'], "10.0.1.3":[2,'00:00:00:00:00:02']}
    self.network2 = {"10.0.2.2":[1,'00:00:00:00:00:03']}
   
  
  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_switch1 (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """

    # Learn the port for the source MAC
    self.mac_to_port1[packet.src] = packet_in.in_port

    if packet.dst in self.mac_to_port1:
      # Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port1[packet.dst])

     
    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)



  def act_like_switch2 (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """

    # Learn the port for the source MAC
    self.mac_to_port2[packet.src] = packet_in.in_port

    if packet.dst in self.mac_to_port2:
      # Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port2[packet.dst])
    


    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL) 
   
  
  def arp_send1(self,packet, packet_in):
      arpPacketProtocol = packet.payload
      if arpPacketProtocol.opcode == pkt.arp.REPLY:
          log.debug("ARP reply reveived")
          self.mac_to_port1[packet.src] = packet_in.in_port
          log.debug("Display the mac_to_port dictionary)(REPLY)")
          #log.debug(self.mac_to_port)
          self.act_like_switch1(packet,packet_in)


      elif arpPacketProtocol.opcode == pkt.arp.REQUEST:
          if str(arpPacketProtocol.protodst) == "10.0.1.1":
          # ARP reply
              arpResponse = pkt.arp()
              arpResponse.hwsrc = adr.EthAddr("10:10:10:10:10:10")
              arpResponse.hwdst = arpPacketProtocol.hwsrc
              arpResponse.opcode = pkt.arp.REPLY
              arpResponse.protosrc = arpPacketProtocol.protodst
              arpResponse.protodst = arpPacketProtocol.protosrc

              #add header to the arp packet, usign the ethernet frame
              arpFrame = pkt.ethernet()
              arpFrame.type = pkt.ethernet.ARP_TYPE
              arpFrame.dst = packet.src
              arpFrame.src = adr.EthAddr("10:10:10:10:10:10")
              arpFrame.payload = arpResponse

              #send the packet
              msg = of.ofp_packet_out()
              msg.data = arpFrame.pack()

              action = of.ofp_action_output(port = packet_in.in_port)
              msg.actions.append(action)
              self.connection.send(msg)

              #add the mac address to the port table##
              self.mac_to_port1[packet.src] = packet_in.in_port
              log.debug("Display the mac_to_port dictionary(REQUEST)")
              log.debug(self.mac_to_port1)
          
          else:
              find_ip = 0
              for ip in self.network1.keys():
                  if ip == str(arpPacketProtocol.protodst):
                      find_ip = ip
              if find_ip == 0:
                  log.debug("ARP: The dst ip is not in the network, we can't find it's mac address")
              else:        
                  self.act_like_switch1(packet,packet_in)
                 
      else:
        pass
  def arp_send2(self,packet, packet_in):
      arpPacketProtocol = packet.payload
      if arpPacketProtocol.opcode == pkt.arp.REPLY:
          log.debug("ARP reply reveived")
          self.mac_to_port2[packet.src] = packet_in.in_port
          log.debug("Display the mac_to_port dictionary)(REPLY)")
          self.act_like_switch2(packet,packet_in)


      elif arpPacketProtocol.opcode == pkt.arp.REQUEST:
          if str(arpPacketProtocol.protodst) == "10.0.2.1":
          # ARP reply
              arpResponse = pkt.arp()
              arpResponse.hwsrc = adr.EthAddr("20:20:20:20:20:20")
              arpResponse.hwdst = arpPacketProtocol.hwsrc
              arpResponse.opcode = pkt.arp.REPLY
              arpResponse.protosrc = arpPacketProtocol.protodst
              arpResponse.protodst = arpPacketProtocol.protosrc

              #add header to the arp packet, usign the ethernet frame
              arpFrame = pkt.ethernet()
              arpFrame.type = pkt.ethernet.ARP_TYPE
              arpFrame.dst = packet.src
              arpFrame.src = adr.EthAddr("20:20:20:20:20:20")
              arpFrame.payload = arpResponse

              #send the packet
              msg = of.ofp_packet_out()
              msg.data = arpFrame.pack()

              action = of.ofp_action_output(port = packet_in.in_port)
              msg.actions.append(action)
              self.connection.send(msg)

              #add the mac address to the port table##
              self.mac_to_port2[packet.src] = packet_in.in_port
              log.debug("Display the mac_to_port dictionary(REQUEST)")
              log.debug(self.mac_to_port2)
          
          else:
              find_ip = 0
              for ip in self.network2.keys():
                  if ip == str(arpPacketProtocol.protodst):
                      find_ip = ip
              if find_ip == 0:
                  log.debug("ARP: The dst ip is not in the network, we can't find it's mac address")
              else:        
                  self.act_like_switch2(packet,packet_in)
                 
      else:
        pass
      

  def reachable_send(self, packet, packet_in):
      msgEcho = pkt.echo()
      msgEcho.seq = packet.payload.payload.payload.seq + 1
      msgEcho.id = packet.payload.payload.payload.id
      
      #encapsulate the reachable ICMP packet
      icmpReachable = pkt.icmp()
      icmpReachable.type = pkt.TYPE_ECHO_REPLY
      icmpReachable.payload = msgEcho

      icmpPkt = pkt.ipv4()
      icmpPkt.srcip = packet.payload.dstip
      icmpPkt.dstip = packet.payload.srcip
      icmpPkt.protocol = pkt.ipv4.ICMP_PROTOCOL
      icmpPkt.payload = icmpReachable

      #encapsulate the packet into frame
      icmpFrame2 = pkt.ethernet()
      icmpFrame2.type = pkt.ethernet.IP_TYPE
      icmpFrame2.dst = packet.src
      icmpFrame2.src = packet.dst
      icmpFrame2.payload = icmpPkt

      msg = of.ofp_packet_out()
      msg.data = icmpFrame2.pack()
      
      action = of.ofp_action_output(port = packet_in.in_port)
      msg.actions.append(action)
      self.connection.send(msg)

  def unreachable_send(self,packet,packet_in):

      msgUnreachable = pkt.unreach()
      msgUnreachable.payload = packet.payload

      icmpReachable = pkt.icmp()
      icmpReachable.type = pkt.TYPE_DEST_UNREACH
      icmpReachable.payload = msgUnreachable

      #encapsulate reachable ICMP packet
      icmpPkt = pkt.ipv4()

      icmpPkt.srcip = packet.payload.dstip  #change the source ip to router's ip
      icmpPkt.dstip = packet.payload.srcip 
      icmpPkt.protocol = pkt.ipv4.ICMP_PROTOCOL
      icmpPkt.payload = icmpReachable

      #encapsulate packet into frame
      icmpFrame = pkt.ethernet()
      icmpFrame.type = pkt.ethernet.IP_TYPE
      icmpFrame.dst = packet.src
      icmpFrame.src = packet.dst
      icmpFrame.payload = icmpPkt

      msg = of.ofp_packet_out()
      msg.data = icmpFrame.pack()

      action = of.ofp_action_output(port = packet_in.in_port)
      msg.actions.append(action)
      self.connection.send(msg)
      
  def ipv4pkt_send1(self, packet, packet_in):

      log.debug("ipv4 function pkt send src ip %r dst ip %r"%(packet.payload.srcip,packet.payload.dstip))
      dstip_pkt = packet.payload.dstip
      srcip_pkt = packet.payload.srcip
      if str(dstip_pkt) in self.network1:
          if str(srcip_pkt) in self.network1:
             
              msg = of.ofp_flow_mod()

              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst  
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port

              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = self.network1[str(dstip_pkt)][0]))
              self.connection.send(msg)


          elif str(srcip_pkt) in self.network2:
              
              log.debug("flow mode...")
              msg = of.ofp_flow_mod()
              
              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port
   

              msg.data = packet_in
              msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.network1[str(dstip_pkt)][1])))
              msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
              msg.actions.append(of.ofp_action_output(port = self.network1[str(dstip_pkt)][0]))
              self.connection.send(msg)
              
          else:
            pass          
      elif str(dstip_pkt) in self.network2:
          log.debug("forward the packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))
          
          msg = of.ofp_flow_mod()

          msg.match.dl_type = pkt.ethernet.IP_TYPE
          msg.match.dl_src = packet.src
          msg.match.dl_dst = packet.dst
          
          msg.match.nw_src = packet.payload.srcip
          msg.match.nw_dst = packet.payload.dstip
          msg.match.in_port = packet_in.in_port


          msg.data = packet_in
          msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("20:20:20:20:20:20")))
          msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
          msg.actions.append(of.ofp_action_output(port = 3))
          self.connection.send(msg)
          

      else:
        pass

  def ipv4pkt_send2(self, packet, packet_in):

      log.debug("ipv4 function pkt send src ip %r dst ip %r"%(packet.payload.srcip,packet.payload.dstip))
      dstip_pkt = packet.payload.dstip
      srcip_pkt = packet.payload.srcip
      if str(dstip_pkt) in self.network2:
          if str(srcip_pkt) in self.network2:
             
              msg = of.ofp_flow_mod()

              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst  
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port

              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = self.network2[str(dstip_pkt)][0]))
              self.connection.send(msg)
          elif str(srcip_pkt) in self.network1:
              
              log.debug("flow mode...")
              msg = of.ofp_flow_mod()
              
              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port
   

              msg.data = packet_in
              msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.network2[str(dstip_pkt)][1])))
              msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
              msg.actions.append(of.ofp_action_output(port = self.network2[str(dstip_pkt)][0]))
              self.connection.send(msg)
              
          else:
            pass          
      elif str(dstip_pkt) in self.network1:
          log.debug("forward the packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))
          
          log.debug("flow mode...")
          
          msg = of.ofp_flow_mod()
          msg.match.dl_type = pkt.ethernet.IP_TYPE
          msg.match.dl_src = packet.src
          msg.match.dl_dst = packet.dst
          msg.match.nw_src = packet.payload.srcip
          msg.match.nw_dst = packet.payload.dstip
          msg.match.in_port = packet_in.in_port


          msg.data = packet_in
          msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("10:10:10:10:10:10")))
          msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
          msg.actions.append(of.ofp_action_output(port = 2))
          self.connection.send(msg)
          
      else:
        pass

  def act_like_router(self,event,packet_in):

      if dpid_to_str(event.dpid) == "00-00-00-00-00-01":
          log.debug("THIS IS SWITCH 1")
          packet = event.parsed
          if event.parsed.type == pkt.ethernet.ARP_TYPE: #if the packet's type is ARP
              self.arp_send1(event.parsed, packet_in)

          elif packet.type == pkt.ethernet.IP_TYPE: #if the packet's type is ipv4ip
              log.debug("IPTYPE packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))
              ipPkt = packet.payload
              ipDstAddr = ipPkt.dstip  #extract the ip of dst
              ipSrcAddr = ipPkt.srcip
              
              #determine whether it is a ICMP
              if ipDstAddr == "10.0.1.3":
                  pass
              else:
                  if ipPkt.protocol == pkt.ipv4.ICMP_PROTOCOL: 
                      icmpPacket = ipPkt.payload   
                      
                      #the dst IP is in the same network with s1
                      if ipDstAddr.inNetwork("10.0.1.0/24"):

                          #ICMP packet is forwarded to s1
                          if ipDstAddr == "10.0.1.1":

                              if icmpPacket.type == pkt.TYPE_ECHO_REQUEST:

                                  if str(ipSrcAddr) in self.network1:
                                      self.reachable_send(packet, packet_in)

                                  elif str(ipSrcAddr) in self.network2:
                                      self.reachable_send(packet, packet_in)

                                  else:
                                      self.unreachable_send(packet, packet_in)
                              else:
                                  pass

                                  
                      
                          elif ipSrcAddr.inNetwork("10.0.1.0/24"):
                              self.act_like_switch1(packet,packet_in)

                          elif ipSrcAddr.inNetwork("10.0.2.0/24"):
                              if str(ipDstAddr) in self.network1:

                                  packet.src = packet.dst
                                  packet.dst = EthAddr(self.network1[str(ipDstAddr)][1])
                                  msg = of.ofp_packet_out()
                                  msg.data = packet.pack()

                                  action = of.ofp_action_output(port = self.network1[str(ipDstAddr)][0])
                                  msg.actions.append(action)
                                  self.connection.send(msg)

                              else:
                                  self.unreachable_send(packet, packet_in)
                          else:
                              pass

                      elif ipDstAddr.inNetwork("10.0.2.0/24"):
                          # this case when destination IP in subnet 2, source IP in subnet 1, no matter it is request or reply
                          # we can make sure that we want to forward this icmp to the next hop router
                          if ipSrcAddr.inNetwork("10.0.1.0/24"):
                              packet.src = packet.dst
                              packet.dst = adr.EthAddr("20:20:20:20:20:20")

                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = 3)
                              msg.actions.append(action)
                              self.connection.send(msg)
                          else:
                              pass
                  
                      else:
                          self.unreachable_send(packet, packet_in)
                  else:
                      self.ipv4pkt_send1(packet, packet_in)      
          else:
              pass                     




      elif dpid_to_str(event.dpid) == "00-00-00-00-00-02":
          log.debug("THIS IS SWITCH 2")
          packet = event.parsed
          if event.parsed.type == pkt.ethernet.ARP_TYPE: #if the packet's type is ARP
              self.arp_send2(event.parsed, packet_in)
          
          elif packet.type == pkt.ethernet.IP_TYPE: #if the packet's type is ipv4ip
              log.debug("IPTYPE packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))
              ipPkt = packet.payload
              ipDstAddr = ipPkt.dstip  #extract the ip of dst
              ipSrcAddr = ipPkt.srcip
              
              if ipDstAddr == "10.0.1.3":
                  pass
              else:
                
                  #determine whether it is a ICMP
                  if ipPkt.protocol == pkt.ipv4.ICMP_PROTOCOL: 
                      icmpPacket = ipPkt.payload   
                    
                      #the dst IP is in the same network with s2
                      if ipDstAddr.inNetwork("10.0.2.0/24"):

                          #ICMP is forwarded to s1
                          if ipDstAddr == "10.0.2.1":

                              if icmpPacket.type == pkt.TYPE_ECHO_REQUEST:

                                  if str(ipSrcAddr) in self.network2:
                                      self.reachable_send(packet, packet_in)

                                  elif str(ipSrcAddr) in self.network1:
                                      self.reachable_send(packet, packet_in)

                                  else:
                                      self.unreachable_send(packet, packet_in)
                              else:
                                  pass
                      
                          elif ipSrcAddr.inNetwork("10.0.2.0/24"):
                              # this case, source IP and and destination IP all in host, no matter it is request or reply
                              # we can sure this case should always act like switch
                              self.act_like_switch2(packet,packet_in)

                          elif ipSrcAddr.inNetwork("10.0.1.0/24"):
                              # this case when source IP from subnet 2, destination IP in host, no matter it is request or reply or unreachale,
                              # we can sure that it need to be forward to the destination port
                              if str(ipDstAddr) in self.network2:

                                  packet.src = packet.dst
                                  packet.dst = EthAddr(self.network2[str(ipDstAddr)][1])
                                  log.debug("ICMP request from switch1 mac address %r"%(self.network2[str(ipDstAddr)][1]))
                                  log.debug("ICMP request from switch1 ip address %r"%(ipDstAddr))
                                  msg = of.ofp_packet_out()
                                  msg.data = packet.pack()

                                  action = of.ofp_action_output(port = self.network2[str(ipDstAddr)][0])
                                  msg.actions.append(action)
                                  self.connection.send(msg)

                              else:
                                  self.unreachable_send(packet, packet_in)

                      elif ipDstAddr.inNetwork("10.0.1.0/24"):
                          if ipSrcAddr.inNetwork("10.0.2.0/24"):
                              packet.src = packet.dst
                              packet.dst = adr.EthAddr("10:10:10:10:10:10")

                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = 2)
                              msg.actions.append(action)
                              self.connection.send(msg)
                          else:
                              pass

                      else:
                          self.unreachable_send(packet, packet_in)
                  else:
                      self.ipv4pkt_send2(packet, packet_in)         
      else:
          pass           
          

  def _handle_PacketIn (self, event):
      """
      Handles packet in messages from the switch.
      """

      packet = event.parsed # This is the parsed packet data.
      if not packet.parsed:
          log.warning("Ignoring incomplete packet")
          return

      packet_in = event.ofp # The actual ofp_packet_in message.

      # Comment out the following line and uncomment the one after
      # when starting the exercise.
      # self.act_like_hub(packet, packet_in)
      # self.act_like_switch(packet, packet_in)

      if packet.type != pkt.ethernet.ARP_TYPE:
          log.debug("arp_frame  from %r to %r"%(packet.payload.srcip, packet.payload.dstip))


      self.act_like_router(event,packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    RouterExercise(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
