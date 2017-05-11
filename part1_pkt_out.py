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
    self.mac_to_port = {}
    # routing table to save ip with network prefix, ip of host, interface name, interface address, switch port
    self.routing_table = {"10.0.1.0/24" :['10.0.1.100', 's1-eth1', '10.0.1.1', 1,'00:00:00:00:00:01'],
                        "10.0.2.0/24" : ['10.0.2.100', 's1-eth2', '10.0.2.1', 2,'00:00:00:00:00:02'],
                        "10.0.3.0/24" : ['10.0.3.100', 's1-eth3', '10.0.3.1', 3,'00:00:00:00:00:03']}


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


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """

    

    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    self.mac_to_port[packet.src] = packet_in.in_port

    if packet.dst in self.mac_to_port:
      # Send packet out the associated port
      #self.resend_packet(packet_in, self.mac_to_port[packet.dst])

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)

      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
      msg.actions.append(action)
      #< Add an output action, and send -- similar to resend_packet() >
      self.connection.sent(msg)

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)
  
  def arp_send(self,packet, packet_in):
      arpPacketProtocol = packet.payload

      # ARP reply
      if arpPacketProtocol.opcode == pkt.arp.REQUEST:
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
          self.mac_to_port[packet.src] = packet_in.in_port
          log.debug("Display the mac_to_port dictionary(REQUEST)")
          log.debug(self.mac_to_port)

      elif arpPacketProtocol.opcode == pkt.arp.REPLY:
          log.debug("ARP reply reveived")
          self.mac_to_port[packet.src] = packet_in.in_port
          log.debug("Display the mac_to_port dictionary)(REPLY)")
          log.debug(self.mac_to_port)
      else:
          log.debug("Other arp")

  def unreachable_send(self,packet,packet_in):

      msgUnreachable = pkt.unreach()
      msgUnreachable.payload = packet.payload

      #set icmp 
      icmpReachable = pkt.icmp()
      icmpReachable.type = pkt.TYPE_DEST_UNREACH
      icmpReachable.payload = msgUnreachable

      #encapsulate icmp into packet
      icmpPkt = pkt.ipv4()

      for net_ip in self.routing_table.keys():
          if packet.payload.srcip.inNetwork(net_ip):
              dst_subnet = net_ip
      dst_ip = self.routing_table[dst_subnet][2]
      log.debug("unreachable packet source ip %s"%(str(dst_ip)))

      icmpPkt.srcip = IPAddr(dst_ip)  #change the source ip to router's ip
      icmpPkt.dstip = packet.payload.srcip 
      icmpPkt.protocol = pkt.ipv4.ICMP_PROTOCOL
      icmpPkt.payload = icmpReachable

      #encapsulate packzet into frame
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

  def ipv4pkt_send(self, packet, packet_in):
      subnetMatch = 0
      log.debug("ipv4 function pkt send src ip %r dst ip %r"%(packet.payload.srcip,packet.payload.dstip) )
      for subnetID in self.routing_table.keys():
          if packet.payload.dstip.inNetwork(subnetID):
              subnetMatch = subnetID
              break
      if subnetMatch == 0:
          log.debug("the ipv4 pkt is unreachable")
          
      else:
          log.debug("forward the packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))
          if (str(packet.payload.dstip) == self.routing_table[subnetMatch][0]):
              
              packet.src = packet.dst
              mac_of_dst = self.routing_table[subnetMatch][4]
              packet.dst = EthAddr(mac_of_dst)
              msg = of.ofp_packet_out()
              msg.data = packet.pack()

              action = of.ofp_action_output(port = self.routing_table[subnetMatch][3])
              msg.actions.append(action)
              self.connection.send(msg)
          
          else:
            pass
         

  def act_like_router(self,packet,packet_in):
      if packet.type == pkt.ethernet.ARP_TYPE: #if the packet's type is ARP
          #protocol = packet.payload
          self.arp_send(packet, packet_in)
      elif packet.type == pkt.ethernet.IP_TYPE: #if the packet's type is ipv4ip
          log.debug("IPTYPE packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))
          ipPkt = packet.payload
          ipDstAddr = ipPkt.dstip  #extract the ip of dst
          
          if ipPkt.protocol == pkt.ipv4.ICMP_PROTOCOL: #judge whether it is a ICMP
              icmpPacket = ipPkt.payload
              if icmpPacket.type == pkt.TYPE_ECHO_REQUEST:
                  log.debug("ICMP request received")
                  log.debug("dst ip: %r"%(ipDstAddr))

                  #determine whether the ip is reachable
                  dstIPMatch = 0

                  #determine whether the ip can be found in routing_table
                  for subnetID in self.routing_table.keys():
                      if ipDstAddr.inNetwork(subnetID):
                          dstIPMatch = subnetID
                          break

                  #if unreachabe
                  if dstIPMatch == 0:
                      log.debug("ip address is unreachable")
                      self.unreachable_send(packet, packet_in)
                  else:
                      log.debug("The subnet of ICMP's ip address is in the routing table")
                      if str(ipDstAddr) == self.routing_table[dstIPMatch][2]:
                          self.reachable_send(packet, packet_in)
                      
                      elif str(ipDstAddr) == self.routing_table[dstIPMatch][0]:

                          packet.src = packet.dst
                          packet.dst = EthAddr(self.routing_table[dstIPMatch][4])
                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = self.routing_table[dstIPMatch][3])
                          msg.actions.append(action)
                          self.connection.send(msg)

                      else:
                          self.unreachable_send(packet, packet_in)

              #if it is not ICMP echo request
              elif icmpPacket.type == pkt.TYPE_ECHO_REPLY:
                  dstIPMatch2 = 0
                  # judge whether the ip can be found in routing_table
                  for subnetID2 in self.routing_table.keys():
                      if (packet.payload.dstip).inNetwork(subnetID2):
                          dstIPMatch2 = subnetID2
                          break

                  packet.src = packet.dst
                  packet.dst = EthAddr(self.routing_table[dstIPMatch2][4])

                  msg = of.ofp_packet_out()
                  msg.data = packet.pack()
  
                  action = of.ofp_action_output(port = self.routing_table[dstIPMatch2][3])
                  msg.actions.append(action)
                  self.connection.send(msg)
 
              else:
                  pass
          # if the ipv4 packet is not ICMP
          else:
              log.debug("not ICMP, forward to other subnets")
              self.ipv4pkt_send(packet, packet_in)
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
        log.debug("EVENT packet from %r to %r"%(packet.payload.srcip, packet.payload.dstip))


    self.act_like_router(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    RouterExercise(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
