# import argparse
import socket
import asyncore
import struct
from pingClass import Ping


def ping(destination_addr, count, packetsize, timeout=1):
  """
  ping(destination_addr: string, count: int, packetsize: int)
  """
  ttl = 0
  IP = socket.gethostbyname(destination_addr)
  print(f'PING {destination_addr} ({IP}) {packetsize}({packetsize + 28}) bytes of data')

  for i in range(count):
    pingInstance = Ping.Ping(destination_addr, count, packetsize)

    # enter polling loop that terminates after count passes or all open channels have been closed
    # timeout argument is essential incase destination_addr refuses to reply
    # and thus prevent endless loop
    asyncore.loop(timeout)

    time_taken = round(pingInstance.delay_time() * 1000)
    packet_data = pingInstance.recv_packet

    ICMP_header = pingInstance.prettifyHeader(
              names=[
                    "type", "code", "checksum",
                    "packet_id", "seq_number"
                ],
                struct_format="bbHHH",
                data=packet_data[20:28]
            )

    # verify packet received is packet sent
    if ICMP_header["packet_id"] == pingInstance.app_packet_id:
      IP_header = pingInstance.prettifyHeader(
                    names=[
                        "version", "type", "length",
                        "id", "flags", "ttl", "protocol",
                        "checksum", "src_ip", "dest_ip"
                    ],
                    struct_format="BBHHHBBHII",
                    data=packet_data[:20]
                )
      packet_size = len(packet_data) - 28
      ip = socket.inet_ntoa(struct.pack("!I", IP_header["src_ip"]))
      ttl = IP_header['ttl']
      icmp_seq = ICMP_header["seq_number"]
        
    print(f'{packetsize + 8} bytes from {IP} ({IP}): icmp_seq={i+1} ttl={ttl} time={time_taken} ms')
  
  print('\n')
  print(f'--- {destination_addr} ping statistics ---')


