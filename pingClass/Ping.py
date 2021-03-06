import socket
import struct
import time
import select
import random
import asyncore
from sys import exit
from socketErrors import socket_errors

icmpProto = socket.getprotobyname('icmp')

class Ping(asyncore.dispatcher):
  """
  Ping class based on asynchronous socket
  handler dispatcher class.
  """
  def __init__(self, destination_addr, timeout, sizeofpacket):
    """
    - destination_addr is remote server address to ping
    - timeout is maximum allowable time destination_addr should reply host

    """
    asyncore.dispatcher.__init__(self)

    self.destination_addr = destination_addr
    self.app_packet_id = random.randint(0, 65535)
    self.timeout = timeout
    self.sizeofpacket = sizeofpacket
    self.packet = self.packetCreator(self.app_packet_id, sizeofpacket)
    self.time_packet_is_sent = 0
    self.time_packet_is_received = 0
    self.recv_packet = ''

    # create a socket interface
    try: 
      self.create_socket(socket.AF_INET, socket.SOCK_RAW, icmpProto)
      # second element of tuple is mandatory but icmp does not use port
      # so a random port was used
      self.connect( (self.destination_addr, 1) )
    except socket.error as err:
      if err.errno in socket_errors.linux_socket_errors:
        raise socket.error(''.join((err.args[1], socket_errors.linux_socket_errors[err.errno])))
      raise

  def create_socket(self, family, type, icmp_proto):
    """
    Ping.create_socket(family, type, icmp_proto: int) -> None
    - family is the address structure to be used on the socket API
    - type is the socket type to use (a raw socket in this case)
    - icmp_proto is the ICMP protocol number

    creates a non-blocking socket interface
    """
    socket_interface = socket.socket(family, type, icmpProto)
    socket_interface.settimeout(0) # raise exception if socket has no data to receive or send

    self.set_socket(socket_interface)

  def checksumCreator(self,octet_sequence, sum=0):
  
    """ 
    Derived from mdelatorre/checksum 
    (https://github.com/mdelatorre/checksum/blob/master/ichecksum.py)

    Computes the Internet Checksum of the supplied data.  The checksum is
    initialized to zero.  Place the return value in the checksum field of a
    packet.  When the packet is received, check the checksum, by passing
    in the checksum field of the packet and the data.  If the result is zero,
    then the checksum has not detected an error.
    """
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in range(0,len(octet_sequence),2):
        if i + 1 >= len(octet_sequence):
            sum += ord(octet_sequence[i]) & 0xFF
        else:
            w = ((ord(octet_sequence[i]) << 8) & 0xFF00) + (ord(octet_sequence[i+1]) & 0xFF)
            sum += w

    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # one's complement the result
    sum = ~sum

    return sum & 0xFFFF
  
  def packetCreator(self, packet_id, packet_size):
    """
    packetCreator(packet_id: integer, packet_size: integer) -> bytes

    ICMP packet consist of header (8bytes)  + variable length payload
    header: 
      standards are ICMP message type(8 bits), code(8 bit), checksum(2 bytes),
      application_id (2 bytes),
      and sequence number(2 bytes)

      - application_id must be unique for every ping process
      - sequence number is an int that increments within a specific ping process

      - application_id and sequence number is mandatory in order
        to deliver replies to right process since ICMP does not 
        utilize ports (like TCP and UDP).

      https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

    """
    icmp_MessageType, icmp_Code  = 8, 0    # defaults

    # handle negative packet size
    if packet_size < 0:
      print(f'ping: illegal negative packet size {packet_size}')
      exit(2)
    # construct packet header and payload
    packet_Header = struct.pack('BBHHH', icmp_MessageType, icmp_Code, 0, packet_id, 1)
    payload = bytes('loudpipes', 'utf-8')

    icmp_Message = str(packet_Header + payload)

    checksum = self.checksumCreator(icmp_Message)
    network_byte_order_checksum = socket.htons(checksum) # convert 16bit host byte checksum
    
    # update checksum with calculated value
    packet_Header = struct.pack('BBHHH', icmp_MessageType,
                                icmp_Code, network_byte_order_checksum, packet_id, 1)
    return (packet_Header + payload)

  def handle_write(self):
    """
    writes data to the socket as a byte stream
    """
    self.time_packet_is_sent = time.time()
    while self.packet:
      # send data to the socket interface created

      socket_send_to_mock_port = 80 # can be any random port since ICMP does not use ports
      sent = self.send(self.packet)

      self.packet = self.packet[sent:]  # empty packet after sending
  
  def writable(self):
    """
    Ping.writable() -> Bool

    checks if the packet byte stream is not empty.

    - A recquired check for adding the channel socket 
    to the write events list 
    """
    return len(self.packet) > 0

  def readable(self):
    if (self.writable == False and (self.timeout < (time.time() - self.time_packet_is_sent))):
      # channel socket is idle (i.e; packet has just been sent) and time for server to reply has elapsed
      self.close()
      return False
    
    return not self.writable()

  def handle_read(self):
    time_byte_is_read = time.time()

    # 1024 is the max receivable byte. Actual might be less
    rec_packet= self.recv(1024)
    self.recv_packet = rec_packet

    # extract the encapsulated ICMP packet header from the buffer received
    icmp_header = rec_packet[20:28] # since 8 bytes was packed and sent initially

    type, code, checksum, app_pid, sequence = struct.unpack('bbHHH', icmp_header)

    if app_pid == self.app_packet_id:
      self.time_packet_is_received = time_byte_is_read
      self.close()
  
  def prettifyHeader(self, names, struct_format, data):
    """ 
    Ping.prettifyHeader(names: object, struct_format: Union[bytes, Unknown],
    data: Union[bytes, bytearray]) -> dict

    unpacks received packet header to a dict
    """
    unpacked_data = struct.unpack(struct_format, data)
    return dict(zip(names, unpacked_data))

  def delay_time(self):
    if self.time_packet_is_received > 0:
      return (self.time_packet_is_received - self.time_packet_is_sent)
