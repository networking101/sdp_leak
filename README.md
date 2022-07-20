Dependencies:

    pip2 packages: pybluez, pwn
    
    - sudo apt-get install libbluetooth-dev
    - sudo pip2 install pybluez pwn

    A CSR USB bluetooth adapter. We need to change the MAC address, and so we use a vendor specific HCI command to do this
    for the CSR bluetooth adapter.
    - An alternative adapter can also be used - the only thing to alter is the set_rand_bdaddr function.

Here is an example to execute.

./arey.py -h                                                          
usage: arey.py [-h] -s SOURCE_BMAC -t TARGET_BMAC -n LEAK_NUMBER [-l LOGGING_LEVEL]

options:
  -h, --help        show this help message and exit
  -s SOURCE_BMAC    source BMAC
  -t TARGET_BMAC    target BMAC
  -n LEAK_NUMBER    number of times to leak target
  -l LOGGING_LEVEL  logging level for output

./arey.py -s "00:01:95:5A:32:52" -t "94:B2:CC:A6:B2:61" -n 20 -l DEBUG