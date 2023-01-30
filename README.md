# Applied-Cryptography-and-Authentication
COMP 3109 Applied Cryptography and Authentication Coursework

If you already have Python 3.10 or later installed, you’ll need to
install Python 3.9, since 3.10 is currently unsupported by Tink. To
determine what version of Python you are using:
  python3 --version //for Ubuntu
  
To install Python 3.9 on Ubuntu using APT, run the commands below. A new
binary called python3.9 will be available in your path. Update your aliases to
use this binary instead of the system default python3 or python.
  sudo add-apt-repository ppa:deadsnakes/ppa
  sudo apt install python3.9 python3.9-distutils
  python3.9 -m pip install pynacl tink protobuf==3.20.*
  
PyNaCl is a Python binding to libsodium, which implements the NaCl library.
It can be installed directly from PyPi by doing:
  pip3 install pynacl
  
The Python implementation of this library (known simply as tink) can be installed 
from PyPi (see documentation) by running:
  pip3 install tink
  
  
