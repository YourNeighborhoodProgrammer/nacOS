from nacOS.main import *


if SoftwareCheck() == False:
    raise Exception("nacOS has been corrupted. A software reset must be performed, use reset.py to reinstall the software.")
Startup()
MainLoop()
