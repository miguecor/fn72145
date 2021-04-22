# fn72145.py

This script will connect to a provided list of APIC controllers and pull 
information about the affected objects of the FN-72145.

## Requirements

To run the script just make sure that you have installed the required libraries:

`pip3 install -r requirements.txt`

This script only works with Python 3.7 and above.

## Usage

The list of APIC controllers is provided in the `credentials.py` file:

For a single APIC:

`APICS = ['1.1.1.1']`

For more than one APIC:

`APICS = ['1.1.1.1', '2.2.2.2', '3.3.3.3']`

Username and password information is also provided in the `credentials.py`
file. Remember that all the APICs should have the same username and password.

For the FN-72145 it is redundant to query more than 1 APIC of the same fabric 
since they will provide the same information.

After querying the APICs, the script will gather connectivity information from 
the ACI switches and will SSH to the affected switches to verify the 
Power_On_Hours of each switch.

## Results

All the gathered information will be dumped in a `fn72145_check.log` file.

## Binaries

Binary files have been provided in the _Binaries_ folder.  These files will be
helpful for clients who cannot run python scripts in their corporate computers.

The usage of these binaries are a little bit different.  For the Windows binary 
(`fn72145.exe`) the user needs only to double-click on the binary file.  A 
series of prompts will require the user to enter some information.  After 
providing all the information, the log file will be created with the data 
gathered from a single ACI fabric.  For multiple fabrics, the binary can be run 
as many times as needed.

## Collaborate

Feel free to collaborate, both by requesting new features/changes to the 
script or by branching the project and adding changes and raising a pull request.