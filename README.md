# FBCD NetTOOL

1- CSV Inventory File auto convert to Yaml while Program Run
2- On inventory Page can see Fact/ARP/Interfaces and Traceroute Details
3- Configure same group devices from a file having configuration commands
4- Save show command output to App Directory on Groupbase or Single device Name
5- Commit Changes after seen Ok
6- Can run show command on device Like CLI
7- Backup Running Configs to App directory on Groupbase

# Install
pip install requirement.txt
run .py file
localhost:5000 in browser 

# PreReq
- Knowledge of Nornir, Flask and HTML/JavaScript is required
- Start APP just double click on Python File
- In Inventory  Each device Link to their Facts,Interface status and ARP table.under IP heading link to Traceroute result.
- You Can backup devices configuration to App dir. Folder by groups by using Nornir Napalm or Nornir Netmiko Command
- show command output save to App dir. by group with date tag
- Add new configuration to device from file groupwise, and then commit changes in other window.
- In commander Page can execute show command by device name output to same page. Like CLI