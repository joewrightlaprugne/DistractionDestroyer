# Distraction Destroyer
Windows desktop app which allows users to temporarily block apps and websites of their choice.

The program scans the user's desktop and start menu for installed programs and displays them in a list. Users can select one or more programs from this list and block them. This is done via the Windows Registry using volatile keys (REG_OPTION_VOLATILE) which disappear when the system is restarted, ensuring that the programs do not stay permanently blocked in the event that the PC crashes.

The program also allows users to block access to one or more domain names, which is done using Windows Filtering Platform and the Winsock API.

Most of wfp.cpp is based off [this project by Mahesh Satya](https://www.codeproject.com/Articles/29026/Firewall-using-Vista-s-Windows-Filtering-Platform), released under the Code Project Open License (CPOL).

## Screenshot:

![Distraction Destroyer interface](https://raw.githubusercontent.com/joewrightlaprugne/DistractionDestroyer/main/DD1.png)
