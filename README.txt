CIA RP REAL SYSTEM
==================

No launcher/START.bat is included.

Server device:
1) Install Node.js 20+.
2) Open a terminal in this folder.
3) Run: npm install
4) Run: npm start

The server listens on 0.0.0.0:3000 so other devices on the same network can connect.

On another PC/phone/tablet:
Open: http://SERVER-LAN-IP:3000
Example: http://192.168.1.20:3000

If Windows Firewall asks about Node.js, allow Node.js on Private networks.
Do not expose port 3000 directly to the public internet without proper HTTPS, firewall rules, and production hardening.
