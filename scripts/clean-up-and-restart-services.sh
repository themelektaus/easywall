#!/bin/bash

echo "Stopping easywall services..."
service easywall-web stop
service easywall stop

echo "Cleaning up..."
rm -rf /home/easywall/easywall/backup
rm -rf /home/easywall/easywall/easywall/__pycache__
rm -rf /home/easywall/easywall/easywall/web/__pycache__
rm /home/easywall/easywall/.acceptance_status
rm /home/easywall/easywall/.acceptance
rm /home/easywall/easywall/.apply
rm /var/log/easywall.log
#rm /var/log/syslog*

echo "Starting easywall services..."
service easywall start
service easywall-web start

echo "Done"
