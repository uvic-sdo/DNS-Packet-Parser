#!/bin/sh

sudo ifconfig wlan0 down

#sudo killall NetworkManager
#sudo killall dhcpd
#sudo killall wpa_supplicant

sudo iwconfig wlan0 mode Monitor
sudo ifconfig wlan0 up

sudo ./sniff
#iwconfig
