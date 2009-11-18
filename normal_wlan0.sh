#!/bin/sh


sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode Managed
sudo iwconfig wlan0 power auto
sudo NetworkManager
sudo ifconfig wlan0 up

