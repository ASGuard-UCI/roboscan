#!/bin/bash

outfile=$(date +"%Y%m%d-%H%M").json

## Tests
# sudo zmap -B 1M -p 11311 127.0.0.0/8 --max-targets=10000 | aztarna -t ROS -p 11311 -o $outfile -e
# sudo zmap -B 1M -p 11311 0.0.0.0/0 --max-targets=100000 | aztarna -t ROS -p 11311 -o $outfile -e
# sudo zmap -B 1M -p 11311 128.195.4.61/24 --max-targets=10000 | aztarna -t ROS -p 11311 -o $outfile -e

## Real run
sudo zmap -B 10M -p 11311 0.0.0.0/0 | aztarna -t ROS -p 11311 -o $outfile -e
