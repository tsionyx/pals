#!/bin/sh

for challenge in 4 6 7 8; do
  wget -nc https://cryptopals.com/static/challenge-data/$challenge.txt
done
