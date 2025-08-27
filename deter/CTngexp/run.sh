#!/bin/bash

for i in $(seq 1 30); do
  echo "=== Iteration $i: Running CTngV3 ==="
  ansible-playbook -i inv.ini ctngv3.yml

  echo "=== Iteration $i: Running Collect ==="
  ansible-playbook -i inv.ini collect.yml
done

echo "All 30 iterations completed!"
