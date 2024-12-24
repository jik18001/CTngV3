#!/bin/bash
SESSION="network"

# Start a new tmux session
tmux new-session -d -s $SESSION

tmux new-window -n "network_monitor_1" bash -c 'go run -race ctng.go Monitor M1 local > monitor_1.log 2>&1'
tmux new-window -n "network_monitor_2" bash -c 'go run -race ctng.go Monitor M2 local > monitor_2.log 2>&1'
tmux new-window -n "network_monitor_3" bash -c 'go run -race ctng.go Monitor M3 local > monitor_3.log 2>&1'
tmux new-window -n "network_monitor_4" bash -c 'go run -race ctng.go Monitor M4 local > monitor_4.log 2>&1'
sleep 1

tmux new-window -n "network_ca_1" bash -c 'go run -race ctng.go CA C1 local > ca_1.log 2>&1'
#tmux new-window -n "network_ca_2" bash -c 'go run -race ctng.go CA C2 local > ca_2.log 2>&1'
#tmux new-window -n "network_ca_1" bash -c 'go run -race ctng.go CAD C1 local > ca_deter.log 2>&1'
tmux new-window -n "network_logger_1" bash -c 'go run -race ctng.go Logger L1 local > logger_1.log 2>&1'
#tmux new-window -n "network_logger_2" bash -c 'go run -race ctng.go Logger L2 local > logger_2.log 2>&1'

# Attach to the tmux session
tmux attach-session -t $SESSION
