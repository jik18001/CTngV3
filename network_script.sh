#!/bin/bash
SESSION="network"

# Start a new tmux session
tmux new-session -d -s $SESSION

tmux new-window -n "network_monitor_1" go run ctng.go Monitor M1
tmux new-window -n "network_monitor_2" go run ctng.go Monitor M2
tmux new-window -n "network_monitor_3" go run ctng.go Monitor M3
tmux new-window -n "network_monitor_4" go run ctng.go Monitor M4
tmux new-window -n "network_ca_1" go run ctng.go CA C1
tmux new-window -n "network_ca_2" go run ctng.go CA C2
tmux new-window -n "network_logger_1" go run ctng.go Logger L1
tmux new-window -n "network_logger_2" go run ctng.go Logger L2

# Attach to the tmux session
tmux attach-session -t $SESSION
