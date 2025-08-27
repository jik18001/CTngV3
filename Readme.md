
# CTng: Certificate and Revocation Transparency

This is a Proof of Concept/Prototype code for Periodic Consistent Broadcast Protocol in CTng. Each entity can be found in their corresponding folder.

## Software Requirements (for local testing)

- Ubuntu 22.04
- Golang 2.23
- g++ (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0
- tmux terminal multiplexer

## Running Tests Locally 

#### Change the variables in the def/testsettings.json file.
#### Modify the run.sh file to run more entities. 

And execute 
 ```
sh run.sh 
 ```
in the project root directory 

## Disclaimer: 
### 1. Only the Logger related functionalities are actively maintained.
### 2. This repository does not simulate Logger/CA misbehaviors. 


## Running Tests with Deterlab TestBed (Sphere Research infrasture)

Link to the testbed: 

https://launch.sphere-testbed.net/


# Model 
The model file creates a star topology as shown in the figure below: 

![image](https://github.com/user-attachments/assets/ebc51907-91f9-44cf-89da-249f72210f03)

Every entity (including a control node) is connected to the backbone router via a 100Mbps access link. 



# Operations from the XDC
## 1. Generate Inventory

> **Note:** Replace `<USERNAME>`, `<PATH_TO_CTNGEXP>`, and `<SOURCE_HOST>` with your actual details.

> You will also need to modify the automation scripts for replication. 

1. Open a root shell in a new terminal and navigate to your CTngexp directory:

   ```bash
   cd <PATH_TO_CTNGEXP>
   ```
   ```bash
   sudo su          
   ```
2. Generate the Ansible inventory file:

   ```bash
   python3 genini.py   
   ```
3. Switch back to your non-root user:

   ```bash
   exit              
   ```
   ```bash
   su <USERNAME>     
   ```

## 2. Distribute Playbooks
Distribute the CTngexp folder:
```bash
ansible-playbook -i inv.ini distribute.yml  
```
From the CTngexp directory, run:

```bash

ansible-playbook -i inv.ini ssh.yml         
```
# Operations from the control Node

## 3. Configure Ansible

Create or update an ansible.cfg file in the project root with:

```ini
[defaults]
forks = 60
timeout = 60
retry_files_enabled = False
async_poll_interval = 5

[ssh_connection]
pipelining = True
```

> **Reminder:** If you modify control-node settings or delete this file, recreate it accordingly.

## 4. Install Prerequisites

```bash
sudo apt update
sudo apt install ansible
```

## 5. Bootstrap All Hosts

Run these playbooks to install prerequisites and Go on every host:

```bash
ansible-playbook -i inv.ini gpp.yml      
ansible-playbook -i inv.ini newgo.yml    
```

Verify on any host:

```bash
ssh <HOSTNAME>
```
```bash
g++ --version
```
```bash
go version
```

## 6. Repository Setup & Distribution

1. **Initial checkout/setup**

   ```bash
   ansible-playbook -i inv.ini repo.yml
   ```
2. **Propagate code changes** (e.g., edits in gen\_test.go)

   ```bash
   ansible-playbook -i inv.ini redis.yml
   ```

## 7. Run the Experiment

From the control node in your CTngexp directory:

```bash
ansible-playbook -i inv.ini ctngv3.yml
```

## 8. Iterating on Experiments

#### 1. Edit your test code (e.g., CTngV3/deter/gen\_test.go).
#### 2. Redistribute

   ```bash
   ansible-playbook -i inv.ini redis.yml
   ```
#### 3. rerun and collect result
   ```bash
   go test ./CTngV3/deter
   ```
   ```bash
   ansible-playbook -i inv.ini ctngv3.yml
   ```
   ```bash
   ansible-playbook -i inv.ini collect.yml
   ```
   or Run experiment for 30 iterations and automatically collect results for every run :
   ```bash
   sh run.sh
   ```


## 9. Retrieve Results & Cleanup

1. **Copy back to XDC:**

   ```bash
   ansible-playbook -i inv.ini copy.yml
   ```
2. **Clean up temporary files on control node:**

   ```bash
   rm -rv output output.tar.gz monitor_files
   ```
## 10. Copy to local machine 
   ```bash
   mrg xdc scp download -r <path_to_folder_on_XDC> <path_local_destination_folder>
   ```
   ```bash
   mrg xdc scp download  <path_to_file_on_XDC> <path_local_destination_folder>
   ```

# Results
### K = f + 1
Results were obtained by Damon James from the University of Connecticut using CTngV3 repository with Commit ID:
```
fe0941c
```
Link:
```
https://github.com/jik18001/CTngV3/commit/fe0941cc115a9085c43b0c48cf64c95086f338dd
```

![image](https://github.com/user-attachments/assets/79f05636-7404-4c56-97e3-672516a68a67)

### K = floor (n/2)
Results were obtained using CTngV3 repository with Commit ID (Only 4 LoC change): 
```
6270562
```
Link:
```
https://github.com/jik18001/CTngV3/commit/62705624cb16bdd9e9a7eb46281bc43590a4b61e
```
<img width="978" height="641" alt="image" src="https://github.com/user-attachments/assets/ff1755a3-6d00-461e-9d64-72f8d0eaf3de" />


