
# CTng: Certificate and Revocation Transparency

This is a Proof of Concept/Prototype code for Periodic Consistent Broadcast Protocol in CTng. Each entity can be found in their corresponding folder.
## Code Structure

- **Monitor, Logger, and CA**:  
  Each has its own folder containing the corresponding implementation.  

- **`CTngV3/def`**:  
  Contains most variable definitions, wrapper functions, and configuration files for local testing.  

- **`CTngV3/deter`**:  
  Includes the model used on Sphere, configuration files for Sphere testing, a simple Python script for computing convergence time, and the `CTngexp` folder.  

- **`CTngV3/deter/CTngexp`**:  
  Contains all automation scripts used to:  
  - Set up the software toolchain on all VMs on Sphere.  
  - Automate experiment execution.  
  - Collect and timestamp experiment results.  

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
- 1. Only the Logger related functionalities are actively maintained.
- 2. This repository does not simulate Logger/CA misbehaviors. 


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

## 6. Running Experiments

#### 6.1 **Initial checkout/setup**
```bash
ansible-playbook -i inv.ini repo.yml
```
#### 6.2 Modify variables 
Modify the variables in 
```
CTngV3/deter/gen_test.go
```
and run (while in CTngV3/deter)
```
go test
```
to apply the changes to the control node. The new setting files now need to be distributed to all the other hosts.

#### 6.3 Redistribute
To distribute the new configuration files to other hosts, navigate to 
```
CTngV3/deter/CTngexp
```
and run
```bash
ansible-playbook -i inv.ini redis.yml
```
To make sure changes are applied properly to all the monitors,open up a new terminal and execute
```bash
su jik18001
```
to switch to user mode and ssh to any monitor by running

```bash
ssh monitor8
```
Then navigate to the CTngV3/deter to check if the changes have been applied by running

```bash
cat detersettings.json
```

#### 6.4 Run and collect result
Nevigate to CTngV3/deter/CTngexp and execute
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
#### 6.5 compute the result
Navigate to the folder where the output folder is placed in (/tmp), make sure the compute.py is in the same folder (copy from CTngV3/deter/compute.py if not) and run
```
python3 compute.py output [Replace _with_number_of_monitors]
```

#### Clean up temporary files on control node:
```bash
rm -rv output output.tar.gz monitor_files 
```
## 6 Copy to local machine 
   **Copy from control to XDC:**
   ```bash
   ansible-playbook -i inv.ini copy.yml
   ```
   **Copy from XDC to local:**
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


