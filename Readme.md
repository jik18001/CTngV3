
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

## Running Tests with Deterlab TestBed (Sphere Research infrasture)

Please refer to 

https://github.com/jik18001/CTng-on-Sphere/tree/main

Link to the testbed: 

https://launch.sphere-testbed.net/


## Disclaimer: 
### 1. Only the Logger related functionalities are actively maintained.
### 2. This repository does not simulate Logger/CA misbehaviors. 
