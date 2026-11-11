##  Week 45 (2 Nov – 8 Nov 2026)
----------------------------------------------------------
Time spent: I worked on Work Package 1 Infrastructure was completed November 6, after which I began Work Package 2 | Plan status: Work Package 1 is running about a week behind schedule was planned completion date on November 1 due to issues encountered during the testing phase: meanwhile, work on the cryptographic library is ahead of schedule.

--------------------------------------------------------------------------
## What? 
I ran the test suite on my laptop on Pythin 3 for the first time: 16 tests passedm and 10 was failed.
All errors/issues were traced back to two files:tickets.py: The issue( ) method was nested inside the _init_ due to incorrect indentation, making it inaccesssible. Additionally, in a first place _keysign was being called instate of _key.sign which is was wrong , and b64decode was used instate of b64encode within the encode( ) method which is was wrong to. key_service/app/main.py: also the two functions shared the same name, _load_share. I fixed them one by one, running pytest after each change: ultimatelly, all 26 test passed

I discovered that the test were using an installed copy of keymesh_common rather than the source files I had edited: since the pip install command creates a copy. I switched to using pip install (editable mode).

I corrected the Docker files: in DockerFile , Iremoved a space in the path /tmp/keymesh_common which had caused the (rm -rf) command to attempt to delete the root directory: I added uvicorn[standard] to requirements: I fixed exit_ok and to_hex_( ) in init_keys.py: and in docker-compose.yml, I update the service name from auth_service to authentification_service (to mach the folder name).

I installed Docker Desktop. The docker is not recognize error indicated that the program was not installed: later , the docker info command only showed the client sied components until the Docker engine itself was started. Initial run of docker compose up --build: 13 containers were brought up (gateway, auth, data, crypto, 8 instance of key services, and Postgres) The localhost 8443/health endpoint returned a successful responce. Only the gateway exposes a port.

Isolation check: crypto_service can communicate with key_service_1 while api_gateway returns a Name or service not know error.

All 8 instance of key_service reported share_loaded; false, even though the share file had been successfully mounted 69 bytes in size. I suspected OneDrive  - the project path contained OneDrive and a parenthesis, so I moved th eproject to - C:\dev\keymes, but the situatuion remained unchanged. The reason was as follows: to resolve a `NameError`, I had changed the call to `_load_share()` instead of renaming the second function. As a result, both `SHARE` and `VERIFIER` were being loaded using the same mechanism—the public key loader—which caused the `SHARE` variable to always remain `None`. I renamed the second function to `_load_verifier` and rebuilt the project; this fixed the issue—all 8 components now function correctly, and the `share_loaded` parameter is set to `true`.

All 26 test remained Green even when no  key shares were loaded, because the basic smoke tests only covered the not configured scenario HTTP 503. The new python file, test_key_service_provisioned.py containing 7 extra tests, which help to verifies the following scenarios: loading a key share when the corresponding file is present, and combining five splitet shares from five diffirent services inti a single key used to decrypt a record. As well as the handlling of invalid request - such as reused tickets, tickets from an outdate security epoch, and tickets wich was a signed with an unknow key. In total, 33 test were succesfully passed. When I during the test writing process, I also managed to uncover several typos of my own - an extra underscope in _file_, errors in folder names and record identifiers, it was inncorect signatures, and the use of the wrong record in a test case involving tickets reuse.involving tickets reuse.

##  So what? 
-----------------------------------------------------------------------------
The 26 tests remained - green they passed successfully, even though no shared resource was loaded. What would need to happen for a test to fail? What did the new tests check that the old ones overlooked? - How can one distinguish a genuine fix from merely covering one's tracks? I was changed a function call, and the error disappeared. - Why didn't the tests see my modifications to the library? What is the difference between pip install and pip install -e? - Also my diagnosis regarding OneDrive turned out to be incorrect. Was moving the project justified in this case? Key shared resources and the .env file were located in a folder that was being synced with the cloud. - What it does an isolation check where the gateway cannot reach key services imply within the context of a threat model that assumes the gateway has been compromised? - Which error was the most dangerous, and why? Using the b64decode instead of b64encode does not cause a failure when importing the module. - How much time was spent on this task compared to the original plan the completion of the WP1 phase was scheduled for November 1st?

## Now what?
------------------------------------------------------------------------------
[ ]The CI on GitHub (under the Actions tab) must be - green: if there are any failed runs - red, fix the first one.

[ ]Need to remove unnecessary files from the GitHub repository (`Final_Year_Project_Keymesh/`, `build/`, `egg-info`, `__pycache__`): set the repository to private.

[ ]Key pair for a ticket: the init_keys.py script generates an Ed25519 key pair, and the key services read the public key from a file (need to write tests first).

[ ]Crypto-service: a client that collects 5 shares for a single ticket (for test we need to using stubs first).

[ ]Complete the logs for weeks 43 and 44: fill out the monthly ethics form .

[ ]Mid-point stage: submission due December 11, presentation scheduled for [ ]

[ ] It is necessary to prepare for December 14–16; clearly define exactly what can be demonstrated by this deadline.

[ ] A GUI to implement the concept discussed with the academic supervisor on November 5: begin by preparing static mockups (including a form for general practitioners, a mobile interface for patients with multi-factor authentication (MFA) support, and a demonstration console); proceed to connecting actual endpoints only once the login functionality, multi-factor authentication, and data processing capabilities are ready.

[ ]Need to record RAM usage metrics for the 13 containers using via the Stats section in Docker Desktop - this data will be needed later for the risk table.

## Supervisor
------------------------------------------------------------------------------
Meeting: November 5, 2026, with Adriana Chis. Adriana Chis is now my academic supervisor.

Topics discussed: the project and its implementation progress; the multi-service architecture; and the idea of  adding a graphical user interface (GUI) so that the project can be presented (demonstrated) at the interim stage and during the final defense.

## Evidence
------------------------------------------------------------------------------
Commits: from the commits page on GitHub
Tests: 33 passed (November 6, 2026), command: `python -m pytest test_for_keymesh`