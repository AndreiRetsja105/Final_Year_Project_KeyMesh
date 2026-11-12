# KeyMesh
-----------------------------------------------------------------------------------------------------------
Distributed Key Management for Protecting Medical Records (National College of Ireland, final-year project, 2026/27).
------------------------------------------------------------------------------------------

**Idea:** 
The main ides is makes all records are encrypted using AES256GCM, with a unique data key employed for each particular record ( by the envelope encryption). The master key is never stored in its entirety in one place: instead, it is distributed across eight independent key services using Shamir’s Secret Sharing algorithm which is requiring 5 out of 8 shares.
Each key service provides its share only for a short duration for one-time use-in the form of a signed decryption ticket bound to a specific user, record, and security epoch. The objective is to

**measure** 
How many independent components must an attacker compromise before they can recover the plaintext?

>Academic prototype. For development purposes only. **Synthetic data only, never real patient data.**

## Status

early development: work package 1 (infrastructure) is complete.
|--------------------------------------------------------------------------|
| Area | State |
---------------------------------------------------------------------------------------------------
| AES 256 GCM, envelope encryption, Shamir's scheme (5 out of 8 keys), signed tickets with anti-replay protection |Done, the device has been tested. 
| done - key service (loads a single shared resource, validates tickets) 
| done - Docker Compose: 13 containers, isolated networks, secure containers 
| done - CI (testing and image building on every push) 
-------------------------------------------------------------------------------------------------
next steps 

| provision of keys for tickets, cryptographic service, API for encryption/decryption >>> next (WP2)
| planed - system login, multi-factor authentication (TOTP MFA), roles, data service, mutual TLS
| planed - attack scenarios and security assessment: 

## Architecture

--------------------------------------------------------------------------------------------------------------
Internet >>>> api_gateway (only published port, :8443)

  internal network
        + auth_service      (tickets, later:login, MFA)
        + data_service      (records, later:storage)
        + crypto_service    (only service on the "keys" network)


  keys network
        + key service 1 key service 8 (one share each)
            postgres (db network only)
----------------------------------------------------------------------------------------

Containers run as a non root user with a read only file system: furthermore, all Linux capabilities are disabled, and the acquisition of new privileges is prohibited.

## Quick start (Windows, PowerShell)

Requires Python 3 and Docker Desktop (engine running)

|-------powershell commands---------|

py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r services/requirements.txt pytest
pip install -e ./libs/keymesh_common

python -m pytest test_for_keymesh        # unit and smoke tests

copy .env.example .env                   # development values
python scripts/init_keys.py              # creates secrets/shares/share_1 of 8.txt 

(git-ignored)
docker compose up --build
-------------------------------------------------------------------------------------------

Check: http://localhost:8443/health returns {"service":"api_gateway", ... "status":"ok"}

each key service reports share_loaded: true on its internal /health:

----------powershell side------------------------------------------------------------------------
ForEach Object { docker compose exec key-service-$_ python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/health').read())" }
-----------------------------------------------------------------------------------------------

Stop with `docker compose down`.

## Repository layout

---------------------------------------------------------------------------------
libs/keymesh_common/   crypto (AES-GCM, envelope, Shamir) and decryption tickets
services/              one folder per microservice, single shared Dockerfile
scripts/               development helpers (init_keys.py)
test_for_keymesh/      unit and smoke tests
journal/               weekly reflective journal (Driscoll: What? So what? Now what?)
.github/workflows/     CI
-----------------------------------------------------------------------------------------

## Security notes

- The .env files and the secrets/ directory have been added to .gitignore they must never be included in commits section.
- There is a known limitation: the main problem is at during the decryption process, the key is briefly reconstructed in RAM. Measures are planned to mitigate the associated risks for example restricting access via tokens, using unique keys for specific records, shortening key lifespans. Teh future plans should include the potential implementation of threshold cryptography fro example, hardware security modules, and trusted execution environments.
