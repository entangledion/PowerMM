# PowerMM
A Powershell-based graphical user interface utility for MineMeld. Additional functionality may be added over time.

Currently the script supports uploading the following types of MineMeld indicators:

- IPv4
    - Also supports CIDR notation
- URL
    - Also supports simple FQDN or domain name, if blocking an entire domain or sub-domain
- SHA1 File Hash
- SHA256 File Hash

Features:

- Rapid indicator ingestion into custom IPv4 & URL MineMeld Miners (nodes). Useful if you maintain custom firewall IP and URL blacklists 
  in MineMeld, or wish to feed a custom IOC list into a SIEM.
- Can upload a combined list of IPV4, CIDR, Domain Name, File Hash, and URL indicators to multiple miner nodes in a single pass.
- Option to automatically create wildcard variants of uploaded domain names.
- Control the age-out TTL of an indicator.
- Automatically stamps indicator descriptions with the user that uploaded it, and date stamp.
- Performs duplicate indicator check prior to upload to prevent duplication of addresses.
- Search option to spot-check the configured Output node/feed URLs for specific indicators or keywords.
- Multi-user support with shared upload history tracking if used from a mapped network drive.

Known Limitations:

- Current version only supports uploading to one miner node name per IOC-type, per transaction (IPv4, URL, SHA1, SHA256).
- In order to enable TTL age-out support for ingested IOCs, the miner nodes you create in MineMeld must use a clone of the following 
  built-in node type: stdlib.localDB. You should be able to locate this built-in node type in the node search box when adding a new 
  miner node in MineMeld. This built-in node type will show it supports indicator type of "ANY", and it may be listed as 
  "expiremental". This is ok. Create a clone of this node type for each blacklist and watchlist node for each of the indicator types you 
  want to ingest (IPv4, URL, SHA1, SHA256)

Instructions:

- Clone/download files to a destination folder where you want it to reside.
- Execute: powershell.exe -ExecutionPolicy bypass -C PowerMM.ps1
- You will be prompted at first execution for:
    - The industry sector of your organization.
        NOTE: This information is used to automatically populate a tag (i.e. keyword) to the incident that will be ingested into    
        ThreatConnect (if this feature is enabled). PowerMM gives you the opportunity to edit or remove this tag every time you ingest 
        an indicator.
    - The IP or hostname of your MineMeld server
      - Example: minemeld.acme.corp
    - Your MineMeld username
    - Your MineMeld password
      - Note: The MM Password is cached to disk using AES standard Powershell SecureString encryption
    
    - You will be prompted to enter the MineMeld node names that will be used for blacklists and watchlists. A blacklist can be used 
    by a firewall to dynamically block against any IOCs you add to the node, or can be used to match firewall traffic logs in a SIEM. A 
    watchlist can also be used to match firewall traffic logs in SIEM, or used to send an email notification from your SIEM any time 
    there is a match. 
    These two use-cases are supported separately in PowerMM because an admin often may not want to always block a specific IOC, but only 
    monitor activity for:

    # IPv4 Node Setup Prompts:
    - The IPv4 miner node name setup to be used as a blacklist, that you want to add IPv4 indicators to
      - Example: Acme_IPv4_blacklist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated IPv4 output feed name for the blacklist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_bl_ipv4 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_bl_ipv4
    - The IPv4 miner node name setup to be used as a watchlist, that you want to add IPv4 indicators to
      - Example: Acme_IPv4_watchlist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated IPv4 output feed name for the watchlist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_watch_ipv4 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_watch_ipv4
      
    # URL Node Setup Prompts:
    - The URL miner node name setup to be used as a blacklist, that you want to add URL indicators to 
      - Example: Acme_URL_blacklist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated URL "output" feed name for the blacklist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_bl_url (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_bl_url
    - The URL miner node name setup to be used as a watchlist, that you want to add URL indicators to 
      - Example: Acme_URL_Watchlist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated URL "output" feed name for the watchlist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_watch_url (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_watch_url

   # SHA1 Node Setup Prompts:
    - The SHA1 miner node name setup to be used as a blacklist, that you want to add SHA1 indicators to 
      - Example: Acme_SHA1_blacklist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated SHA1 "output" feed name for the blacklist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_bl_sha1 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_bl_sha1
    - The SHA1 miner node name setup to be used as a watchlist, that you want to add SHA1 indicators to 
      - Example: Acme_SHA1_Watchlist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated SHA1 "output" feed name for the watchlist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_watch_sha1 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_watch_sha1
 
    # SHA256 Node Setup Prompts:
    - The SHA256 miner node name setup to be used as a blacklist, that you want to add SHA256 indicators to 
      - Example: Acme_SHA256_blacklist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated SHA256 "output" feed name for the blacklist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_bl_sha256 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_bl_sha256
    - The SHA256 miner node name setup to be used as a watchlist, that you want to add SHA256 indicators to 
      - Example: Acme_SHA256_Watchlist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated SHA256 "output" feed name for the watchlist (so the script can check it for duplicate indicators)
      - Example: inboundfeed_watch_SHA256 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeed_watch_sha256
      
- At the main menu, select the action you want to perform
- Click "GO"
- Enter a description of the indicator(s) you want to upload, then click Next
- Type or paste in a list of indicators (IP, CIDR, Domain Name, URL, SHA1 file hash, or SHA256 file hash)
- Optionally, check or uncheck the box "Create wildcard entries for domains"
- Optionally, set a TTL for the indicators before they automatically age-out of MineMeld
- Optionally, check the box to ingest into ThreatConnect (if you are using this feature), and follow the associated prompts
- Click Next
- Review the summary information for accuracy, click Back to make changes, or Confirm to start the upload
- At the Main Menu, click Exit, or select a new action

Credit:

- entangledion (Core script)
- Sean Engelbrecht (MineMeld Add-Indicator Powershell function)
- Daniel Schroeder (Show-Multi & Single LineInputDialog). Originally based on the code shown at http://technet.microsoft.com/en-us/library/ff730941.aspx
