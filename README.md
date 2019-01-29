# PowerMM
PowerMM (Power"MineMeld") is a Powershell-based graphical user interface utility for uploading Indicators of Compromise (IOCs) into Palo Alto MineMeld (https://github.com/PaloAltoNetworks/minemeld/wiki) Mining Nodes. The tool was first created as a way to operationalize and bring together the need to ingest cyber attack IOCs quickly into multiple non-integrated platforms, by multiple analysts within a SOC. Additional functionality may be added over time. 

Features:

- Rapid indicator ingestion into custom MineMeld Miner nodes. Useful if you maintain aggregated lists of IP, URL, and file hash 
  blacklists in MineMeld, and want a simplified way to ingest and purge indicators across a SOC.
- Can upload a combined list of IPV4, CIDR, Domain Name, File Hash, and URL indicators to multiple miner nodes in a single pass.
- Option to automatically create wildcard variants of uploaded domain names.
- Control the age-out TTL of an indicator.
- Automatically stamps indicator descriptions with the user that uploaded it, and date stamp.
- Performs duplicate indicator check prior to upload to prevent duplication of addresses.
- Search miner node output URLs for specific indicators or keywords.
- Multi-user support with shared upload history tracking if used from a mapped network drive.
- Currently the script supports uploading the following types of indicators:
    - IPv4 (also supports CIDR notation)
    - URL (also supports simple FQDN or domain name)
    - SHA1 File Hash
    - SHA256 File Hash

Release Notes:

New in v2.4.1:
- Bug Fix: Error locating icon file
- Enhanced error handling logic

New in v2.4 :
- Code review, sanitation, and cleanup
- New Feature: You can now ingest IPv4 CIDR Blocks.
- New button on main menu to view the release notes.
- New button on main menu to view the log file of your last action.
- New colors to help indicate action result status in the Powershell console window.
- Ingest IOC window now requires use of http:// or https:// when adding URL's.
- ThreatConnect Threat Intelligence Platform support.
- Bug Fix: Miscellaneous

Known Limitations:

- Current version only supports uploading to one miner node name per IOC-type, per transaction (IPv4, URL, SHA1, SHA256).

Pre-requisites:

1) You must have an instance of Palo Alto's MineMeld tool deployed.
2) A mapped network drive is recommended for shared multi-user 
   or team use, but not required.
3) To use the ThreatConnect feature of the script, you must have access to and must have created a ThreatConnect API user account. You 
   will be prompted to enter the API Access ID and Secret Key the first time you execute this script.
4) You must have Windows Management Framework v3.0 or greater installed (to add Powershell v3.0 minimum support.
   Powershell v5.0+ is recommended). For more information about this package visit: https://www.microsoft.com/en-
   us/download/details.aspx?id=34595
5) You must configure Powershell execution policy to allow execution of unsigned scripts, or execute the script using the -
   ExecutionPolicy bypass parameter (Windows default is set to Restricted). For more information about this setting, visit: 
   https://technet.microsoft.com/en-us/library/ee176961.aspx
6) When you first execute PowerMM, you will be prompted to enter some initial setup information, including the MineMeld node names that 
   will be used for blacklists and watchlists. A blacklist can be used by a firewall to dynamically block against any IOCs you add to
   the mining node, or can be used to match firewall traffic logs in a SIEM. A watchlist can also be used to match firewall traffic logs 
   in a SIEM, or be used to send an email notification any time there is a match. These two use-cases are supported in PowerMM by using 
   separate miner nodes in MineMeld, because an admin may not always want to block a specific IOC, but only monitor for activity. You 
   will need to create four MineMeld miner (nodes) to use for blacklists, and four miner (nodes) to use for watchlists, for each of the 
   supported IOC types (IPv4, URL, SHA1, SHA256). This step is required, even if you don't end up using all of these miner nodes.
7) In order to enable TTL for aging out old indicators in MineMeld, the miner nodes you create in MineMeld must use a clone of the 
   following built-in node type: stdlib.localDB. You should be able to locate this built-in node type in the node search box when adding 
   a new miner node in MineMeld. This built-in node type will show it supports indicator type of "ANY", and it may be listed as 
   "expiremental". This is ok. Create a clone of this node type and deploy it for each blacklist and watchlist node for each of the 
   indicator types you want to ingest (IPv4, URL, SHA1, SHA256)

Instructions:

- Clone/download files to a destination folder where you want it to reside.
- Execute: powershell.exe -ExecutionPolicy bypass -C PowerMM.ps1
- You will be prompted at first execution for:
    - The industry sector of your organization.
        NOTE: This information is used to automatically populate a tag (i.e. keyword) to the incident that will be ingested into    
        ThreatConnect (if you chose to enable this feature). PowerMM gives you the opportunity to edit or remove this tag every time you         ingest an indicator.
    - The IP or hostname of your MineMeld server
      - Example: minemeld.acme.corp
    - Your MineMeld username
    - Your MineMeld password
      - Note: The MM Password is cached to disk using AES standard Powershell SecureString encryption

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
