# PowerMM
A Powershell-based graphical user interface utility to quickly paste in a list of indicators and upload to MineMeld Miners. Useful if you maintain custom firewall IP and URL dynamic blocklists in MineMeld. Additional functionality may be added over time.

Currently the script supports uploading the following types of indicators:

- IPv4
- Domain
- URL

Features:

- Rapid indicator ingestion into custom IPv4 & URL MineMeld Miners (nodes).
- Can upload a combined list of IPv4, Domain Name, and URL indicators to multiple miners in a single pass.
- The paste indicators box will accept unstructured text and will extract valid indicators automatically.
- Option to automatically create wildcard variants of uploaded domain names.
- Automatically stamps indicator descriptions with the user that uploaded it, and date stamp.
- Performs duplicate indicator check prior to upload to prevent duplication of addresses.
- Search option to spot-check the configured Output node/feed URLs for specific indicators.
- Multi-user support with shared upload history tracking if used from a mapped network drive.
- Secure storage of MM username/password credentials using built-in Powershell SecureString encryption.

Known Limitations:

- Current version only supports simultaneous uploading to one IPv4 and one URL MineMeld Miner.
- Has only been tested using a minemeldlocal (cloned) IPv4 and URL node prototype.

Instructions:

- Clone/download files to a destination folder where you want it to reside.
- Execute: powershell.exe -ExecutionPolicy bypass -C PowerMM.ps1
- You will be prompted at first execution for:
    - The IP or hostname of your MineMeld server
      - Example: minemeld.acme.corp
    - Your MineMeld username
    - Your MineMeld password
    - The URL node type (Miner) name that you want to update 
      - Example: Acme_URL_Blocklist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated URL output feed name (so the script can check it for duplicate indicators)
      - Example: inboundfeedhc_url (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeedhc_url
    - The IPv4 node type (Miner) name that you want to update
      - Example: Acme_IPv4_Blocklist (the "Miner" Node name shown under the "Config" tab in MineMeld)
    - An associated IPv4 output feed name (so the script can check it for duplicate indicators)
      - Example: inboundfeedhc_ipv4 (the "Output" Node name shown under the "Config" tab in MineMeld)
      - Example: Corresponds to https://minemeld.acme.corp/feeds/inboundfeedhc_ipv4
- At the main menu, click "GO"
- Enter a description of the indicators you want to upload, then click Next
- Type or paste in a list of indicators (IP, Domain Name, or URL)
- Optionally, check or uncheck the box "Create wildcard entries for domains"
- Click Next
- Review the summary information for accuracy, click Back to make changes, or Confirm to start the upload
- At the Main Menu, click Exit, or "GO" to upload more indicators

Credit:

- entangledion (Core script)
- Sean Engelbrecht (MineMeld Add-Indicator Powershell function)
- Daniel Schroeder (Show-Multi & Single LineInputDialog). Originally based on the code shown at http://technet.microsoft.com/en-us/library/ff730941.aspx
