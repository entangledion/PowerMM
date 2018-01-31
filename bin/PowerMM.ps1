<#

CREDIT.

- entangledion (Core script)
- Sean Engelbrecht (MineMeld Add-Indicator Powershell function)
- Daniel Schroeder (Show-Multi & Single LineInputDialog). Originally based on the code shown at http://technet.microsoft.com/en-us/library/ff730941.aspx.

PRE-REQUISITES.

1) You must have Windows Management Framework v3.0 or greater installed (to add Powershell v3.0 minimum support.
   Powershell v5.0 is recommended). For more information about this package visit: https://www.microsoft.com/en-us/download/details.aspx?id=34595

BUG REPORTING.

Please report any bugs @ https://github.com/entangledion/PowerMM/issues

#>

clear

# Set Static Variables
if ($true) {
	$version = "1.2"
	$logonas = $env:username # Do not modify
	$invocation = (Get-Variable MyInvocation).Value
	$workingpath = Split-Path $invocation.MyCommand.Path
	$incident_history = ($workingpath + "\incident_history")
	$cachefile_iocs = ($workingpath + "\cache_iocs.txt")
	$cachefile_hosts = ($workingpath + "\cache_hosts.txt")
	$cachefile_urls = ($workingpath + "\cache_urls.txt")
	$cachefile_addr = ($workingpath + "\cache_addr.txt")
	$logdir = ($workingpath + "\logs")
	$file_iocs = ($workingpath + "\iocs.txt")
}

# Create log file directory if it doesn't exist
$logdir_exists = test-path $logdir
if ($logdir_exists -eq $false) {
	New-Item -ItemType directory -Path $logdir | Out-Null
}

# Delete log files older than 30 day(s)
$daysback = "-30"
$currentdate = Get-Date
$datetodelete = $currentdate.AddDays($daysback)
Get-ChildItem $logdir | Where-Object { $_.LastWriteTime -lt $datetodelete } | Remove-Item

# Set Dynamic Variables
if ($true) {

	# Set MineMeld server variable
	# Example: minemeld.acme.corp
	$server_exists = test-path ($workingpath + "\server.conf")
	if ($server_exists -eq $false) {
		read-host -Prompt "Enter the MineMeld Server IP or Hostname (e.g. minemeld.acme.corp)" | out-file ($workingpath + "\server.conf")
	}
	[String]$server = Get-Content ($workingpath + "\server.conf")

	# Securely stage or call API username
	$accessid_exists = test-path ($workingpath + "\api_accessid-" + $logonas)
	if ($accessid_exists -eq $false) {
		read-host -Prompt "Enter your MineMeld username" | out-file ($workingpath + "\api_accessid-" + $logonas)
	}
	[String]$Script:AccessID = Get-Content ($workingpath + "\api_accessid-" + $logonas)

	# Securely stage or call encrypted API password
	$securestring_exists = test-path ($workingpath + "\api_securestring-" + $logonas)
	if ($securestring_exists -eq $false) {
		read-host -assecurestring -Prompt "Enter your MineMeld password" | convertfrom-securestring | out-file ($workingpath + "\api_securestring-" + $logonas)
	}
	$encryptedpassword = Get-Content ($workingpath + "\api_securestring-" + $logonas) | ConvertTo-SecureString
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedpassword)
	[String]$Script:SecretKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

	# Set URL Indicator List
	# Example: Acme_URL_Blocklist
	$global:urlindlist_exists = test-path ($workingpath + "\ioclist_url.conf")
	if ($global:urlindlist_exists -eq $false) {
		read-host -Prompt "Enter the URL Miner you wish to update" | out-file ($workingpath + "\ioclist_url.conf")
	}
	[String]$global:urlindlist = Get-Content ($workingpath + "\ioclist_url.conf")

	# Set URL Output Node
	# Example: inboundfeedhc_url
	$global:urloutnode_exists = test-path ($workingpath + "\outnode_url.conf")
	if ($global:urloutnode_exists -eq $false) {
		read-host -Prompt "Enter the associated URL Output node name (to check it for duplicate indicators)" | out-file ($workingpath + "\outnode_url.conf")
	}
	[String]$global:urloutnode = Get-Content ($workingpath + "\outnode_url.conf")

	# Set IPv4 Indicator List
	# Example: Acme_IPv4_Blocklist
	$ipv4indlist_exists = test-path ($workingpath + "\ioclist_ipv4.conf")
	if ($ipv4indlist_exists -eq $false) {
		read-host -Prompt "Enter the IPv4 Miner you wish to update" | out-file ($workingpath + "\ioclist_ipv4.conf")
	}
	[String]$ipv4indlist = Get-Content ($workingpath + "\ioclist_ipv4.conf")

	# Set IPv4 Output Node
	# Example: inboundfeedhc_ipv4
	$ipv4outnode_exists = test-path ($workingpath + "\outnode_ipv4.conf")
	if ($ipv4outnode_exists -eq $false) {
		read-host -Prompt "Enter the associated IPv4 Output node name (to check it for duplicate indicators)" | out-file ($workingpath + "\outnode_ipv4.conf")
	}
	[String]$ipv4outnode = Get-Content ($workingpath + "\outnode_ipv4.conf")
}

# Define indicator regex variables
if ($true) {
	$regexhost = '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'
	$regexurl = '(?i:\b(?:(?:https?|ftp):\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,}))\.?)(?::\d{2,5})?(?:[/?#]\S*)?\b)'
	$regexaddr = '\b(?!(10\.|172\.(1[6-9]|2[0-9]|3[0-2])|192\.168))(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b'
	$regexemailaddr = '\b+[a-zA-Z0-9\.\-_]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z0-9\.\-]+\b'
	$regexfilehash_md5 = '\b([a-fA-F\d]{32})\b'
	$regexfilehash_sha1 = '\b([a-fA-F\d]{40})\b'
	$regexfilehash_sha256 = '\b([a-fA-F\d]{64})\b'
	$regexfilehash_sha512 = '\b([a-fA-F\d]{128})\b'
}

# Build Functions
function Cleanup {
	# Reset variables from an aborted execution
	$global:var_incidentname = $null
	$global:var_indicators = $null
	$global:var_prop_value = $null
	$global:BackButtonAction = $null
	$global:BackButtonState = $null
	$global:dialogResult = $null
	$global:Confirm = $null
	$global:logfile = $null
	
	# Check for and cleanup leftover remenants of an aborted execution
	$testpath_cleanup = Test-Path -Path $cachefile_iocs
	if ($testpath_cleanup -eq $true) {
		Remove-Item -Path $cachefile_iocs
	}
	$testpath_cleanup = Test-Path -Path $file_iocs
	if ($testpath_cleanup -eq $true) {
		Remove-Item -Path $file_iocs
	}	
	$testpath_cleanup = Test-Path -Path $cachefile_hosts
	if ($testpath_cleanup -eq $true) {
		Remove-Item -Path $cachefile_hosts
	}
	$testpath_cleanup = Test-Path -Path $cachefile_urls
	if ($testpath_cleanup -eq $true) {
		Remove-Item -Path $cachefile_urls
	}
	$testpath_cleanup = Test-Path -Path $cachefile_addr
	if ($testpath_cleanup -eq $true) {
		Remove-Item -Path $cachefile_addr
	}
}

function Read-MultiLineInputBoxDialog([string]$Message, [string]$WindowTitle, [string]$HelpText, [string]$DefaultText, [string]$Required, [string]$CheckboxID) {
	<#
    .SYNOPSIS
    Prompts the user with a multi-line input box and returns the text they enter, or null if they cancelled the prompt.
     
    .DESCRIPTION
    Prompts the user with a multi-line input box and returns the text they enter, or null if they cancelled the prompt.
     
    .PARAMETER Message
    The message to display to the user explaining what text we are asking them to enter.
     
    .PARAMETER WindowTitle
    The text to display on the prompt window's title.
	
	.PARAMETER HelpText
	The text to display in the help message box.
     
    .PARAMETER DefaultText
    The default text to show in the input box.
     
    .EXAMPLE
    $userText = Read-MultiLineInputDialog "Input some text please:" "Get User's Input"
     
    Shows how to create a simple prompt to get mutli-line input from a user.
     
    .EXAMPLE
    # Setup the default multi-line address to fill the input box with.
    $defaultAddress = @'
    John Doe
    123 St.
    Some Town, SK, Canada
    A1B 2C3
    '@
     
    $address = Read-MultiLineInputDialog "Please enter your full address, including name, street, city, and postal code:" "Get User's Address" $defaultAddress
    if ($address -eq $null)
    {
        Write-Error "You pressed the Cancel button on the multi-line input box."
    }
     
    Prompts the user for their address and stores it in a variable, pre-filling the input box with a default multi-line address.
    if the user pressed the Cancel button an error is written to the console.
     
    .EXAMPLE
    $inputText = Read-MultiLineInputDialog -Message "if you have a really long message you can break it apart`nover two lines with the powershell newline character:" -WindowTitle "Window Title" -DefaultText "Default text for the input box."
     
    Shows how to break the second parameter (Message) up onto two lines using the powershell newline character (`n).
    if you break the message up into more than two lines the extra lines will be hidden behind or show ontop of the TextBox.

#>
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
    	
    # Create the Label.
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Size(10,10) 
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.AutoSize = $true
    $label.Text = $Message
     
    # Create the TextBox used to capture the user's text.
    $textBox = New-Object System.Windows.Forms.TextBox
	$textBox.add_TextChanged({IsThereText})
	function IsThereText
	{
		if ($textBox.Text.Length -ne 0)
		{
			$okButton.Enabled = $true
		}
		else
		{
			$okButton.Enabled = $false
		}
	}
	$textBox.add_TextChanged({ IsThereText })
    $textBox.Location = New-Object System.Drawing.Size(10,40) 
    $textBox.Size = New-Object System.Drawing.Size(575,200)
    $textBox.AcceptsReturn = $true
    $textBox.AcceptsTab = $false
    $textBox.Multiline = $true
    $textBox.ScrollBars = 'Both'
    $textBox.Text = $DefaultText
	
	# Create the Save checkbox
	$checkBox = New-Object System.Windows.Forms.CheckBox
	$checkBox.Location = '10,250'
	$checkBox.Autosize = $true
	$checkBox.Text = "Create wildcard entries for domains"
	$checkBox.Name = "checkBox"
	$checkBox.Enabled = $true
	$checkBox.checked = $true
	if ($global:cb -eq "1") {
		$checkBox.checked = $true
	} else {
		$checkBox.checked = $false
	}
	$checkBox.Add_CheckStateChanged({
		if ($checkBox.checked -eq $true) {
			Set-Variable -Name "global:cb" -Value "1"
		} else {
			Set-Variable -Name "global:cb" -Value "0"
		}
    })
	
    # Create the Next button.
    $okButton = New-Object System.Windows.Forms.Button
	if ($Required -eq $true -and $global:BackButtonState -ne $true) {
		$okButton.Enabled = $false
	} else {
		$okButton.Enabled = $true
	}
    $okButton.Location = '10,290'
    $okButton.Size = '75,25'
    $okButton.Text = "Next"
    $okButton.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $false; $form.Close() })
	
	# Create the Back button.
    $BackButton = New-Object System.Windows.Forms.Button
	if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "incident") {
		$BackButton.Enabled = $true
	} else {
		$BackButton.Enabled = $false
	}
    $BackButton.Size = '75,25'
    $BackButton.Text = "Back"
    $BackButton.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $true; $global:BackButtonState = $true; $form.Close() })
    $BackButton.Location = '90,290' 
	
    # Create the Cancel button.
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = '170,290'
    $cancelButton.Size = '75,25'
    $cancelButton.Text = "Cancel"
	$cancelButton.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })

	# Create the Help button.
	$HelpButton = new-object System.Windows.Forms.Button
	$HelpButton.Location = '250,290'
    $HelpButton.Size = '75,25'
    $HelpButton.Text = 'Help'
    $HelpButton.DialogResult=[System.Windows.Forms.DialogResult]::None
    $HelpButton.Add_Click({[System.Windows.Forms.MessageBox]::Show("$HelpText" , "Help" , 0)})
	
    # Create the form.
    $form = New-Object System.Windows.Forms.Form 
	$form.StartPosition = "CenterScreen"
    $form.Text = $WindowTitle
    $form.Size = New-Object System.Drawing.Size(610,370)
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.Topmost = $True
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.ShowInTaskbar = $true   
	$form.KeyPreview = $True

    # Add all of the controls to the form.
    $form.Controls.Add($label)
    $form.Controls.Add($textBox)
	$form.Controls.Add($checkBox)
    $form.Controls.Add($okButton)
	$form.Controls.Add($BackButton)
	$form.Controls.Add($cancelButton)
	$form.Controls.Add($HelpButton)
     
    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null   # Trash the text of the button that was clicked.
	
	return $form.Tag
	
}

function Read-SingleLineInputBoxDialog([string]$Message, [string]$WindowTitle, [string]$HelpText, [string]$DefaultText, [string]$Required, [string]$CheckboxID) {
	<#
    .SYNOPSIS
    Prompts the user with a single-line input box and returns the text they enter, or null if they cancelled the prompt.
     
    .DESCRIPTION
    Prompts the user with a single-line input box and returns the text they enter, or null if they cancelled the prompt.
     
    .PARAMETER Message
    The message to display to the user explaining what text we are asking them to enter.
     
    .PARAMETER WindowTitle
    The text to display on the prompt window's title.
	
	.PARAMETER HelpText
	The text to display in the Help message box.
     
    .PARAMETER DefaultText
    The default text to show in the input box.
     
    .EXAMPLE
    $inputText = Read-SingleLineInputDialog -Message "Enter a value:" -WindowTitle "Window Title" -DefaultText "Default text for the input box."

#>
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
		
    # Create the Label.
    $label = New-Object System.Windows.Forms.Label
    $label.Location = '10,10'
    $label.Size = '80,20'
    $label.AutoSize = $true
    $label.Text = $Message
    
    # Create the TextBox used to capture the user's text.
    $textBox = New-Object System.Windows.Forms.TextBox
	$textBox.add_TextChanged({IsThereText})
	function IsThereText
	{
		if ($textBox.Text.Length -ne 0)
		{
			$okButton.Enabled = $true
		}
		else
		{
			$okButton.Enabled = $false
		}
	}
	$textBox.add_TextChanged({ IsThereText })
	$textBox.Size = '200,80'
    $textBox.AcceptsReturn = $true
    $textBox.AcceptsTab = $false
    $textBox.Multiline = $false
	$textBox.MaxLength = 100
    $textBox.ScrollBars = 'Both'
	$textBox.Text = $DefaultText
	if ($Message.Length -gt 35) {
	    $textBox.Location = '10,65' 
	} else {
		$textBox.Location = '10,40'
	}

    # Create the Next button.
    $okButton = New-Object System.Windows.Forms.Button
	if ($Required -eq $true -and $global:BackButtonState -ne $true) {
		$okButton.Enabled = $false
	} else {
		$okButton.Enabled = $true
	}
    $okButton.Size = '75,25'
    $okButton.Text = "Next"
    $okButton.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $false; $form.Close() })
	if ($Message.Length -gt 35) {
	    $okButton.Location = '10,120' 
	} else {
		$okButton.Location = '10,100'
	}
	
	# Create the Back button.
    $BackButton = New-Object System.Windows.Forms.Button
	if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "incident" -and $global:var_prop_value -ne "query") {
		$BackButton.Enabled = $true
	} else {
		$BackButton.Enabled = $false
	}
    $BackButton.Size = '75,25'
    $BackButton.Text = "Back"
    $BackButton.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $true; $global:BackButtonState = $true; $form.Close() })
	if ($Message.Length -gt 35) {
	    $BackButton.Location = '90,120' 
	} else {
		$BackButton.Location = '90,100'
	}
	
	# Create the Cancel button.
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Size = '75,25'
    $cancelButton.Text = "Cancel"
	$cancelButton.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
	if ($Message.Length -gt 35) {
	    $cancelButton.Location = '170,120' 
	} else {
		$cancelButton.Location = '170,100'
	}
	
	# Create the Help button.
	$HelpButton = new-object System.Windows.Forms.Button
    $HelpButton.Size = '75,25'
    $HelpButton.Text = 'Help'
    $HelpButton.DialogResult=[System.Windows.Forms.DialogResult]::None
    $HelpButton.Add_Click({[System.Windows.Forms.MessageBox]::Show("$HelpText" , "Help" , 0)})
	if ($Message.Length -gt 35) {
	    $HelpButton.Location = '250,120' 
	} else {
		$HelpButton.Location = '250,100'
	}
	
    # Create the form.
    $form = New-Object System.Windows.Forms.Form 
	$form.StartPosition = "CenterScreen"
    $form.Text = $WindowTitle
	if ($Message.Length -gt 35) {
	    $form.Size = '360,200' 
	} else {
		$form.Size = '360,180'
	}
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.Topmost = $True
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.ShowInTaskbar = $true   
	$form.KeyPreview = $True
	
    # Add all of the controls to the form.
    $form.Controls.Add($label)
    $form.Controls.Add($textBox)
	$form.Controls.Add($checkBox)
    $form.Controls.Add($okButton)
	$form.Controls.Add($cancelButton)
	$form.Controls.Add($BackButton)
	$form.Controls.Add($HelpButton)
     
    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null   # Trash the text of the button that was clicked.
    
	# Return the text that the user entered.
	return $form.Tag
}

function Build-Indicator-Files {
	if ($global:var_indicators -ne $null -and $global:var_indicators -ne "") {
		echo $null > $cachefile_iocs
		foreach ($ioc in $global:var_indicators) {
			$ioc = $ioc.replace("[","")
			$ioc = $ioc.replace("]","")
			$ioc = $ioc.replace("(","")
			$ioc = $ioc.replace(")","")
			$ioc = $ioc.replace("{","")
			$ioc = $ioc.replace("}","")
			Write-Output $ioc >> $cachefile_iocs
		}
		# Loop Hostname indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		select-string -Path $input_file -Pattern $regexhost -AllMatches | % { $_.Matches } | % { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache1 = Get-Content $output_file
		$global:ioccache1 = $global:ioccache1 | select -Unique
		Remove-Item -Path $cachefile_hosts -ErrorAction SilentlyContinue
		if ($global:ioccache1 -ne $null -and $global:ioccache1 -ne "") {
			Write-Host "Regex extracted the following domains: ($global:ioccache1)"
			$global:ioccache1 = Get-Content $output_file
			foreach ($ioc in $global:ioccache1) {
				Write-Output $ioc >> $cachefile_hosts
			}
		}
		
		# Loop URL indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		select-string -Path $input_file -Pattern $regexurl -AllMatches | % { $_.Matches } | % { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache2 = Get-Content $output_file
		$global:ioccache2 = $global:ioccache2 | select -Unique
		Remove-Item -Path $cachefile_urls -ErrorAction SilentlyContinue
		if ($global:ioccache2 -ne $null -and $global:ioccache2 -ne "") {
			Write-Host "Regex extracted the following URLs: ($global:ioccache2)"
			$global:ioccache2 = Get-Content $output_file
			foreach ($ioc in $global:ioccache2) {
				Write-Output $ioc >> $cachefile_urls
			}
		}
		
		# Loop IPv4 Address indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		select-string -Path $input_file -Pattern $regexaddr -AllMatches | % { $_.Matches } | % { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache3 = Get-Content $output_file
		$global:ioccache3 = $global:ioccache3 | select -Unique
		Remove-Item -Path $cachefile_addr -ErrorAction SilentlyContinue
		if ($global:ioccache3 -ne $null -and $global:ioccache3 -ne "") {
			Write-Host "Regex extracted the following IP Addresses: ($global:ioccache3)"
			Write-Host ""
			foreach ($ioc in $global:ioccache3) {
				Write-Output $ioc >> $cachefile_addr
			}
		}
	}
}

function Add-Indicator {
    <#
    .SYNOPSIS
        Add indicators to MineMeld feeds utilized by Palo Alto Firewalls
    .DESCRIPTION
        This cmdlet can be utilized to add threat indicators to fields listed in minemeld ( A Palo Alto open source threat aggregation tool).
        Mandatory functions for this function include; Server, FeedList, IndicatorList, Type and Indicator.
    .PARAMETER Server
        This Parameter contains the ip-address or FQDN of the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Indicator
        This Parameter contains the Indicator to be added to the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Type
        This Parameter contains the type of indicator to be added to the the MineMeld server (IPv4 or URL).
        Parameter Default Value: URL
    .PARAMETER IndicatorList
        This Parameter contains the name of the input stream/list where the indicator should be added.
        Parameter Default Value: dvn_Malware_List
    .PARAMETER FeedList
        This Parameter contains the name of the output stream/list where the indicator should be added.
        Parameter Default Value: HC_URL_List
    .PARAMETER IncludeSubDomain
        If this parameter is present and the Type is URL an additional indicator will be added containing a wildcard token.
    .PARAMETER BypassSSL
        If this parameter is present self-signed certificate errors will be bypassed.
    .EXAMPLE
	    Add-Indicator -Server 192.168.1.10 -Indicator "evil.com"
        This will add the url evil.com to the default list on minemeld server (192.168.1.1)
    .EXAMPLE
	    Add-Indicator -Server 192.168.1.10 -Indicator "evil.com" -IncludeSubDomain
        Will add the url's evil.com and *.evil.com to the default list on minemeld server (192.168.1.1)
    .EXAMPLE
	    Add-Indicator -Server 192.168.1.10 -Indicator "evil.com" -BypassSSL
        This will add the url evil.com to the default list on minemeld server (192.168.1.1) and bypass and SSL certificate errors caused by self-signed SSL certs.
    .EXAMPLE
	    Add-Indicator -Server 192.168.1.10 -Indicator "172.16.12.21" -Type IPv4 -FeedList "mm_dc_list" -IndicatorList "DC_IP_List"
        Will Add ip address 172.16.21.21 to DC_IP_List on minemeld server (192.168.1.1). It will check "mm_dc_list" for the indicator first to avoid duplicating the indicator.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="IP-Address or FQDN of MineMeld Server:",
                   Position=0)]
        [String]
        $Server,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="IP-Address or FQDN of MineMeld Server:",
                   Position=3)]
        [String]
        $FeedList = "Default_URL_List",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Input node to add threat indicator to:",
                   Position=4)]
        [String]
        $IndicatorList = "Default_Indicator_List",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Indicator type (IPv4 or URL):",
                   Position=1)]
        [string]
        [validateSet("IPv4","URL")]
        $Type = "URL",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Indicator type (IPv4 or URL):",
                   Position=5)]
		[string]
        $Indicator,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Bypass SSL Errors:",
                   Position=7)]
        [string]
        [validateSet("green","yellow","red")]
        $ShareLevel = "red",
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Threat indicator to Add:",
                   Position=2)]
        [switch]
        $BypassSSL,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Include wildcard character to for subdomains *.evil.com:",
                   Position=6)]
        [switch]
        $IncludeSubDomain
    )
    Begin
    {	$global:url =  "https://" + $Server + "/feeds/" + $FeedList + "?tr=1"
		$global:currentList = Invoke-WebRequest $global:url -TimeoutSec 30
        
        If ($BypassSSL)
        {
            #if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type)
            #{
                add-type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            #}
        }
        
		# Variable used to the while loop needed to include a wildcard for subdomains
        $exitLoop = $false
    }
    Process
    {
        Try
        {
            $Error.Clear()

            #Credentials can be passed using basic authentication
            #   * Simply base46 encode {username}:{password} and add that string to the headers
            #   * Be sure to include the ':' between the strings
            $userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Script:AccessID):$($Script:SecretKey)"))
            # Adding the Authentication string to the post request headers
            $Headers = @{
                Authorization = 'Basic ' +  $userPass
            }
            while ( -not $exitLoop)
            {
                # Check if indicator exists
                if ( -not $global:currentList.Content.Contains($Indicator) )
                {
                    
					# Array that will be converted to JSON format for POST request
                    $indicatorArr = @{
                        indicator = "$Indicator"
                        type = "$Type"
                        share_level = "$ShareLevel"
                        comment = "$global:Comment"
                    }
                    $requestBody = $indicatorArr | ConvertTo-Json
                    $global:url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList
                    $Response = Invoke-RestMethod $global:url -Method Post -Body $requestBody -ContentType 'application/json' -Headers $Headers
                    Write-Host "The Following Indicator was added: $indicator"
					Write-Output "The Following Indicator was added: $indicator" >> $global:logfile
                }
                else
                {
                    Write-Host "The Following Indicator was skipped, already in the list: $indicator"
                    Write-Output "The Following Indicator was skipped, already in the list: $indicator" >> $global:logfile
                }
                if ( "$Type" -eq "URL" )
                    {
                        # Process structure for URL Indicators
                        if ( ($IncludeSubDomain -and $Indicator.Contains("*.") ) -or -not $IncludeSubDomain )
                        {
                            # If the wildcard has been processed already, or there is no need to include sub-domains, exit the loop.
                            $exitLoop = $true
                        }
                        else
                        # Since sub-domains are to be included, loop back around and add additional indicator with wildcard token.
                        {
                            $Indicator = "*.$Indicator"
                        }
                    }
                    else
                    # If the Indicator is an IPv4 type, simply exit the loop.
                    {
                        $exitLoop = $true
                    }
            }
        }
        catch
        {

        }
    }
    end
    {
        #Print function status and cleanup
    }
}

function Get-Indicator {
    <#
    .SYNOPSIS
        Search indicator feeds in MineMeld
    .DESCRIPTION
        This cmdlet can be utilized to return threat indicators listed in minemeld output feeds.
        Mandatory functions for this function include; Server, FeedList, Type and Indicator.
    .PARAMETER Server
        This Parameter contains the ip-address or FQDN of the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Indicator
        This Parameter contains the Indicator to be searched.
        Parameter has no Default Value
    .PARAMETER Type
        This Parameter contains the type of indicator to be searched on the MineMeld server (IPv4 or URL).
        Parameter Default Value: URL
    .PARAMETER FeedList
        This Parameter contains the name of the output stream/list where the indicator should be searched.
        Parameter Default Value: HC_URL_List
    .PARAMETER BypassSSL
        If this parameter is present self-signed certificate errors will be bypassed.
    .EXAMPLE
	    Get-Indicator -Server 192.168.1.10 -Indicator "172.16.12.21" -Type IPv4 -FeedList "mm_dc_list"
        It will search "mm_dc_list" for the defined indicator "172.16.12.21".
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="IP-Address or FQDN of MineMeld Server:",
                   Position=0)]
        [String]
        $Server,
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="IP-Address or FQDN of MineMeld Server:",
                   Position=1)]
        [String]
        $FeedList = "Default_URL_List",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Indicator type (IPv4 or URL):",
                   Position=1)]
        [string]
        [validateSet("IPv4","URL")]
        $Type = "URL",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Indicator type (IPv4 or URL):",
                   Position=3)]
		[string]
        $Indicator,
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Threat indicator to search for:",
                   Position=2)]
        [switch]
        $BypassSSL
    )
    Begin
    {	$global:url = ("https://" + $Server + "/feeds/" + $FeedList + "?tr=1")
		$global:currentList = Invoke-WebRequest -Uri $global:url -TimeoutSec 30
        
        If ($BypassSSL)
        {
            #if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type)
            #{
                add-type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            #}
        }
    }
    Process
    {
        Try
        {
            $global:searchresult = $null
			$Error.Clear()

            #Credentials can be passed using basic authentication
            #   * Simply base46 encode {username}:{password} and add that string to the headers
            #   * Be sure to include the ':' between the strings
            $userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Script:AccessID):$($Script:SecretKey)"))
            # Adding the Authentication string to the post request headers
            $Headers = @{
                Authorization = 'Basic ' +  $userPass
            }
			
            # Search for indicator
            if ( -not $global:currentList.Content.Contains($Indicator) )
            {
                $global:searchresult = "Nothing Found"
            }
            else
            {
                $global:searchresult = "$indicator was found in $FeedList on MineMeld server $Server."
            }
        }
        catch
        {

        }
    }
    end
    {
        #Print function status and cleanup
    }
}

function Main-Menu {

    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
	
	# Set the size of the form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = ("PowerMM v" + $version + " - Main Menu")
	$Form.StartPosition = "CenterScreen"
	$Form.size = '615,420'
     
	# Set the font of the text to be used within the form
    $Font = New-Object System.Drawing.Font("Arial",9)
    $Form.Font = $Font
	
	# Create a group that will contain your radio buttons
    $MyGroupBox1 = New-Object System.Windows.Forms.GroupBox
	$MyGroupBox1.AutoSize = $True
	$MyGroupBox1.AutoSizeMode = "GrowAndShrink"
    $MyGroupBox1.Location = '20,20'
	$MyGroupBox1.height = '100'
    $MyGroupBox1.text = "Select an option:"
    
    # Create the collection of radio buttons
    $RadioButton1 = New-Object System.Windows.Forms.RadioButton
    $RadioButton1.AutoSize = $True
	$RadioButton1.Location = '20,25'
    $RadioButton1.Checked = $true 
    $RadioButton1.Text = "Upload Indicators"

    # Create the collection of radio buttons
    $RadioButton2 = New-Object System.Windows.Forms.RadioButton
    $RadioButton2.AutoSize = $True
	$RadioButton2.Location = '20,50'
    $RadioButton2.Checked = $false 
    $RadioButton2.Text = "Search Indicators"
	
    # Add an OK button
    $okButton = new-object System.Windows.Forms.Button
	$okButton.Location = '50,120'
    $okButton.Size = '100,40'
    $okButton.Text = 'GO'
    $okButton.DialogResult=[System.Windows.Forms.DialogResult]::OK
 
    # Add a cancel button
    $CancelButton = new-object System.Windows.Forms.Button
    $CancelButton.Location = '170,120'
    $CancelButton.Size = '100,40'
    $CancelButton.Text = "EXIT"
    $CancelButton.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
    
	# Display Instructions
	$textbox = New-Object Windows.Forms.TextBox
	$textbox.AutoSize = $True
	$textbox.Location = '20,180'
	$textbox.Size = '560,160'
	$textbox.MultiLine = $True
	$textbox.scrollbars = 'Both'
	$textbox.wordwrap = $True
	$textbox.readonly = $True
	
	# Get ingestion history
	$incidenthist_exists = test-path $incident_history
	if ($incidenthist_exists -eq $true) {
		$incident_hist_detail = Import-CSV -Path $incident_history | Sort-Object timestamp,name -Descending
		$textbox.text = ("History:`n`r`n`r`n")
		$hist_array = $null
		foreach ($r in $incident_hist_detail) {
			$hist_array = $hist_array + ("(" + $r.timestamp + ") - (" + $r.name + ")`n`r`n`r")
		}
		$textbox.AppendText($hist_array)
	} else {
		$incident_hist_detail = $null
		$textbox.text = ("<No upload history>")
	}
		
    # Add all the Form controls on one line
    $form.Controls.AddRange(@($MyGroupBox1,$MyTextBox1,$okButton,$CancelButton,$textbox))
 
    # Add all the GroupBox controls on one line
    $MyGroupBox1.Controls.AddRange(@($Radiobutton1,$RadioButton2,$RadioButton3))
    
    # Assign the Accept and Cancel options in the form to the corresponding buttons
    $form.AcceptButton = $okButton
    $form.CancelButton = $CancelButton

    # Activate the form
    $form.Add_Shown({$form.Activate()})    
    
    # Get the results from the button click
    $global:dialogResult = $form.ShowDialog()
	
	# if the Cancel button is selected
    if ($global:dialogResult -eq "Cancel"){
		Exit
	}
	
    # if the OK button is selected
    if ($global:dialogResult -eq "OK"){
        
        # Check the current state of each radio button and respond accordingly
        if ($RadioButton1.Checked){
			$global:abortdialog = $false
        	Invoke-Expression Ingest
		}
		if ($RadioButton2.Checked){
			$global:abortdialog = $false
        	Invoke-Expression Search
		}
    }
}

function Ingest {

	# Cleanup prior environment
	Invoke-Expression Cleanup
	$global:var_prop_value = $null

	# Prompt for Description
	if ($global:abortdialog -ne $true) {
		function Get-IncidentName {
			$global:var_prop_value = "incident"
			if (($global:var_incidentname = Read-SingleLineInputBoxDialog -Message "Enter a Description:" -WindowTitle ("PowerMM v" + $version + " - Description") -HelpText "Give the indicators a description in 100 characters or less." -DefaultText $global:var_incidentname -Required $true -CheckboxID "1") -eq "") {
			}
		}
		Invoke-Expression Get-IncidentName
		$global:BackButtonAction = $false
	} else {
		Invoke-Expression Cleanup
		Invoke-Expression Main-Menu
	}
	
	# Prompt for Attack Indicators
	if ($global:abortdialog -ne $true) {
		function Get-Indicators {
			$global:var_prop_value = "indicators"
			if ($global:var_indicators -eq $null) {
				$global:BackButtonState = $null
			}
			if (($global:var_indicators = Read-MultiLineInputBoxDialog -Message "Paste in attack indicators (IP, Domain, or URL)." -WindowTitle ("PowerMM v" + $version + " - Attack Indicators") -HelpText "Type or paste in a list of attack indicators (IP, Domain, or URL). The paste indicators box will accept unstructured text and will extract valid indicators automatically." -DefaultText $global:var_indicators -Required $true) -eq "") {
				$global:var_indicators
			}
				
			# Prep indicators for submission
			Invoke-Expression Build-Indicator-Files
			
			while ($global:BackButtonAction -eq $true) {
				if ($global:abortdialog -ne $true) {
					Invoke-Expression Get-IncidentName
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true) {
						if ($global:var_prop_value -eq "incident") {
							Invoke-Expression Get-Indicators
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		Invoke-Expression Get-Indicators
		$global:BackButtonAction = $false
	} else {
		Invoke-Expression Cleanup
		Invoke-Expression Main-Menu
	}
	
	# Confirm and Execute Ingestion Logic
	if ($global:abortdialog -ne $true) {
				
		# Display final submission detail page
		if ($var_indicators -ne $null -and $var_indicators -ne "" -and $global:abortdialog -ne $true) {
			function Get-SubmissionForm {
				
				if ($cb -eq "1") {
					$domainarray = @()
					foreach ($ioc in $global:ioccache1) {
						$domainarray += "$ioc"
						$domainarray += "*.$ioc"
					}
				} else {
					$domainarray = @()
					foreach ($ioc in $global:ioccache1) {
						$domainarray += "$ioc"
					}
				}
				$domainarray = $domainarray -join "`r`n"
				
				$urlarray = @()
				foreach ($ioc in $global:ioccache2) {
					$urlarray += "$ioc"
				}
				$urlarray = $urlarray -join "`r`n"
					
				$addrarray = @()
				foreach ($ioc in $global:ioccache3) {
					$addrarray += "$ioc"
				}
				$addrarray = $addrarray -join "`r`n"
				
				# To add date to the comments field for each indicator
				$Timestamp = Get-Date -Format "MM-dd-yyyy"
                $global:Comment = ($global:var_incidentname + " - PowerMM [" + $Script:AccessID + " - " + $Timestamp + "]")
				
				[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
			    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
				
				# Set the size of the form
			    $Form = New-Object System.Windows.Forms.Form
			    $Form.Text = "PowerMM - Confirmation"
				$Form.StartPosition = "CenterScreen"
				$Form.size = '580,520'
			     
				# Set the font of the text to be used within the form
			    $Font = New-Object System.Drawing.Font("Arial",10)
			    $Form.Font = $Font
				
				# Display Instructions
				$textbox = New-Object Windows.Forms.TextBox
				if ($global:var_prop_value -eq $null) {
					$textbox.add_TextChanged({ $okButton.Enabled = $true })
				}
				$textbox.AutoSize = $True
				$textbox.Location = New-Object System.Drawing.Size(10,10)
				$textbox.Size = New-Object System.Drawing.Size(500,400)
				$textbox.MultiLine = $True
				$textbox.scrollbars = 'Both'
				$textbox.wordwrap = $True
				$textbox.readonly = $True
				$textbox.text = "(Description):

$global:Comment

(Domains):

$domainarray

(URLs):

$urlarray

(IPv4 Addresses):

$addrarray"

				$form.controls.add($textbox)

			    # Add an OK button
			    $okButton = new-object System.Windows.Forms.Button
				if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "") {
					$okButton.Enabled = $true
				}
				if ($Required -eq $true -and $global:var_prop_value -eq $null) {
					$okButton.Enabled = $false
				}
				$okButton.Location = '10,430'
			    $okButton.Size = '75,25' 
			    $okButton.Text = 'Confirm'
			    $okButton.DialogResult=[System.Windows.Forms.DialogResult]::OK
			 
			 	# Create the Back button.
			    $BackButton = New-Object System.Windows.Forms.Button
				if ($global:var_prop_value -eq $null) {
					$BackButton.Enabled = $false
				} else {
					$BackButton.Enabled = $true
				}
				$BackButton.Location = '90,430'
			    $BackButton.Size = '75,25'
			    $BackButton.Text = "Back"
			    $BackButton.Add_Click({ $form.Tag = $null; $global:BackButtonAction = $true; $form.Close() })
			 
			    # Add a cancel button
			    $CancelButton = new-object System.Windows.Forms.Button
			    $CancelButton.Location = '170,430'
			    $CancelButton.Size = '75,25'
			    $CancelButton.Text = "Cancel"
			    $CancelButton.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
				$CancelButton.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
			 
			    # Add all the Form controls on one line 
			    $form.Controls.AddRange(@($okButton,$BackButton,$CancelButton))
			 
			    # Assign the Accept and Cancel options in the form to the corresponding buttons
			    $form.AcceptButton = $okButton
			    $form.CancelButton = $CancelButton
			 
			    # Activate the form
			    $form.Add_Shown({$form.Activate()})
				
				# Get the results from the button click
		    	$global:Confirm = $form.ShowDialog()
				
				$global:BackButtonState = $true
									
				while ($global:BackButtonAction -eq $true) {
					if ($global:abortdialog -ne $true) {
						Invoke-Expression Get-Indicators
						$global:BackButtonAction = $false
						if ($global:abortdialog -ne $true) {
							if ($global:var_prop_value -eq "indicators") {
								Invoke-Expression Get-SubmissionForm
								$global:BackButtonAction = $false
							}
						}
					}
				}
			}
			Invoke-Expression Get-SubmissionForm
			$global:BackButtonAction = $false
			
		    # if the Confirm button is selected
			if ($global:Confirm -eq "OK"){
					
				# Submit a new incident
				$global:BackButtonAction = $false
				
				# Set incident timestamp
				$global:Timestamp = Get-Date -Format "yyyy-MM-ddTHH-mm-sszz"
				
				# Create and update log files
				$global:logfile = ($logdir + "\log-" + $global:Timestamp + ".txt")
				Write-Output $global:Comment >> $global:logfile
				
				# Create and update incident history file
				$incidenthist_exists = test-path $incident_history
				if ($incidenthist_exists -eq $false) {
						Write-Output "timestamp,name" > $incident_history
				} else {
						Write-Output  ("`n`r" + $global:Timestamp + "," + [string]$global:var_incidentname) >> $incident_history
				}
				
				# Create and associate the defined indicators
				$testpath = Test-Path $cachefile_hosts
				if ($testpath -eq $true) {
					$hosts = Get-Content $cachefile_hosts
					foreach ($ioc in $hosts) {
						if ($cb -eq "1") {
							try {
								Add-Indicator -Server $server -Indicator $ioc -IncludeSubDomain -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -BypassSSL
							} catch {
								Write-Output $_ >> $global:logfile
							}
						} else {
							try {
								Add-Indicator -Server $server -Indicator $ioc -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -BypassSSL
							} catch {
								Write-Output $_ >> $global:logfile
							}
						}
					}
				}
				
				$testpath = Test-Path $cachefile_urls
				if ($testpath -eq $true) {
					$urls = Get-Content $cachefile_urls
					foreach ($ioc in $urls) {
						try {
							Add-Indicator -Server $server -Indicator $ioc -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -BypassSSL
						} catch {
							Write-Output $_ >> $global:logfile
						}
					}
				}
				
				$testpath = Test-Path $cachefile_addr
				if ($testpath -eq $true) {
					$addr = Get-Content $cachefile_addr
					foreach ($ioc in $addr) {
						try {
							Add-Indicator -Server $server -Indicator $ioc -Type IPv4 -FeedList $ipv4outnode -IndicatorList $ipv4indlist -BypassSSL
						} catch {
							Write-Output $_ >> $global:logfile
						}

					}
				}
				
				Write-Host -ForegroundColor Green "Operation Completed. Returning to the Main Menu.."
				Invoke-Expression Cleanup
				Invoke-Expression Main-Menu
				break
			}
			# if the Cancel button is selected
			if ($global:Confirm -eq "Cancel"){
				Write-Host -ForegroundColor Red "Operation Cancelled. Returning to the Main Menu.."
				Invoke-Expression Cleanup
				Invoke-Expression Main-Menu
				break
			}
		} else {
			Invoke-Expression Cleanup
			Invoke-Expression Main-Menu
			break
		}
	} else {
		Invoke-Expression Cleanup
		Invoke-Expression Main-Menu
		break
	}
}

function Search {

	$global:var_prop_value = $null
	$global:var_searchquery = $null
	
	# Prompt for Search Query
	if ($global:abortdialog -ne $true) {
		function Get-Query {
			$global:var_prop_value = "query"
			if (($global:var_searchquery = Read-SingleLineInputBoxDialog -Message "Search for indicator:" -WindowTitle ("PowerMM v" + $version + " - Search Query") -HelpText "In 100 characters or less, enter an IP, Domain, or URL to perform a search on." -DefaultText $global:var_searchquery -Required $true -CheckboxID "2") -eq "") {
			}
		if ($global:BackButtonState -eq $true) {
			$global:BackButtonState = $false
			Invoke-Expression Main-Menu
		}
		}
		Invoke-Expression Get-Query
		$global:BackButtonAction = $false
	} else {
		Invoke-Expression Main-Menu
	}
	
	# Confirm and Execute Search Query Logic
	if ($global:abortdialog -ne $true) {
		Get-Indicator -Server $Server -Indicator $global:var_searchquery -Type IPv4 -FeedList $ipv4outnode -BypassSSL
		
		if ($global:searchresult -ne "Nothing Found") {
			Write-Host $global:searchresult
		} else {
			Get-Indicator -Server $Server -Indicator $global:var_searchquery -Type URL -FeedList $urloutnode -BypassSSL
			if ($global:searchresult -ne "Nothing Found") {
				Write-Host $global:searchresult
			} else {
				Write-Host $global:searchresult
			}
		}
	
		# Display query results detail page
		if ($global:abortdialog -ne $true) {
			function Get-QueryResults {
				
				[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
			    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
				
				# Set the size of the form
			    $Form = New-Object System.Windows.Forms.Form
			    $Form.Text = "PowerMM - Confirmation"
				$Form.StartPosition = "CenterScreen"
				$Form.size = '580,260'
			     
				# Set the font of the text to be used within the form
			    $Font = New-Object System.Drawing.Font("Arial",10)
			    $Form.Font = $Font
				
				# Display Instructions
				$textbox = New-Object Windows.Forms.TextBox
				$textbox.add_TextChanged({IsThereText})
				function IsThereText
				{
					if ($textbox.Text.Length -ne 0)
					{
						$okButton.Enabled = $true
					}
					else
					{
						$okButton.Enabled = $false
					}
				}
				$textBox.add_TextChanged({ IsThereText })
				if ($global:var_prop_value -eq $null) {
					$textbox.add_TextChanged({ $okButton.Enabled = $true })
				}
				$textbox.AutoSize = $True
				$textbox.Location = New-Object System.Drawing.Size(10,10)
				$textbox.Size = New-Object System.Drawing.Size(500,160)
				$textbox.MultiLine = $True
				$textbox.scrollbars = 'Both'
				$textbox.wordwrap = $True
				$textbox.readonly = $True
				$textbox.text = "
$global:searchresult"

				$form.controls.add($textbox)
	 
			    # Add a cancel button
			    $CancelButton = new-object System.Windows.Forms.Button
			    $CancelButton.Location = '10,180'
			    $CancelButton.Size = '75,25'
			    $CancelButton.Text = "Cancel"
			    $CancelButton.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
				$CancelButton.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
			 
			    # Add all the Form controls on one line 
			    $form.Controls.AddRange(@($CancelButton))
			 
			    # Assign the Accept and Cancel options in the form to the corresponding buttons
			    $form.AcceptButton = $CancelButton
			    $form.CancelButton = $CancelButton
			 
			    # Activate the form
			    $form.Add_Shown({$form.Activate()})
				
				# Get the results from the button click
		    	$global:Confirm = $form.ShowDialog()
				
				#$global:BackButtonState = $true
									
				while ($global:BackButtonAction -eq $true) {
					if ($global:abortdialog -ne $true) {
						Invoke-Expression Get-Query
						$global:BackButtonAction = $false
						if ($global:abortdialog -ne $true) {
							if ($global:var_prop_value -eq "query") {
								Invoke-Expression Get-QueryResults
								$global:BackButtonAction = $false
							}
						}
					}
				}
			}
			Invoke-Expression Get-QueryResults
			$global:BackButtonAction = $false
			
			# if the Cancel button is selected
			if ($global:Confirm -eq "Cancel"){
				Write-Host -ForegroundColor Green "Returning to the Main Menu.."
				Invoke-Expression Main-Menu
				break
			}
		} else {
			Invoke-Expression Main-Menu
			break
		}
	} else {
		Invoke-Expression Main-Menu
		break
	}
}

Invoke-Expression Main-Menu
