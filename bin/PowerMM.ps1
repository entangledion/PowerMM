<#

CREDIT.

- entangledion (Core script)
- Sean Engelbrecht (MineMeld New-MMIndicator Powershell function)
- Daniel Schroeder (Show-Multi & Single LineInputDialog). Originally based on the code shown at http://technet.microsoft.com/en-us/library/ff730941.aspx.
- David Howell and his PS-ThreatConnectV2API modules for the ThreatConnect common API v2

DISCLAIMERS and LIMITATIONS on LIABILITY.

THIS SCRIPT IS PROVIDED ON AN "AS IS" BASIS, AND NO WARRANTY, EITHER EXPRESS OR IMPLIED, IS GIVEN. YOUR USE OF THE SCRIPT IS AT YOUR SOLE RISK. The developer will not
warrant that (i) the Software will meet your specific requirements; (ii) the Software is fully compatible with any particular platform; or (iii) any
errors in the Software will be corrected. This script has been made available to the public "as is" for their own evaluation and use as they deem appropriate.
Users are free to modify or otherwise improve upon this script, and upon their own discretion share improvements with the project.

PRE-REQUISITES.

See the Readme @ https://github.com/entangledion/PowerMM

BUG REPORTING.

Please report any bugs @ https://github.com/entangledion/PowerMM/issues

#>

Clear-Host

# Set Static Variables
if ($true)
{
	# Global Static Variables
	$version = "2.4.1"
	$default_ioc_expiration = "365"
	$log_retention_days = "30"
	$mask_sensitivevalues = ("acmecorp.local", "acmecorp.com") # A list of sensitive information values you want PowerMM to replace with asterisks
	$global:logonas = $env:username # Do not modify
	$invocation = (Get-Variable MyInvocation).Value
	$workingpath = Split-Path $invocation.MyCommand.Path
	$incident_history = ($workingpath + "\incident_history.txt")
	$cachedir = ($workingpath + "\cache\")
	$configdir = ($workingpath + "\config\")
	$credsdir = ($workingpath + "\creds\")
	$logdir = ($workingpath + "\logs\")
	$serverconf = ($configdir + "server.conf")
	$sectorconf = ($configdir + "sector.conf")
	$tccommunityconf = ($configdir + "tccommunity.conf")
	$cachefile_tags = ($cachedir + "cache_tags-" + $global:logonas + ".txt")
	$cachefile_iocs = ($cachedir + "cache_iocs-" + $global:logonas + ".txt")
	$cachefile_hosts = ($cachedir + "cache_hosts-" + $global:logonas + ".txt")
	$cachefile_urls = ($cachedir + "cache_urls-" + $global:logonas + ".txt")
	$cachefile_addr = ($cachedir + "cache_addr-" + $global:logonas + ".txt")
	$cachefile_sha1 = ($cachedir + "cache_sha1-" + $global:logonas + ".txt")
	$cachefile_sha256 = ($cachedir + "cache_sha256-" + $global:logonas + ".txt")
	$cachefile_cidr = ($cachedir + "cache_cidr-" + $global:logonas + ".txt")
	$nodeconfig_bl_ipv4 = ($configdir + "node_bl_ipv4.conf")
	$nodeconfig_bl_url = ($configdir + "node_bl_url.conf")
	$nodeconfig_bl_sha1 = ($configdir + "node_bl_sha1.conf")
	$nodeconfig_bl_sha256 = ($configdir + "node_bl_sha256.conf")
	$nodeconfig_watch_ipv4 = ($configdir + "node_watch_ipv4.conf")
	$nodeconfig_watch_url = ($configdir + "node_watch_url.conf")
	$nodeconfig_watch_sha1 = ($configdir + "node_watch_sha1.conf")
	$nodeconfig_watch_sha256 = ($configdir + "node_watch_sha256.conf")
	$tcapi_accessid = ($credsdir + "tcapi_accessid")
	$tcapi_secretkey = ($credsdir + "tcapi_skey-" + $logonas)
	$file_releasenotes = ($workingpath + "\release-notes.txt")
	$iconfile = ($workingpath + "\minemeld.ico")
	$file_iocs = ($workingpath + "\iocs-" + $global:logonas + ".txt")

	# MineMeld Static Variables
	$mmapi_user = ($credsdir + "api_accessid-" + $global:logonas)
	$mmapi_pass = ($credsdir + "api_securestring-" + $global:logonas)

	# ThreatConnect Static Variables
	[String]$Script:APIBaseURL = 'https://api.threatconnect.com'
	$throttle = '2' # Adjust to reduce or increase speed (in seconds) of API queries if ThreatConnect blocks connections due to agressiveness.
}

# Powershell version check (ConvertTo-Json -Compress requires Microsoft Powershell v3.0)
if ([string]$PSVersionTable.PSVersion -lt 3)
{
	Write-Host ""
	Write-Host "Missing Prerequisite: Windows Management Framework v3.0 or greater (Powershell v3.0+) is not installed."
	Write-Host "For more information about this package, visit: https://www.microsoft.com/en-us/download/details.aspx?id=34595"
	Write-Host ""
	Write-Host "Contact your system administrator for assistance.."
	Start-Sleep 10
	[Environment]::Exit(0)
}

# Create cache file directory if it doesn't exist
$cachedir_exists = test-path $cachedir
if ($cachedir_exists -eq $false)
{
	New-Item -ItemType directory -Path $cachedir | Out-Null
}

# Create config file directory if it doesn't exist
$configdir_exists = test-path $configdir
if ($configdir_exists -eq $false)
{
	New-Item -ItemType directory -Path $configdir | Out-Null
}

# Create creds file directory if it doesn't exist
$credsdir_exists = test-path $credsdir
if ($credsdir_exists -eq $false)
{
	New-Item -ItemType directory -Path $credsdir | Out-Null
}

# Create log file directory if it doesn't exist
$logdir_exists = test-path $logdir
if ($logdir_exists -eq $false)
{
	New-Item -ItemType directory -Path $logdir | Out-Null
}

# Purge Log Files
$daysback = ("-" + $log_retention_days)
$currentdate = Get-Date
$datetodelete = $currentdate.AddDays($daysback)
Get-ChildItem $logdir | Where-Object { $_.LastWriteTime -lt $datetodelete } | Remove-Item

# Prompt for Industry Sector
[String]$global:var_industrysector = Get-Content $sectorconf -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
if ($global:var_industrysector -eq $null -or $var_industrysector -eq "")
{

	[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
	[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
	
	$Form = New-Object System.Windows.Forms.Form
	$Form.Text = "Select your Industry Sector"
	$Form.Size = New-Object System.Drawing.Size(360, 240)
	$Form.StartPosition = "CenterScreen"
	$Icon = [system.drawing.icon]::ExtractAssociatedIcon($iconfile)
	$Form.Icon = $Icon
	
	$Form.KeyPreview = $True
	$Form.Add_KeyDown({
			if ($_.KeyCode -eq "Enter")
			{ $global:var_industrysector = $ListBox.SelectedItem; $Form.Close() }
		})
	$Form.Add_KeyDown({
			if ($_.KeyCode -eq "Escape")
			{ $Form.Close() }
		})
	
	$okButton = New-Object System.Windows.Forms.Button
	$okButton.Location = New-Object System.Drawing.Size(135, 140)
	$okButton.Size = New-Object System.Drawing.Size(75, 23)
	$okButton.Text = "OK"
	$okButton.Add_Click({ $global:var_industrysector = $ListBox.SelectedItem; $Form.Close() })
	$Form.Controls.Add($okButton)
	
	$Label = New-Object System.Windows.Forms.Label
	$Label.Location = New-Object System.Drawing.Size(10, 20)
	$Label.Size = New-Object System.Drawing.Size(350, 40)
	$Label.Text = "Please select an industry sector that closely`n`rmatches your organization the most (only used with ThreatConnect):"
	$Form.Controls.Add($Label)
	
	$ListBox = New-Object System.Windows.Forms.ListBox
	$ListBox.Location = New-Object System.Drawing.Size(10, 60)
	$ListBox.Size = New-Object System.Drawing.Size(320, 20)
	$ListBox.Height = 80
	
	[void]$ListBox.Items.Add("Aerospace")
	[void]$ListBox.Items.Add("Agriculture")
	[void]$ListBox.Items.Add("Automotive")
	[void]$ListBox.Items.Add("Chemical")
	[void]$ListBox.Items.Add("Commerical Facilities")
	[void]$ListBox.Items.Add("Communications and Telecommunications")
	[void]$ListBox.Items.Add("Construction")
	[void]$ListBox.Items.Add("Consumer Discretionary")
	[void]$ListBox.Items.Add("Dams")
	[void]$ListBox.Items.Add("Defense Industrial")
	[void]$ListBox.Items.Add("Education")
	[void]$ListBox.Items.Add("Emergency Services")
	[void]$ListBox.Items.Add("Entertainment")
	[void]$ListBox.Items.Add("Energy")
	[void]$ListBox.Items.Add("Financial Services")
	[void]$ListBox.Items.Add("Food and Agriculture")
	[void]$ListBox.Items.Add("Government")
	[void]$ListBox.Items.Add("Healthcare and Public Health")
	[void]$ListBox.Items.Add("Hospitality")
	[void]$ListBox.Items.Add("Information Technology")
	[void]$ListBox.Items.Add("Insurance")
	[void]$ListBox.Items.Add("Manufacturing")
	[void]$ListBox.Items.Add("Mining")
	[void]$ListBox.Items.Add("Media")
	[void]$ListBox.Items.Add("Pharmaceutical")
	[void]$ListBox.Items.Add("Real Estate")
	[void]$ListBox.Items.Add("Retail Trade")
	[void]$ListBox.Items.Add("Transportation")
	[void]$ListBox.Items.Add("Water and Wastewater")
	[void]$ListBox.Items.Add("Wholesale Trade")
	
	$Form.Controls.Add($ListBox)
	
	$Form.Topmost = $True
	
	$Form.Add_Shown({ $Form.Activate() })
	[void]$Form.ShowDialog()
	
	Write-Output $global:var_industrysector > $sectorconf
}

# Define indicator regex variables
if ($true)
{
	$regexhost = '(?i)(?=[^\s]+)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-zA-Z]{2,63})'
	$regexurl = '(?i:\b(?:(?:https?|ftp):\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,}))\.?)(?::\d{2,5})?(?:[/?#]\S*)?\b)'
	$regexaddr = '\b(?!(10) | 192\.168 | 172\. | ^.*\/$ | ^.*\/[0-9]{1,2}$)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
	$regexcidr = '\b(?!(10)|192\.168|172\.(2[0-9]|1[6-9]|3[0-2]))[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/(([0-9]|[1-2][0-9]|3[0-2]))?$\b'
	#$regexemailaddr = '\b+[a-zA-Z0-9\.\-_]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z0-9\.\-]+\b'
	#$regexmd5 = '(\b([a-fA-F\d]{32})\b)'
	$regexsha1 = '(\b([a-fA-F\d]{40})\b)'
	$regexsha256 = '\b([a-fA-F\d]{64})\b'
	#$regexsha512 = '\b([a-fA-F\d]{128})\b)'
}

# Build Functions
function Read-SingleLineInputBoxDialog([string]$Message, [string]$WindowTitle, [string]$HelpText, [string]$DefaultText, [string]$Required, [string]$IsPassword, [string]$CheckboxID)
{
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
 
	.PARAMETER IsPassword
    Text in the input box will be masked.
	
    .EXAMPLE
    $inputText = Read-SingleLineInputDialog -Message "Enter a value:" -WindowTitle "Window Title" -DefaultText "Default text for the input box."
	$inputText = Read-SingleLineInputDialog -Message "Enter a password:" -WindowTitle "Password Prompt" -DefaultText "" -IsPassword $true -Required $true
	
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
	if ($IsPassword -eq $true)
	{
		$textBox = New-Object System.Windows.Forms.MaskedTextBox
		$textBox.PasswordChar = '*'
		function IsThereText
		{
			if ($textBox.Text.Length -ne 0)
			{
				$button_confirm.Enabled = $true
			}
			else
			{
				$button_confirm.Enabled = $false
			}
		}
		$textBox.add_TextChanged({ IsThereText })
		$textBox.Size = '300,80'
		$textBox.AcceptsTab = $false
		$textBox.Multiline = $false
		$textBox.MaxLength = 100
		$textBox.Text = $DefaultText
		if ($Message.Length -gt 35)
		{
			$textBox.Location = '10,65'
		}
		else
		{
			$textBox.Location = '10,40'
		}
	}
	else
	{
		$textBox = New-Object System.Windows.Forms.TextBox
		$textBox.Text = $DefaultText
		function IsThereText
		{
			if ($textBox.Text.Length -ne 0)
			{
				$button_confirm.Enabled = $true
			}
			else
			{
				$button_confirm.Enabled = $false
			}
		}
		$textBox.add_TextChanged({ IsThereText })
		$textBox.Size = '300,80'
		$textBox.AcceptsReturn = $true
		$textBox.AcceptsTab = $false
		$textBox.Multiline = $false
		$textBox.MaxLength = 100
		$textBox.ScrollBars = 'Both'
		$textBox.Text = $DefaultText
		if ($Message.Length -gt 35)
		{
			$textBox.Location = '10,65'
		}
		else
		{
			$textBox.Location = '10,40'
		}
	}
	
	# Create the Next button.
	$button_confirm = New-Object System.Windows.Forms.Button
	if ($Required -eq $true -and $global:BackButtonState -ne $true -and $textBox.Text -eq "")
	{
		$button_confirm.Enabled = $false
	}
	else
	{
		$button_confirm.Enabled = $true
	}
	$button_confirm.Size = '75,25'
	$button_confirm.Text = "Next"
	$button_confirm.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $false; $form.Close() })
	if ($Message.Length -gt 35)
	{
		$button_confirm.Location = '10,120'
	}
	else
	{
		$button_confirm.Location = '10,100'
	}
	
	# Create the Back button.
	$button_back = New-Object System.Windows.Forms.Button
	if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "incident" -and $global:var_prop_value -ne "query")
	{
		$button_back.Enabled = $true
	}
	else
	{
		$button_back.Enabled = $false
	}
	$button_back.Size = '75,25'
	$button_back.Text = "Back"
	$button_back.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $true; $global:BackButtonState = $true; $form.Close() })
	if ($Message.Length -gt 35)
	{
		$button_back.Location = '90,120'
	}
	else
	{
		$button_back.Location = '90,100'
	}
	
	# Create the Cancel button.
	$button_cancel = New-Object System.Windows.Forms.Button
	$button_cancel.Size = '75,25'
	$button_cancel.Text = "Cancel"
	$button_cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$button_cancel.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
	if ($Message.Length -gt 35)
	{
		$button_cancel.Location = '170,120'
	}
	else
	{
		$button_cancel.Location = '170,100'
	}
	
	# Create the Help button.
	$HelpButton = new-object System.Windows.Forms.Button
	$HelpButton.Size = '75,25'
	$HelpButton.Text = 'Help'
	$HelpButton.DialogResult = [System.Windows.Forms.DialogResult]::None
	$HelpButton.Add_Click({ [System.Windows.Forms.MessageBox]::Show("$HelpText", "Help", 0) })
	if ($Message.Length -gt 35)
	{
		$HelpButton.Location = '250,120'
	}
	else
	{
		$HelpButton.Location = '250,100'
	}
	
	# Create the form.
	$form = New-Object System.Windows.Forms.Form
	$form.StartPosition = "CenterScreen"
	$form.Text = $WindowTitle
	if ($Message.Length -gt 35)
	{
		$form.Size = '360,200'
	}
	else
	{
		$form.Size = '360,180'
	}
	$form.FormBorderStyle = 'FixedSingle'
	$form.StartPosition = "CenterScreen"
	$form.AutoSizeMode = 'GrowAndShrink'
	$form.Topmost = $True
	$form.AcceptButton = $button_confirm
	$form.CancelButton = $button_cancel
	$form.ShowInTaskbar = $true
	$form.KeyPreview = $True
	
	# Add all of the controls to the form.
	$form.Controls.Add($label)
	$form.Controls.Add($textBox)
	$form.Controls.Add($button_confirm)
	$form.Controls.Add($button_cancel)
	$form.Controls.Add($button_back)
	$form.Controls.Add($HelpButton)
	
	# Initialize and show the form.
	$form.Add_Shown({ $form.Activate() })
	$form.ShowDialog() > $null # Trash the text of the button that was clicked.
	
	# Return the text that the user entered.
	return $form.Tag
}

function Read-MultiLineInputBoxDialog([string]$Message, [string]$WindowTitle, [string]$HelpText, [string]$DefaultText, [string]$Required, [string]$CheckboxID)
{
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
	$label.Location = New-Object System.Drawing.Size(10, 10)
	$label.Size = New-Object System.Drawing.Size(280, 300)
	$label.AutoSize = $true
	$label.Text = $Message
	
	# Create the TextBox used to capture the user's text.
	$textBox = New-Object System.Windows.Forms.TextBox
	$textBox.Location = New-Object System.Drawing.Size(10, 40)
	$textBox.Size = New-Object System.Drawing.Size(575, 200)
	$textBox.AcceptsReturn = $true
	$textBox.AcceptsTab = $false
	$textBox.Multiline = $true
	$textBox.ScrollBars = 'Both'
	$textBox.Text = $DefaultText
	
	if ($global:hideradio -ne "1")
	{
		
		# Create the TextBox used to set ttl.
		$textBox2 = New-Object System.Windows.Forms.TextBox
		$textBox2.Location = New-Object System.Drawing.Size(440, 250)
		$textBox2.Size = New-Object System.Drawing.Size(50, 20)
		$textBox2.AcceptsReturn = $true
		$textBox2.AcceptsTab = $false
		$textBox2.Multiline = $false
		$textBox2.ScrollBars = 'Both'
		$textBox2.Text = "365"
		$global:mmttl = $default_ioc_expiration
		
		$statusbar = New-Object System.Windows.Forms.StatusBar
		$statusbarpanel = New-Object System.Windows.Forms.StatusBarPanel
		$statusbarpanel.width = 600
		$statusbar.text = ""
		$statusbar.showpanels = $true
		$statusbar.Panels.Add($statusbarpanel) | Out-Null
		
		# Create the ttl checkbox
		$checkBox4 = New-Object System.Windows.Forms.CheckBox
		$checkBox4.Location = '250,250'
		$checkBox4.Autosize = $true
		$checkBox4.Text = "Expire indicators after (in days)"
		$checkBox4.Name = "checkBox"
		$checkBox4.checked = $true
		
		if ($global:mmttl)
		{
			$textBox2.Text = $global:mmttl
			$checkBox4.checked = $true
			$textBox2.Visible = $true
		}
		else
		{
			$textBox2.Text = ""
			$global:mmttl = ""
			$textBox2.Visible = $false
		}
		
		# Create the wildcard checkbox
		$checkBox1 = New-Object System.Windows.Forms.CheckBox
		$checkBox1.Location = '10,250'
		$checkBox1.Autosize = $true
		$checkBox1.Text = "Create wildcard entries for domains"
		$checkBox1.Name = "checkBox"
		if ($global:watchlistsel -eq $true -or $flag_mmdisabled -eq "1")
		{
			$checkBox1.Enabled = $false
		}
		else
		{
			$checkBox1.Enabled = $true
		}
		if ($global:cb -eq "1")
		{
			$checkBox1.checked = $true
		}
		else
		{
			$checkBox1.checked = $false
		}
		$checkBox1.Add_CheckStateChanged({
				if ($checkBox1.checked -eq $true)
				{
					Set-Variable -Name "global:cb" -Value "1"
				}
				else
				{
					Set-Variable -Name "global:cb" -Value "0"
				}
			})
		
		# Create the update watchlist checkbox
		$checkBox2 = New-Object System.Windows.Forms.CheckBox
		$checkBox2.Location = '10,270'
		$checkBox2.Autosize = $true
		$checkBox2.Text = "Also update the watchlist"
		$checkBox2.Name = "checkBox"
		if ($global:watchlistsel -eq $true -or $flag_mmdisabled -eq "1")
		{
			$checkBox2.Enabled = $false
		}
		else
		{
			$checkBox2.Enabled = $true
		}
		$checkBox2.checked = $true
		if ($global:cb2 -eq "1")
		{
			$checkBox2.checked = $true
		}
		else
		{
			$checkBox2.checked = $false
		}
		$checkBox2.Add_CheckStateChanged({
				if ($checkBox2.checked -eq $true)
				{
					Set-Variable -Name "global:cb2" -Value "1"
				}
				else
				{
					Set-Variable -Name "global:cb2" -Value "0"
				}
			})
		
		# Create the upload to ThreatConnect checkbox
		$checkBox3 = New-Object System.Windows.Forms.CheckBox
		$checkBox3.Location = '10,290'
		$checkBox3.Autosize = $true
		$checkBox3.Text = "Upload indicators to ThreatConnect"
		$checkBox3.Name = "checkBox"
		if ($global:watchlistsel -eq $true -or $flag_tcdisabled -eq "1")
		{
			$checkBox3.Enabled = $false
		}
		else
		{
			$checkBox3.Enabled = $true
		}
		
		if ($global:cb3 -eq "1")
		{
			$checkBox3.checked = $true
			$global:activatetc = "1"
			Set-Variable -Name "global:cb3" -Value "1"
		}
		elseif ($flag_mmdisabled -eq "1")
		{
			$checkBox3.Enabled = $false
			$checkBox3.checked = $true
			$global:activatetc = "1"
			Set-Variable -Name "global:cb3" -Value "1"
		}
		else
		{
			$checkBox3.checked = $false
		}
		$checkBox3.Add_CheckStateChanged({
				if ($checkBox3.checked -eq $true)
				{
					Set-Variable -Name "global:cb3" -Value "1"
					$global:activatetc = "1"
				}
				else
				{
					Set-Variable -Name "global:cb3" -Value "0"
					$global:activatetc = "0"
				}
			})
		
		$checkBox4.Enabled = $true
		if ($flag_mmdisabled -eq "1")
		{
			$checkBox4.Enabled = $false
		}
		else
		{
			$checkBox4.Enabled = $true
		}
		if ($global:cb4 -eq "1")
		{
			$checkBox4.checked = $true
		}
		else
		{
			$checkBox4.checked = $true
		}
		
		$textBox2.Visible = $true
		if ($flag_mmdisabled -eq "1")
		{
			$textBox2.Enabled = $false
		}
		else
		{
			$textBox2.Enabled = $true
		}
		if ($global:cb4 -eq "1")
		{
			$textBox2.Enabled = $true
			$textBox2.Visible = $true
		}
		else
		{
			$textBox2.Enabled = $true
		}
	}
	
	function global:IsThereText
	{
		if (($textBox.Text.Length -ne 0 -and ($checkBox4.checked -ne $true)) -or ($textBox.Text.Length -ne 0 -and ($checkBox4.checked -eq $true -and $textBox2.Text.Length -ne 0)))
		{
			if (($textBox.Text -like "*/*" -and $textBox.Text -like "*http*://*") -or ($textBox.Text -like "*/*" -and $textBox.Text -match ".*\/\d{1,2}"))
			{
				$statusbarpanel.text = ""
				$button_confirm.Enabled = $true
			}
			if (($textBox.Text -like "*/*" -and $textBox.Text -notlike "*http*://*") -and ($textBox.Text -like "*/*" -and $textBox.Text -notmatch ".*\/\d{1,2}"))
			{
				$statusbarpanel.text = "VALIDATION ERROR: URL's must be preceded with http:// or https://"
				$button_confirm.Enabled = $false
			}
			else
			{
				$statusbarpanel.text = ""
				$button_confirm.Enabled = $true
			}
			
		}
		else
		{
			$button_confirm.Enabled = $false
		}
	}
	
	function IsTTLChecked
	{
		if ($checkBox4.checked -eq $true)
		{
			$textBox2.Enabled = $true
			$textBox2.Visible = $true
			Set-Variable -Name "global:cb4" -Value "1"
			& IsThereText
		}
		else
		{
			$textBox2.Enabled = $false
			& IsThereText
			Set-Variable -Name "global:cb4" -Value "0"
		}
	}
	
	$textBox.add_TextChanged({ IsThereText })
	if ($global:hideradio -ne "1")
	{
		$checkBox4.Add_CheckStateChanged({ IsTTLChecked })
	}
	
	function IsTextChanged
	{
		# Check if Text contains any non-Digits
		if ($textBox2.Text -match '\D' -or $textBox2.Text -eq '' -or $textBox2.Text -eq '0')
		{
			# If so, remove them
			$textBox2.Text = $textBox2.Text -replace '\D'
			$textBox2.Text = $textBox2.Text -replace '0'
			# If Text still has a value, move the cursor to the end of the number
			& IsThereText
		}
		if ($textBox2.Text.Length -gt 0)
		{
			$textBox2.Focus()
			$textBox2.SelectionStart = $textBox2.Text.Length
			& IsThereText
			$global:mmttl = $textBox2.Text
		}
	}
	
	if ($global:hideradio -ne "1")
	{
		$textBox2.add_TextChanged({ IsThereText })
		$textBox2.add_TextChanged({ IsTextChanged })
	}
	
	# Create the Next button.
	$button_confirm = New-Object System.Windows.Forms.Button
	if ($Required -eq $true -and $global:BackButtonState -ne $true)
	{
		$button_confirm.Enabled = $false
		& IsThereText
	}
	else
	{
		$button_confirm.Enabled = $true
	}
	$button_confirm.Location = '10,320'
	$button_confirm.Size = '75,25'
	$button_confirm.Text = "Next"
	$button_confirm.Add_Click({ $form.Tag = $textBox.Text; $global:BackButtonAction = $false; $form.Close() })
	
	# Create the Back button.
	$button_back = New-Object System.Windows.Forms.Button
	if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "incident")
	{
		$button_back.Enabled = $true
	}
	else
	{
		$button_back.Enabled = $false
	}
	$button_back.Size = '75,25'
	$button_back.Text = "Back"
	$button_back.Add_Click({ $global:mmttl = $textBox2.Text; $form.Tag = $textBox.Text; $global:BackButtonAction = $true; $global:BackButtonState = $true; $form.Close() })
	$button_back.Location = '90,320'
	
	# Create the Cancel button.
	$button_cancel = New-Object System.Windows.Forms.Button
	$button_cancel.Location = '170,320'
	$button_cancel.Size = '75,25'
	$button_cancel.Text = "Cancel"
	$button_cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$button_cancel.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
	
	# Create the Help button.
	$HelpButton = new-object System.Windows.Forms.Button
	$HelpButton.Location = '250,320'
	$HelpButton.Size = '75,25'
	$HelpButton.Text = 'Help'
	$HelpButton.DialogResult = [System.Windows.Forms.DialogResult]::None
	$HelpButton.Add_Click({ [System.Windows.Forms.MessageBox]::Show("$HelpText", "Help", 0) })
	
	# Create the form.
	$form = New-Object System.Windows.Forms.Form
	$form.StartPosition = "CenterScreen"
	$form.Text = $WindowTitle
	$form.Size = New-Object System.Drawing.Size(610, 420)
	$form.FormBorderStyle = 'FixedSingle'
	$form.StartPosition = "CenterScreen"
	$form.AutoSizeMode = 'GrowAndShrink'
	$form.Topmost = $True
	$form.AcceptButton = $button_confirm
	$form.CancelButton = $button_cancel
	$form.ShowInTaskbar = $true
	$form.KeyPreview = $True
	
	# Add all of the controls to the form.
	$form.Controls.Add($label)
	$form.Controls.Add($textBox)
	$form.Controls.Add($textBox2)
	$form.Controls.Add($statusbar)
	if ($global:hideradio -ne "1")
	{
		$form.Controls.Add($checkBox1)
		$form.Controls.Add($checkBox2)
		$form.Controls.Add($checkBox3)
		$form.Controls.Add($checkBox4)
	}
	$form.Controls.Add($button_confirm)
	$form.Controls.Add($button_back)
	$form.Controls.Add($button_cancel)
	$form.Controls.Add($HelpButton)
	
	# Initialize and show the form.
	$form.Add_Shown({ $form.Activate() })
	$form.ShowDialog() > $null # Trash the text of the button that was clicked.
	
	return $form.Tag
}

# Set Dynamic Variables
if ($true)
{
	
	# Set MineMeld server variable
	# Example: minemeld.acme.corp
	[String]$server = Get-Content $serverconf -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	if ($server -eq $null -or $server -eq "")
	{
		read-host -Prompt "Enter your MineMeld Server IP or Hostname (e.g. minemeld.acme.corp)" | out-file $serverconf
	}
	
	# Stage or call MineMeld API username
	[String]$Script:MMAccessID = Get-Content $mmapi_user -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	if ($Script:MMAccessID -eq $null -or $Script:MMAccessID -eq "")
	{
		$mmapi_un_result = Read-SingleLineInputBoxDialog -Message "Enter your MineMeld username:" -WindowTitle ("PowerMM v" + $version + " - MM Username") -HelpText "Enter your username for the API user you setup in MineMeld.`n`r`n`r[ Enter 'None' to disable MineMeld support ]" -DefaultText "" -Required $true -CheckboxID "10"
		$mmapi_un_result | out-file $mmapi_user
	}
	if ($Script:MMAccessID -eq "None")
	{
		$flag_mmdisabled = "1"
	}
	else
	{
		$flag_mmdisabled = "0"
	}
	
	# Securely stage or call MineMeld encrypted API password
	$encryptedpassword = Get-Content $mmapi_pass -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | ConvertTo-SecureString -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	if (($encryptedpassword -eq $null -or $encryptedpassword -eq "") -and $flag_mmdisabled -ne "1")
	{
		$mmapi_ps_result = Read-SingleLineInputBoxDialog -Message "Enter your MineMeld password:" -WindowTitle ("PowerMM v" + $version + " - MM Password") -HelpText "Enter your password for the API user you setup in MineMeld." -DefaultText "" -Required $true -IsPassword $true -CheckboxID "11"
		$mmapi_ps_result = $mmapi_ps_result | ConvertTo-SecureString -AsPlainText -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
		$mmapi_ps_result | convertfrom-securestring -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | out-file $mmapi_pass
	}
	if ($flag_mmdisabled -eq "1")
	{
		$mmapi_ps_result = "None"
		$mmapi_ps_result = $mmapi_ps_result | ConvertTo-SecureString -AsPlainText -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
		$mmapi_ps_result | convertfrom-securestring -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | out-file $mmapi_pass
	}
	if ($encryptedpassword -ne $null -and $encryptedpassword -ne "")
	{
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedpassword)
		[String]$Script:MMSecretKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
	}
	
	# Securely stage or call ThreatConnect API authentication Access ID
	[String]$Script:TCAccessID = Get-Content $tcapi_accessid -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	if ($Script:TCAccessID -eq $null -or $Script:TCAccessID -eq "")
	{
		$tcapi_aid_result = Read-SingleLineInputBoxDialog -Message "Enter your ThreatConnect Access ID, or enter 'None' to disable:" -WindowTitle ("PowerMM v" + $version + " - TC Access ID") -HelpText "Enter your Access ID for the API user you setup in ThreatConnect.`n`r`n`r[ Enter 'None' to disable ThreatConnect support ]" -DefaultText "" -Required $true -CheckboxID "12"
		$tcapi_aid_result | out-file $tcapi_accessid
	}

	if ($Script:TCAccessID -eq "None" -or $Script:TCAccessID -eq $null -or $Script:TCAccessID -eq "")
	{
		$flag_tcdisabled = "1"
	}
	else
	{
		$flag_tcdisabled = "0"
	}
	
	# Securely stage or call ThreatConnect API authentication Secret Key
	$tcencryptedpassword = Get-Content $tcapi_secretkey -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	if (($tcencryptedpassword -eq $null -or $tcencryptedpassword -eq "") -and $flag_tcdisabled -ne "1")
	{
		$tcapi_skey_result = Read-SingleLineInputBoxDialog -Message "Enter your ThreatConnect Secret Key:" -WindowTitle ("PowerMM v" + $version + " - TC Secret Key") -HelpText "Enter your Secret Key for the API user you setup in ThreatConnect." -DefaultText "" -Required $true -IsPassword $true -CheckboxID "13"
		$tcapi_skey_result = $tcapi_skey_result | ConvertTo-SecureString -AsPlainText -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
		$tcapi_skey_result | convertfrom-securestring -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | out-file $tcapi_secretkey
	}
	if ($flag_tcdisabled -eq "1")
	{
		$tcapi_skey_result = "None"
		$tcapi_skey_result = $tcapi_skey_result | ConvertTo-SecureString -AsPlainText -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
		$tcapi_skey_result | convertfrom-securestring -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | out-file $tcapi_secretkey
	}
	
	# Set ThreatConnect Community
	[String]$community = Get-Content $tccommunityconf -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	if (($community -eq $null -or $community -eq "") -and $flag_tcdisabled -ne "1")
	{
		$tccommunity_result = Read-SingleLineInputBoxDialog -Message "Enter a ThreatConnect Community name:" -WindowTitle ("PowerMM v" + $version + " - TC Community") -HelpText "Enter a ThreatConnect Community Name that you want to update." -DefaultText "" -Required $true -CheckboxID "13"
		$tccommunity_result | out-file $tccommunityconf
	}
	if ($flag_tcdisabled -eq "1")
	{
		$tccommunity_result = "None"
		$tccommunity_result | out-file $tccommunityconf
	}
	
	# Set IPv4 Indicator List
	# Example: Acme_IPv4_blacklist
	$nodeconfig_path = $nodeconfig_bl_ipv4
	try
	{
		$nodesettings_bl_ipv4 = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_bl_ipv4 -eq $null -or $nodesettings_bl_ipv4 -eq "")
	{
		$nodename = read-host -Prompt "Enter the IPv4 Miner node name you wish to use for a blacklist"
		$outnodename = read-host -Prompt "Enter the associated IPv4 blacklist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",IPv4," + $outnodename) >> $nodeconfig_path
		}
		
	}
	foreach ($node in $nodesettings_bl_ipv4)
	{
		[String]$ipv4indlist = $node.name
		[String]$ipv4outnode = $node.output
	}
	
	# Set IPv4 Watch List
	# Example: Acme_IPv4_Watchlist
	$nodeconfig_path = $nodeconfig_watch_ipv4
	try
	{
		$nodesettings_watch_ipv4 = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_watch_ipv4 -eq $null -or $nodesettings_watch_ipv4 -eq "")
	{
		$nodename = read-host -Prompt "Enter the IPv4 Miner node name you wish to use for a watchlist"
		$outnodename = read-host -Prompt "Enter the associated IPv4 watchlist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",IPv4," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_watch_ipv4)
	{
		[String]$global:ipv4watchlist = $node.name
		[String]$global:ipv4wloutnode = $node.output
	}
	
	# Set URL Indicator List
	# Example: Acme_URL_blacklist
	$nodeconfig_path = $nodeconfig_bl_url
	try
	{
		$nodesettings_bl_url = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_bl_url -eq $null -or $nodesettings_bl_url -eq "")
	{
		$nodename = read-host -Prompt "Enter the URL Miner node name you wish to use for a blacklist"
		$outnodename = read-host -Prompt "Enter the associated URL blacklist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",URL," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_bl_url)
	{
		[String]$global:urlindlist = $node.name
		[String]$global:urloutnode = $node.output
	}
	
	# Set URL Watch List
	# Example: Acme_URL_Watchlist
	$nodeconfig_path = $nodeconfig_watch_url
	try
	{
		$nodesettings_watch_url = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_watch_url -eq $null -or $nodesettings_watch_url -eq "")
	{
		$nodename = read-host -Prompt "Enter the URL Miner node name you wish to use for a watchlist"
		$outnodename = read-host -Prompt "Enter the associated URL watchlist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",URL," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_watch_url)
	{
		[String]$global:urlwatchlist = $node.name
		[String]$global:urlwloutnode = $node.output
	}
	
	# Set SHA1 Indicator List
	# Example: Acme_SHA1_blacklist
	$nodeconfig_path = $nodeconfig_bl_sha1
	try
	{
		$nodesettings_bl_sha1 = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_bl_sha1 -eq $null -or $nodesettings_bl_sha1 -eq "")
	{
		$nodename = read-host -Prompt "Enter the SHA1 Miner node name you wish to use for a blacklist"
		$outnodename = read-host -Prompt "Enter the associated SHA1 blacklist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",SHA1," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_bl_sha1)
	{
		[String]$sha1indlist = $node.name
		[String]$sha1outnode = $node.output
	}
	
	# Set SHA1 Watch List
	# Example: Acme_SHA1_Watchlist
	$nodeconfig_path = $nodeconfig_watch_sha1
	try
	{
		$nodesettings_watch_sha1 = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_watch_sha1 -eq $null -or $nodesettings_watch_sha1 -eq "")
	{
		$nodename = read-host -Prompt "Enter the SHA1 Miner node name you wish to use for a watchlist"
		$outnodename = read-host -Prompt "Enter the associated SHA1 watchlist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",SHA1," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_watch_sha1)
	{
		[String]$global:sha1watchlist = $node.name
		[String]$global:sha1wloutnode = $node.output
	}
		
	# Set SHA256 Indicator List
	# Example: Acme_SHA256_blacklist
	$nodeconfig_path = $nodeconfig_bl_sha256
	try
	{
		$nodesettings_bl_sha256 = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_bl_sha256 -eq $null -or $nodesettings_bl_sha256 -eq "")
	{
		$nodename = read-host -Prompt "Enter the SHA256 Miner node name you wish to use for a blacklist"
		$outnodename = read-host -Prompt "Enter the associated SHA256 blacklist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",SHA256," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_bl_sha256)
	{
		[String]$sha256indlist = $node.name
		[String]$sha256outnode = $node.output
	}
	
	# Set SHA256 Watch List
	# Example: Acme_SHA256_Watchlist
	$nodeconfig_path = $nodeconfig_watch_sha256
	try
	{
		$nodesettings_watch_sha256 = Import-Csv $nodeconfig_path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	}
	catch [System.IO.FileNotFoundException]
	{
	}
	if ($nodesettings_watch_sha256 -eq $null -or $nodesettings_watch_sha256 -eq "")
	{
		$nodename = read-host -Prompt "Enter the SHA256 Miner node name you wish to use for a watchlist"
		$outnodename = read-host -Prompt "Enter the associated SHA256 watchlist output node name (to check it for duplicate indicators)"
		if ($nodename -ne $null -and $nodename -ne "" -and $outnodename -ne $null -and $outnodename -ne "")
		{
			Write-Output "name,type,output" > $nodeconfig_path
			Write-Output ($nodename + ",SHA256," + $outnodename) >> $nodeconfig_path
		}
	}
	foreach ($node in $nodesettings_watch_sha256)
	{
		[String]$global:sha256watchlist = $node.name
		[String]$global:sha256wloutnode = $node.output
	}
}

function Cleanup
{
	
	# Cleanup operational variables
	if ($Authorization) { Clear-Variable Authorization -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($AuthorizationHeaders) { Clear-Variable AuthorizationHeaders -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($HMACSHA256) { Clear-Variable HMACSHA256 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($HMACSignature) { Clear-Variable HMACSignature -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($HMACBase64) { Clear-Variable HMACBase64 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Headers) { Clear-Variable Headers -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($TCSecretKey) { Clear-Variable Headers -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Script:TCSecretKey) { Clear-Variable Headers -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($abortdialog) { Clear-Variable abortdialog -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($activatetc) { Clear-Variable activatetc -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($addr) { Clear-Variable addr -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($BackButtonAction) { Clear-Variable BackButtonAction -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($BackButtonState) { Clear-Variable BackButtonState -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($button_cancel) { Clear-Variable button_cancel -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($button_confirm) { Clear-Variable button_confirm -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($cb) { Clear-Variable cb -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($cb1) { Clear-Variable cb1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($cb2) { Clear-Variable cb2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($cb3) { Clear-Variable cb3 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($cb4) { Clear-Variable cb4 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Checkbox_History) { Clear-Variable Checkbox_History -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Checkbox_ManagedNodes) { Clear-Variable Checkbox_ManagedNodes -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Checkbox_ManagedServer) { Clear-Variable Checkbox_ManagedServer -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Checkboxes_History) { Clear-Variable Checkboxes_History -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Checkboxes_ManagedNodes) { Clear-Variable Checkboxes_ManagedNodes -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Comment) { Clear-Variable Comment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Confirm) { Clear-Variable Confirm -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($currentList) { Clear-Variable currentList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($dialogResult) { Clear-Variable dialogResult -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($DefaultText) { Clear-Variable DefaultText -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($flag_mmdisabled) { Clear-Variable flag_mmdisabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($flag_tcdisabled) { Clear-Variable flag_tcdisabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($foreach) { Clear-Variable foreach -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Form_MainMenu) { Clear-Variable Form_MainMenu -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Groupbox_History) { Clear-Variable Groupbox_History -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Groupbox_History_Offset) { Clear-Variable Groupbox_History_Offset -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Groupbox_ManagedNodes) { Clear-Variable Groupbox_ManagedNodes -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Groupbox_ManagedNodes_Offset) { Clear-Variable Groupbox_ManagedNodes_Offset -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($hideradio) { Clear-Variable hideradio -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($hist_checkboxfont) { Clear-Variable hist_checkboxfont -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($hist_desc) { Clear-Variable hist_desc -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($hist_timestamp) { Clear-Variable hist_timestamp -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($hist_user) { Clear-Variable hist_user -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($hosts) { Clear-Variable hosts -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($incident_hist_detail) { Clear-Variable incident_hist_detail -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($incidenthist_exists) { Clear-Variable incidenthist_exists -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($input) { Clear-Variable input -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioc) { Clear-Variable ioc -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioccache1) { Clear-Variable ioccache1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioccache2) { Clear-Variable ioccache2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioccache3) { Clear-Variable ioccache3 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioccache4) { Clear-Variable ioccache4 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioccache5) { Clear-Variable ioccache5 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($ioccache6) { Clear-Variable ioccache6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($list) { Clear-Variable list -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($listname) { Clear-Variable listname -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($listoutput) { Clear-Variable listoutput -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($listtype) { Clear-Variable listtype -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($logfile) { Clear-Variable logfile -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($mmttl) { Clear-Variable mmttl -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($node) { Clear-Variable node -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($nodearray2) { Clear-Variable nodearray2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($nodelist2) { Clear-Variable nodelist2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($nodename) { Clear-Variable nodename -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($nodeoutput) { Clear-Variable nodeoutput -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($nodetype) { Clear-Variable nodetype -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Panel_History) { Clear-Variable Panel_History -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($RadioButton_Option1) { Clear-Variable RadioButton_Option1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($RadioButton_Option2) { Clear-Variable RadioButton_Option2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($RadioButton_Option3) { Clear-Variable RadioButton_Option3 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($RadioButton_Option4) { Clear-Variable RadioButton_Option4 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($searchnodelist) { Clear-Variable searchnodelist -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($searchresult) { Clear-Variable searchresult -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($testpath) { Clear-Variable testpath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($testpath_tags) { Clear-Variable testpath_tags -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Textbox_ManagedServer) { Clear-Variable Textbox_ManagedServer -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($Textbox_MenuOptions) { Clear-Variable Textbox_MenuOptions -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($url) { Clear-Variable url -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($UTC) { Clear-Variable UTC -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($var_community) { Clear-Variable var_community -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($var_incidentname) { Clear-Variable var_incidentname -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($var_indicators) { Clear-Variable var_indicators -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($var_prop_value) { Clear-Variable var_prop_value -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($watchlistsel) { Clear-Variable watchlistsel -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:abortdialog) { Clear-Variable abortdialog -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:activatetc) { Clear-Variable activatetc -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:addr) { Clear-Variable addr -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:BackButtonAction) { Clear-Variable BackButtonAction -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:BackButtonState) { Clear-Variable BackButtonState -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:button_cancel) { Clear-Variable button_cancel -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:button_confirm) { Clear-Variable button_confirm -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:cb) { Clear-Variable cb -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:cb1) { Clear-Variable cb1 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:cb2) { Clear-Variable cb2 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:cb3) { Clear-Variable cb3 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:cb4) { Clear-Variable cb4 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Checkbox_History) { Clear-Variable Checkbox_History -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Checkbox_ManagedNodes) { Clear-Variable Checkbox_ManagedNodes -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Checkbox_ManagedServer) { Clear-Variable Checkbox_ManagedServer -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Checkboxes_History) { Clear-Variable Checkboxes_History -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Checkboxes_ManagedNodes) { Clear-Variable Checkboxes_ManagedNodes -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Comment) { Clear-Variable Comment -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Confirm) { Clear-Variable Confirm -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:currentList) { Clear-Variable currentList -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:dialogResult) { Clear-Variable dialogResult -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:DefaultText) { Clear-Variable DefaultText -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:flag_mmdisabled) { Clear-Variable flag_mmdisabled -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:flag_tcdisabled) { Clear-Variable flag_tcdisabled -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:foreach) { Clear-Variable foreach -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Form_MainMenu) { Clear-Variable Form_MainMenu -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Groupbox_History) { Clear-Variable Groupbox_History -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Groupbox_History_Offset) { Clear-Variable Groupbox_History_Offset -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Groupbox_ManagedNodes) { Clear-Variable Groupbox_ManagedNodes -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Groupbox_ManagedNodes_Offset) { Clear-Variable Groupbox_ManagedNodes_Offset -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:hideradio) { Clear-Variable hideradio -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:hist_checkboxfont) { Clear-Variable hist_checkboxfont -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:hist_desc) { Clear-Variable hist_desc -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:hist_timestamp) { Clear-Variable hist_timestamp -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:hist_user) { Clear-Variable hist_user -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:hosts) { Clear-Variable hosts -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:incident_hist_detail) { Clear-Variable incident_hist_detail -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:incidenthist_exists) { Clear-Variable incidenthist_exists -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:input) { Clear-Variable input -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioc) { Clear-Variable ioc -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioccache1) { Clear-Variable ioccache1 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioccache2) { Clear-Variable ioccache2 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioccache3) { Clear-Variable ioccache3 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioccache4) { Clear-Variable ioccache4 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioccache5) { Clear-Variable ioccache5 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:ioccache6) { Clear-Variable ioccache6 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:list) { Clear-Variable list -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:listname) { Clear-Variable listname -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:listoutput) { Clear-Variable listoutput -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:listtype) { Clear-Variable listtype -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:logfile) { Clear-Variable logfile -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:node) { Clear-Variable node -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:nodearray2) { Clear-Variable nodearray2 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:nodelist2) { Clear-Variable nodelist2 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:nodename) { Clear-Variable nodename -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:nodeoutput) { Clear-Variable nodeoutput -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:nodetype) { Clear-Variable nodetype -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Panel_History) { Clear-Variable Panel_History -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:RadioButton_Option1) { Clear-Variable RadioButton_Option1 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:RadioButton_Option2) { Clear-Variable RadioButton_Option2 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:RadioButton_Option3) { Clear-Variable RadioButton_Option3 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:RadioButton_Option4) { Clear-Variable RadioButton_Option4 -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:searchnodelist) { Clear-Variable searchnodelist -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:searchresult) { Clear-Variable searchresult -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:testpath) { Clear-Variable testpath -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:testpath_tags) { Clear-Variable testpath_tags -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Textbox_ManagedServer) { Clear-Variable Textbox_ManagedServer -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:Textbox_MenuOptions) { Clear-Variable Textbox_MenuOptions -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:url) { Clear-Variable url -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:UTC) { Clear-Variable UTC -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:var_community) { Clear-Variable var_community -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:var_incidentname) { Clear-Variable var_incidentname -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:var_indicators) { Clear-Variable var_indicators -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:var_prop_value) { Clear-Variable var_prop_value -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	if ($global:watchlistsel) { Clear-Variable watchlistsel -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue }
	
	# Check for and cleanup leftover remenants of an aborted execution
	$testpath_cleanup = Test-Path -Path $cachefile_iocs
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_iocs
	}
	$testpath_cleanup = Test-Path -Path $cachefile_tags
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_tags
	}
	$testpath_cleanup = Test-Path -Path $file_iocs
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $file_iocs
	}
	$testpath_cleanup = Test-Path -Path $cachefile_hosts
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_hosts
	}
	$testpath_cleanup = Test-Path -Path $cachefile_urls
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_urls
	}
	$testpath_cleanup = Test-Path -Path $cachefile_addr
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_addr
	}
	$testpath_cleanup = Test-Path -Path $cachefile_sha1
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_sha1
	}
	$testpath_cleanup = Test-Path -Path $cachefile_sha256
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_sha256
	}
	$testpath_cleanup = Test-Path -Path $cachefile_cidr
	if ($testpath_cleanup -eq $true)
	{
		Remove-Item -Path $cachefile_cidr
	}
}

function Get-ThreatConnectHeader
{
	<#
	.SYNOPSIS
		Generates the HTTP headers for an API request.
		
	.DESCRIPTION
		Each API request must contain headers that include a HMAC-SHA256, Base64 encoded signature and the Unix Timestamp. This function handles creation of those headers.
		This command is intended to be used by other commands in the Threat Connect Module.  It is not intended to be used manually at the command line, unless for testing purposes.
	
	.PARAMETER RequestMethod
		The HTTP Request Method for the API request (GET, PUT, POST, DELETE)
	
	.PARAMETER URL
		The Child URL for the API Request (Exclude the root, eg. https://api.threatconnect.com should not be included)
		
	.EXAMPLE
		Get-ThreatConnectHeader -RequestMethod "GET" -URL "/v2/owners"
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$RequestMethod,
		[Parameter(Mandatory = $True)]
		[String]$URL
	)
	# Calculate Unix UTC time
	[String]$Timestamp = [Math]::Floor([Decimal](Get-Date -Date (Get-Date).ToUniversalTime() -UFormat "%s"))
	# Create the HMAC-SHA256 Object to work with
	$HMACSHA256 = New-Object System.Security.Cryptography.HMACSHA256
	# Set the HMAC Key to the API Secret Key
	$tcencryptedpassword = Get-Content $tcapi_secretkey -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | ConvertTo-SecureString -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
	$TCBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tcencryptedpassword)
	[String]$Script:TCSecretKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($TCBSTR)
	$HMACSHA256.Key = [System.Text.Encoding]::UTF8.GetBytes($TCSecretKey)
	# Generate the HMAC Signature using API URI, Request Method, and Unix Time
	$HMACSignature = $HMACSHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$URL`:$RequestMethod`:$Timestamp"))
	# Base 64 Encode the HMAC Signature
	$HMACBase64 = [System.Convert]::ToBase64String($HMACSignature)
	# Craft the full Authorization Header
	$Authorization = "TC $($TCAccessID)`:$HMACBase64"
	# Create a HashTable where we will add the Authorization information
	$Headers = New-Object System.Collections.Hashtable
	$Headers.Add("Timestamp", $Timestamp)
	$Headers.Add("Authorization", $Authorization)
	return $Headers
}

function Get-EscapedURIString
{
	<#
	.SYNOPSIS
		Escapes special characters in the provided URI string (spaces become %20, etc.)
	
	.DESCRIPTION
		Uses System.URI's method "EscapeDataString" to convert special characters into their hex representation.
	
	.PARAMETER String
		The string that requires conversion
	
	.EXAMPLE
		Get-EscapedURIString -String "Test Escaping"
	#>
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$String
	)
	
	# Use System.URI's "EscapeDataString" method to convert
	[System.Uri]::EscapeDataString($String)
}

function UrlFix([Uri]$url)
{
	$uriFixerDef = @'
using System;
using System.Reflection;

public class UriFixer
{
    private const int UnEscapeDotsAndSlashes = 0x2000000;
    private const int SimpleUserSyntax = 0x20000;

    public static void LeaveDotsAndSlashesEscaped(Uri uri)
    {
        if (uri == null)
            throw new ArgumentNullException("uri");

        FieldInfo fieldInfo = uri.GetType().GetField("m_Syntax", BindingFlags.Instance | BindingFlags.NonPublic);
        if (fieldInfo == null)
            throw new MissingFieldException("'m_Syntax' field not found");

        object uriParser = fieldInfo.GetValue(uri);
        fieldInfo = typeof(UriParser).GetField("m_Flags", BindingFlags.Instance | BindingFlags.NonPublic);
        if (fieldInfo == null)
            throw new MissingFieldException("'m_Flags' field not found");

        object uriSyntaxFlags = fieldInfo.GetValue(uriParser);

        // Clear the flag that we do not want
        uriSyntaxFlags = (int)uriSyntaxFlags & ~UnEscapeDotsAndSlashes;
        uriSyntaxFlags = (int)uriSyntaxFlags & ~SimpleUserSyntax;
        fieldInfo.SetValue(uriParser, uriSyntaxFlags);
    }
}
'@
	Add-Type -TypeDefinition $uriFixerDef
	[UriFixer]::LeaveDotsAndSlashesEscaped($url)
}

function Build-Indicator-Files
{
	if ($global:var_indicators -ne $null -and $global:var_indicators -ne "")
	{
		$global:var_indicators = $global:var_indicators -split '\n'
		Write-Output $null > $cachefile_iocs
		foreach ($ioc in $global:var_indicators)
		{
			$ioc = $ioc.replace("[", "")
			$ioc = $ioc.replace("]", "")
			$ioc = $ioc.replace("(", "")
			$ioc = $ioc.replace(")", "")
			$ioc = $ioc.replace("{", "")
			$ioc = $ioc.replace("}", "")
			$ioc = $ioc.replace("hxxps://", "https://")
			$ioc = $ioc.replace("hxxp://", "http://")
			Write-Output $ioc >> $cachefile_iocs
		}
		
		# Loop URL indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		Select-String -Path $input_file -Pattern $regexurl -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache2 = Get-Content $output_file
		$cachearray_urls = @()
		foreach ($ioc in $global:ioccache2)
		{
			$ioc = $ioc.replace("https://www.", "")
			$ioc = $ioc.replace("http://www.", "")
			$ioc = $ioc.replace("https://", "")
			$ioc = $ioc.replace("http://", "")
			$cachearray_urls += "$ioc"
		}
		$global:ioccache2 = $cachearray_urls | Select-Object -Unique
		Remove-Item -Path $cachefile_urls -ErrorAction SilentlyContinue
		if ($global:ioccache2 -ne $null -and $global:ioccache2 -ne "")
		{
			Write-Host "Regex extracted the following URLs: ($global:ioccache2)"
			foreach ($ioc in $global:ioccache2)
			{
				Write-Output $ioc >> $cachefile_urls
			}
			$nohttp = Get-Content $input_file | Where-Object { $_ -notmatch '^http.*$' } | Out-File $output_file -Force -Confirm:$false
			Get-Content $output_file | Where-Object { $_.trim() -ne "" } | Out-File $input_file -Force -Confirm:$false
		}
		
		# Loop Hostname indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		Select-String -Path $input_file -Pattern $regexhost -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache1 = Get-Content $output_file
		$global:ioccache1 = $global:ioccache1 | Select-Object -Unique
		Remove-Item -Path $cachefile_hosts -ErrorAction SilentlyContinue
		if ($global:ioccache1 -ne $null -and $global:ioccache1 -ne "")
		{
			Write-Host "Regex extracted the following domains: ($global:ioccache1)"
			$global:ioccache1 = Get-Content $output_file
			foreach ($ioc in $global:ioccache1)
			{
				Write-Output $ioc >> $cachefile_hosts
			}
		}
		
		# Loop IPv4 Address indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		Select-String -Path $input_file -Pattern $regexaddr -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache3 = Get-Content $output_file
		$global:ioccache3 = $global:ioccache3 | Select-Object -Unique
		Remove-Item -Path $cachefile_addr -ErrorAction SilentlyContinue
		if ($global:ioccache3 -ne $null -and $global:ioccache3 -ne "")
		{
			Write-Host "Regex extracted the following IP Addresses: ($global:ioccache3)"
			Write-Host ""
			foreach ($ioc in $global:ioccache3)
			{
				Write-Output $ioc >> $cachefile_addr
			}
		}
				
		# Loop File SHA1 indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		Select-String -Path $input_file -Pattern $regexsha1 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache4 = Get-Content $output_file
		$global:ioccache4 = $global:ioccache4 | Select-Object -Unique
		Remove-Item -Path $cachefile_sha1 -ErrorAction SilentlyContinue
		if ($global:ioccache4 -ne $null -and $global:ioccache4 -ne "")
		{
			Write-Host "Regex extracted the following SHA1 file hashes: ($global:ioccache4)"
			Write-Host ""
			foreach ($ioc in $global:ioccache4)
			{
				Write-Output $ioc >> $cachefile_sha1
			}
		}
		
		# Loop File SHA256 indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		Select-String -Path $input_file -Pattern $regexsha256 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache5 = Get-Content $output_file
		$global:ioccache5 = $global:ioccache5 | Select-Object -Unique
		Remove-Item -Path $cachefile_sha256 -ErrorAction SilentlyContinue
		if ($global:ioccache5 -ne $null -and $global:ioccache5 -ne "")
		{
			Write-Host "Regex extracted the following SHA256 file hashes: ($global:ioccache5)"
			Write-Host ""
			foreach ($ioc in $global:ioccache5)
			{
				Write-Output $ioc >> $cachefile_sha256
			}
		}
		
		# Loop IPv4 CIDR Block indicator regex pattern through import file
		$input_file = $cachefile_iocs
		$output_file = $file_iocs
		Select-String -Path $input_file -Pattern $regexcidr -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } > $output_file -ErrorAction SilentlyContinue
		$global:ioccache6 = Get-Content $output_file
		$global:ioccache6 = $global:ioccache6 | Select-Object -Unique
		Remove-Item -Path $cachefile_cidr -ErrorAction SilentlyContinue
		if ($global:ioccache6 -ne $null -and $global:ioccache6 -ne "")
		{
			Write-Host "Regex extracted the following IP CIDR Blocks: ($global:ioccache6)"
			Write-Host ""
			foreach ($ioc in $global:ioccache6)
			{
				Write-Output $ioc >> $cachefile_cidr
			}
		}
		
	}
}

function New-MMIndicator
{
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
	    New-MMIndicator -Server 192.168.1.10 -Indicator "evil.com"
        This will add the url evil.com to the default list on minemeld server (192.168.1.1)
    .EXAMPLE
	    New-MMIndicator -Server 192.168.1.10 -Indicator "evil.com" -IncludeSubDomain
        Will add the url's evil.com and *.evil.com to the default list on minemeld server (192.168.1.1)
    .EXAMPLE
	    New-MMIndicator -Server 192.168.1.10 -Indicator "evil.com" -BypassSSL
        This will add the url evil.com to the default list on minemeld server (192.168.1.1) and bypass and SSL certificate errors caused by self-signed SSL certs.
    .EXAMPLE
	    New-MMIndicator -Server 192.168.1.10 -Indicator "172.16.12.21" -Type IPv4 -FeedList "mm_dc_list" -IndicatorList "DC_IP_List"
        Will Add ip address 172.16.21.21 to DC_IP_List on minemeld server (192.168.1.1). It will check "mm_dc_list" for the indicator first to avoid duplicating the indicator.
    #>
	[CmdletBinding()]
	Param (
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "IP-Address or FQDN of MineMeld Server:",
				   Position = 0)]
		[String]$Server,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Output List Name:",
				   Position = 1)]
		[String]$FeedList = "Default_URL_List",
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Node Name:",
				   Position = 2)]
		[String]$IndicatorList = "Default_Indicator_List",
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Indicator type (IPv4, CIDR, URL, SHA1, or SHA256):",
				   Position = 3)]
		[string][validateSet("IPv4", "CIDR", "URL", "SHA1", "SHA256")]
		$Type = "URL",
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Indicator value:",
				   Position = 4)]
		[string]$Indicator,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Share level:",
				   Position = 5)]
		[string][validateSet("green", "yellow", "red")]
		$ShareLevel = "red",
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Bypasses SSL:",
				   Position = 6)]
		[switch]$BypassSSL,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $false,
				   HelpMessage = "Skips checking for duplicates:",
				   Position = 7)]
		[switch]$SkipDupCheck,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Include wildcard character to for subdomains (e.g. *.evil.com):",
				   Position = 8)]
		[switch]$IncludeSubDomain
	)
	Begin
	{
		if ($SkipDupCheck -ne $true)
		{
			$global:url = "https://" + $Server + "/feeds/" + $FeedList + "?tr=1"
			$global:currentList = Invoke-RestMethod $global:url -TimeoutSec 30
		}
		
		#        If ($BypassSSL)
		#        {
		#            #if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type)
		#            #{
		#                add-type @"
		#                using System.Net;
		#                using System.Security.Cryptography.X509Certificates;
		#                public class TrustAllCertsPolicy : ICertificatePolicy {
		#                    public bool CheckValidationResult(
		#                        ServicePoint srvPoint, X509Certificate certificate,
		#                        WebRequest request, int certificateProblem) {
		#                        return true;
		#                    }
		#                }
		#"@
		#                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
		#            #}
		#        }
		
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
			$userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Script:MMAccessID):$($Script:MMSecretKey)"))
			# Adding the Authentication string to the post request headers
			$MMHeaders = @{
				Authorization = 'Basic ' + $userPass
			}
			while (-not $exitLoop)
			{
				if ($SkipDupCheck -ne $true)
				{
					# Check if indicator exists
					$Indicator_ioconly = $null
					$Indicator_addstamp = $null
					$Indicator_comment = $null
					$Indicator_ioconly, $Indicator_addstamp, $Indicator_comment = $Indicator.split(',')
					if ($Indicator_addstamp -eq $null -or $Indicator_addstamp -eq "")
					{
						$Indicator_addstamp = $global:UTC
					}
					if ($Indicator_comment -eq $null -or $Indicator_comment -eq "")
					{
						$Indicator_comment = $global:Comment
					}
					if ($global:currentList)
					{
						if ($global:currentList.Contains(","))
						{
							if (-not $global:currentList.Contains($Indicator_ioconly + ","))
							{
								# Array that will be converted to JSON format for POST request
								if ($global:mmttl -eq "0" -or $global:mmttl -eq "")
								{
									$ttl = "-1"
								}
								else
								{
									$ttl = New-TimeSpan -Days $global:mmttl
									$ttl = $ttl.TotalSeconds
								}
								$indicatorArr = @{
									indicator = "$Indicator"
									type	  = "$Type"
									share_level = "$ShareLevel"
									comment   = "$global:Comment"
									ttl	      = $ttl
								}
								$requestBody = $indicatorArr | ConvertTo-Json -Compress
								$global:url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList + "&t=localdb"
								$Response = Invoke-RestMethod $global:url -Method 'Post' -Body $requestBody -ContentType 'application/json' -Headers $MMHeaders
								Write-Host -ForegroundColor Green "   The indicator $indicator_ioconly was added to $IndicatorList"
								Write-Output "The indicator $indicator_ioconly was added to $IndicatorList" >> $global:logfile
							}
							else
							{
								Write-Host -ForegroundColor Red "   The indicator $indicator_ioconly found in $IndicatorList was skipped. Delete it using search first, then re-add."
								Write-Output "The indicator $indicator_ioconly found in $IndicatorList was skipped. Delete it using search first, then re-add." >> $global:logfile
							}
						}
						else
						{
							if (-not $global:currentList.Contains($Indicator_ioconly))
							{
								# Array that will be converted to JSON format for POST request
								if ($global:mmttl -eq "0" -or $global:mmttl -eq "")
								{
									$ttl = "-1"
								}
								else
								{
									$ttl = New-TimeSpan -Days $global:mmttl
									$ttl = $ttl.TotalSeconds
								}
								$indicatorArr = @{
									indicator = "$Indicator"
									type	  = "$Type"
									share_level = "$ShareLevel"
									comment   = "$global:Comment"
									ttl	      = $ttl
								}
								$requestBody = $indicatorArr | ConvertTo-Json -Compress
								$global:url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList + "&t=localdb"
								$Response = Invoke-RestMethod $global:url -Method 'Post' -Body $requestBody -ContentType 'application/json' -Headers $MMHeaders
								Write-Host -ForegroundColor Green "   The indicator $indicator_ioconly was added to $IndicatorList"
								Write-Output "The indicator $indicator_ioconly was added to $IndicatorList" >> $global:logfile
							}
							else
							{
								# Array that will be converted to JSON format for POST request
								if ($global:mmttl -eq "0" -or $global:mmttl -eq "")
								{
									$ttl = "-1"
								}
								else
								{
									$ttl = New-TimeSpan -Days $global:mmttl
									$ttl = $ttl.TotalSeconds
								}
								$indicatorArr = @{
									indicator = "$Indicator"
									type	  = "$Type"
									share_level = "$ShareLevel"
									comment   = "$global:Comment"
									ttl	      = $ttl
								}
								$requestBody = $indicatorArr | ConvertTo-Json -Compress
								$global:url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList + "&t=localdb"
								$Response = Invoke-RestMethod $global:url -Method 'Post' -Body $requestBody -ContentType 'application/json' -Headers $MMHeaders
								Write-Host -ForegroundColor Cyan "   The indicator $indicator_ioconly exists in $IndicatorList and has been updated."
								Write-Output "The indicator $indicator_ioconly exists in $IndicatorList and has been updated." >> $global:logfile
							}
						}
					}
				}
				else
				{
					# Array that will be converted to JSON format for POST request
					$Indicator_ioconly = $null
					$Indicator_addstamp = $null
					$Indicator_comment = $null
					$Indicator_ioconly, $Indicator_addstamp, $Indicator_comment = $Indicator.split(',')
					if ($Indicator_addstamp -eq $null -or $Indicator_addstamp -eq "")
					{
						$Indicator_addstamp = $global:UTC
					}
					if ($Indicator_comment -eq $null -or $Indicator_comment -eq "")
					{
						$Indicator_comment = "-"
					}
					if ($global:mmttl -eq "0" -or $global:mmttl -eq "")
					{
						$ttl = "-1"
					}
					else
					{
						$ttl = New-TimeSpan -Days $global:mmttl
						$ttl = $ttl.TotalSeconds
					}
					$indicatorArr = @{
						indicator = "$Indicator"
						type	  = "$Type"
						share_level = "$ShareLevel"
						comment   = "$global:Comment"
						ttl	      = $ttl
					}
					$requestBody = $indicatorArr | ConvertTo-Json -Compress
					$global:url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList + "&t=localdb"
					$Response = Invoke-RestMethod $global:url -Method 'Post' -Body $requestBody -ContentType 'application/json' -Headers $MMHeaders
					Write-Host -ForegroundColor Green "   The indicator $indicator_ioconly was added to $IndicatorList"
					Write-Output "The indicator $indicator_ioconly was added to $IndicatorList" >> $global:logfile
				}
				if ("$Type" -eq "URL")
				{
					# Process structure for URL Indicators
					if (($IncludeSubDomain -and $Indicator.Contains("*.")) -or -not $IncludeSubDomain)
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
			if ($Response -eq $null)
			{
				Clear-Host
				Write-Host -ForegroundColor Red $_.Exception.Message
				Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
				pause
			}
		}
	}
	end
	{

	}
}

function Remove-MMIndicator
{
    <#
    .SYNOPSIS
        Remove indicators from MineMeld feeds utilized by Palo Alto Firewalls
    .DESCRIPTION
        This cmdlet can be utilized to remove threat indicators from nodes in minemeld ( A Palo Alto open source threat aggregation tool).
        Mandatory functions for this function include; Server, FeedList, IndicatorList, Type and Indicator.
    .PARAMETER Server
        This Parameter contains the ip-address or FQDN of the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Indicator
        This Parameter contains the Indicator to be removed from the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Type
        This Parameter contains the type of indicator to be removed from the the MineMeld server (IPv4 or URL).
        Parameter Default Value: URL
    .PARAMETER IndicatorList
        This Parameter contains the name of the input stream/list where the indicator should be removed from.
        Parameter Default Value: dvn_Malware_List
    .PARAMETER BypassSSL
        If this parameter is present self-signed certificate errors will be bypassed.
    .EXAMPLE
	    Remove-MMIndicator -Server 192.168.1.10 -Indicator "evil.com"
        This will remove the url evil.com from the default list on minemeld server (192.168.1.1)
    .EXAMPLE
	    Remve-Indicator -Server 192.168.1.10 -Indicator "evil.com" -BypassSSL
        This will remove the url evil.com from the default list on minemeld server (192.168.1.1) and bypass SSL certificate errors caused by self-signed SSL certs.
    .EXAMPLE
	    Remove-MMIndicator -Server 192.168.1.10 -Indicator "172.16.12.21" -Type IPv4 -IndicatorList "DC_IP_List"
        Will remove ip address 172.16.21.21 from DC_IP_List on minemeld server (192.168.1.1).
    #>
	[CmdletBinding()]
	Param (
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "IP-Address or FQDN of MineMeld Server:",
				   Position = 0)]
		[String]$Server,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Node Name/List:",
				   Position = 3)]
		[String]$IndicatorList = "Default_Indicator_List",
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Indicator type (IPv4, CIDR, URL, SHA1, or SHA256):",
				   Position = 1)]
		[string][validateSet("IPv4", "CIDR", "URL", "SHA1", "SHA256")]
		$Type = "URL",
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Indicator value:",
				   Position = 5)]
		[string]$Indicator,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Share level:",
				   Position = 7)]
		[string][validateSet("green", "yellow", "red")]
		$ShareLevel = "red",
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Bypass SSL Errors:",
				   Position = 2)]
		[switch]$BypassSSL
	)
	Begin
	{
		If ($BypassSSL)
		{
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
			$userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Script:MMAccessID):$($Script:MMSecretKey)"))
			# Adding the Authentication string to the post request headers
			$MMHeaders = @{
				Authorization = 'Basic ' + $userPass
			}
			# Array that will be converted to JSON format for POST request
			$Indicator_ioconly = $Indicator -replace ",.*"
			$indicatorArr = @{
				ttl  = 0
				type = "$Type"
				indicator = "$Indicator"
			}
			$requestBody = $indicatorArr | ConvertTo-Json -Compress
			$global:url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList + "&t=localdb"
			$Response = Invoke-RestMethod $global:url -Method 'Post' -Body $requestBody -ContentType 'application/json' -Headers $MMHeaders
			Write-Host -ForegroundColor Green "   The following indicator has been deleted: $Indicator_ioconly"
			Write-Output "The following indicator has been deleted: $Indicator_ioconly" >> $global:logfile
		}
		catch
		{
			if ($Response -eq $null)
			{
				Clear-Host
				Write-Host -ForegroundColor Red $_.Exception.Message
				Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
				pause
			}
		}
	}
	end
	{
	}
}

function Populate-MMNode
{
    <#
    .SYNOPSIS
        Populate indicators from a URL to a Node in MineMeld
    #>
	[CmdletBinding()]
	Param (
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "IP-Address or FQDN of MineMeld Server:",
				   Position = 0)]
		[String]$Server,
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Name of source URL containing indicators to clone:",
				   Position = 1)]
		[String]$SourceURL,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Name of destination node to copy indicators to:",
				   Position = 2)]
		[string]$DestNode,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Indicator type (IPv4, CIDR, URL, SHA1, or SHA256):",
				   Position = 3)]
		[string][validateSet("IPv4", "CIDR", "URL", "SHA1", "SHA256")]
		$Type = "URL",
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Bypass SSL",
				   Position = 4)]
		[switch]$BypassSSL
	)
	Begin
	{
		If ($BypassSSL)
		{
			#                add-type @"
			#                using System.Net;
			#                using System.Security.Cryptography.X509Certificates;
			#                public class TrustAllCertsPolicy : ICertificatePolicy {
			#                    public bool CheckValidationResult(
			#                        ServicePoint srvPoint, X509Certificate certificate,
			#                        WebRequest request, int certificateProblem) {
			#                        return true;
			#                    }
			#                }
			#"@
			#                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
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
			$userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Script:MMAccessID):$($Script:MMSecretKey)"))
			# Adding the Authentication string to the post request headers
			$MMHeaders = @{
				Authorization = 'Basic ' + $userPass
			}
			
			function Populate-Engine
			{
				
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
				
				$global:url = ($SourceURL + "?tr=1")
				$global:currentList = Invoke-RestMethod -Uri $global:url -TimeoutSec 30
				$iocarray = @()
				$iocarray = $global:currentList.ParsedHtml.body.InnerText.split(" ")
				
				foreach ($line in $iocarray)
				{
					$nullline = $false
					if ($line -eq $null -or $line -eq "")
					{
						Write-Host "Error: empty ioc"
						$nullline = $true
					}
					$Indicator_ioconly = $null
					$Indicator_addstamp = $null
					$Indicator_comment = $null
					$Indicator_ioconly, $Indicator_addstamp, $Indicator_comment = $line.split(',')
					if ($Indicator_addstamp -eq $null -or $Indicator_addstamp -eq "")
					{
						$Indicator_addstamp = $global:UTC
					}
					if ($Indicator_comment -eq $null -or $Indicator_comment -eq "")
					{
						$Indicator_comment = "-"
					}
					if ($nullline -ne $true)
					{
						if ($Indicator_ioconly -eq $line)
						{
							New-MMIndicator -Server $Server -Indicator ($line) -Type $Type -IndicatorList $DestNode -SkipDupCheck:$false -BypassSSL
						}
						else
						{
							New-MMIndicator -Server $Server -Indicator ($Indicator_ioconly + "," + $Indicator_addstamp + "," + $Indicator_comment) -Type $Type -IndicatorList $DestNode -SkipDupCheck:$false -BypassSSL
						}
					}
				}
				
				while ($global:BackButtonAction -eq $true)
				{
					if ($global:abortdialog -ne $true)
					{
						& Populate-Query
						$global:BackButtonAction = $false
						if ($global:abortdialog -ne $true)
						{
							if ($global:var_prop_value -eq "query")
							{
								& Populate-Query
								$global:BackButtonAction = $false
							}
						}
					}
				}
			}
			& Populate-Engine
		}
		catch
		{
			Clear-Host
			Write-Host -ForegroundColor Red $_.Exception.Message
			Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
			pause
		}
	}
	end
	{
	}
}

function Search-MMIndicator
{
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
	    Search-MMIndicator -Server 192.168.1.10 -Indicator "172.16.12.21" -Type IPv4 -FeedList "mm_dc_list"
        It will search "mm_dc_list" for the defined indicator "172.16.12.21".
    #>
	[CmdletBinding()]
	Param (
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "IP-Address or FQDN of MineMeld Server:",
				   Position = 0)]
		[String]$Server,
		[parameter(Mandatory = $false,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Indicator type (IPv4, CIDR, URL, SHA1, SHA256):",
				   Position = 3)]
		[string]$Indicator,
		[parameter(Mandatory = $true,
				   valueFromPipelineByPropertyName = $true,
				   HelpMessage = "Threat indicator to search for:",
				   Position = 2)]
		[switch]$BypassSSL
	)
	Begin
	{
		If ($BypassSSL)
		{
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
			$userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Script:MMAccessID):$($Script:MMSecretKey)"))
			# Adding the Authentication string to the post request headers
			$MMHeaders = @{
				Authorization = 'Basic ' + $userPass
			}
			
			function Search-QueryResult
			{
				
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
				
				$searchnodelist = $null
				$global:dialogResult = $null
				$global:somethingfound = $false
				$global:enableform = $false
				$Checkboxes = $null
				$Checkbox = $null
				
				# Set the size of the form
				$form = New-Object System.Windows.Forms.Form
				$form.Text = "PowerMM - Confirmation"
				$form.StartPosition = "CenterScreen"
				$form.AutoSize = $true
				
				# Set the font of the text to be used within the form
				$formfont = New-Object System.Drawing.Font("Arial", 10)
				$groupboxfont = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
				$checkboxfont = New-Object System.Drawing.Font("Arial", 8)
				
				$form.Font = $formfont
				
				$groupBox = New-Object System.Windows.Forms.GroupBox
				$groupBox.Font = $groupboxfont
				$groupBox.Location = New-Object System.Drawing.Size(10, 8)
				$groupBox.AutoSize = $true
				$groupBox.MinimumSize = '400,0'
				$groupBox.text = ("Matching Entries:")
				
				$Checkboxes += New-Object System.Windows.Forms.CheckBox
				$Checkboxes.Location = New-Object System.Drawing.Size(10, 20)
				
				$nodelist = Import-Csv -Path (Get-ChildItem -Path $configdir -Filter 'node_*.conf').FullName
				$nodearray = @()
				$Checkboxes = @()
				$Groupbox_IOC_Offset = 20
				
				foreach ($node in $nodelist)
				{
					$searchnodelist = New-Object System.Object
					$nodename = $node.name
					$nodetype = $node.type
					$nodeoutput = $node.output
					$searchnodelist | Add-Member -MemberType NoteProperty -name "IndicatorList" -Value $nodename
					$searchnodelist | Add-Member -MemberType NoteProperty -name "Type" -Value $nodetype
					$searchnodelist | Add-Member -MemberType NoteProperty -name "FeedList" -Value $nodeoutput
					$nodearray += $searchnodelist
				}
				
				foreach ($list in $nodearray)
				{
					$listname = $list.IndicatorList
					$listtype = $list.Type
					$listoutput = $list.FeedList
					$global:url = ("https://" + $Server + "/feeds/" + $listoutput + "?tr=1&v=json")
					Write-Host "Searching $listname.."
					$global:currentList = Invoke-RestMethod -Uri $global:url -TimeoutSec 30
					if ($global:currentList.Length -ne "1")
					{
						$iocarray = $global:currentList.indicator
						foreach ($line in $iocarray)
						{
							$origline = $line
							$Indicator | ForEach-Object -Begin { $found = $false } {
								$splitdesc = $null
								$ind = $_.ToString()
								$splitioc = $line.split(",")[0]
								if ($line.Contains(','))
								{
									$splitdesc = $line.split(",")[2]
								}
								else
								{
									$splitdesc = $null
								}
								$line = $splitioc
								If ($line -match $ind)
								{
									$found = $true
									$linematch = $origline
									$global:somethingfound = $true
									$global:enableform = $true
								}
								if ($found)
								{
									$Checkbox = New-Object System.Windows.Forms.CheckBox
									$Checkbox | Add-Member -NotePropertyName IndicatorList -NotePropertyValue $listname
									$Checkbox | Add-Member -NotePropertyName Type -NotePropertyValue $listtype
									$Checkbox | Add-Member -NotePropertyName FeedList -NotePropertyValue $listoutput
									$Checkbox | Add-Member -NotePropertyName IOC -NotePropertyValue $line
									$Checkbox | Add-Member -NotePropertyName OrigLine -NotePropertyValue $linematch
									$line = $line -replace ",.*"
									if ($splitdesc -ne $null)
									{
										$Checkbox.Text = ("( " + $listname + " ):   " + $line + " [ Description: " + $splitdesc + " ]")
									}
									else
									{
										$Checkbox.Text = ("( " + $listname + " ):   " + $line)
									}
									$Checkbox.Font = $checkboxfont
									if ($Checkbox.Text -match "CoM*Watch*")
									{
										$Checkbox.ForeColor = "red"
										$Checkbox.Enabled = "false"
									}
									elseif ($Checkbox.Text -like "CoM*ssl*")
									{
										$Checkbox.ForeColor = "blue"
									}
									elseif ($Checkbox.Text -like "wl*")
									{
										$Checkbox.ForeColor = "green"
									}
									$Checkbox.Location = New-Object System.Drawing.Size(10, $Groupbox_IOC_Offset)
									$Groupbox_IOC_Offset += 20
									$Checkbox.AutoSize = $true
									$groupBox.Controls.Add($Checkbox)
									$Checkboxes += $Checkbox
								}
							}
						}
					}
				}
				
				if ($global:enableform -eq $true)
				{
					
					# Padding
					$padding = New-Object Windows.Forms.Textbox
					$padding.AutoSize = $false
					$padding.Location = New-Object System.Drawing.Size(10, 550)
					$padding.Size = '1,20'
					$padding.BorderStyle = 'None'
					$padding.Readonly = $True
					$padding.Text = ''
					
					# Action Status Bar							
					$statusbar = New-Object System.Windows.Forms.StatusBar
					$statusbarpanel = New-Object System.Windows.Forms.StatusBarPanel
					$statusbarpanel.width = 600
					$statusbar.text = ''
					$statusbar.showpanels = $true
					$statusbar.Panels.Add($statusbarpanel) | Out-Null
					
					$button_confirm_action = {
						foreach ($obj in $Checkboxes)
						{
							if ($obj.checked -eq $true)
							{
								$ioc = $obj.IOC
								$iocline = $obj.OrigLine
								$ioctype = $obj.Type
								$ioclist = $obj.IndicatorList
								$iocfeed = $obj.FeedList
								if ($iocline.Contains(','))
								{
									Remove-MMIndicator -Server $server -Indicator $iocline -Type $ioctype -IndicatorList $ioclist -BypassSSL
								}
								else
								{
									Remove-MMIndicator -Server $server -Indicator $ioc -Type $ioctype -IndicatorList $ioclist -BypassSSL
								}
							}
						}
						$statusbarpanel.text = "Records deleted.."
						Start-Sleep -Seconds 2.5
						$statusbarpanel.text = ""
						$form.Close()
						
					}
					
					$copyButton_action = {
						[System.Windows.Forms.Clipboard]::Clear()
						foreach ($obj in $Checkboxes)
						{
							if ($obj.checked -eq $true)
							{
								$ioc = $obj.IOC
								$ioctype = $obj.Type
								$ioclist = $obj.IndicatorList
								$iocfeed = $obj.FeedList
								$ioc = $ioc -replace ",.*"
								Set-Clipboard -Append $ioc
							}
						}
						$statusbarpanel.text = "Copied to clipboard.."
						Start-Sleep -Seconds 2.5
						$statusbarpanel.text = ""
					}
					
					# Create the Next button.
					$button_confirm = New-Object System.Windows.Forms.Button
					$button_confirm.Location = New-Object System.Drawing.Size(270, 500)
					$button_confirm.Size = '175,25'
					$button_confirm.Text = "Delete Selected"
					$button_confirm.Add_Click($button_confirm_action)
					
					# Create the Copy button.
					$copyButton = New-Object System.Windows.Forms.Button
					$copyButton.Location = New-Object System.Drawing.Size(90, 500)
					$copyButton.Size = '175,25'
					$copyButton.Text = "Copy to Clipboard"
					$copyButton.Add_Click($copyButton_action)
					
					# Create the Cancel button.
					$button_cancel = New-Object System.Windows.Forms.Button
					$button_cancel.Location = New-Object System.Drawing.Size(10, 500)
					$button_cancel.Size = '75,25'
					$button_cancel.Text = "Close"
					$button_cancel.Add_Click({ $form.Close() })
					
					$panel_searchresults = New-Object System.Windows.Forms.Panel
					$panel_searchresults.Controls.Add($groupBox)
					$panel_searchresults.BackColor = "Window"
					$panel_searchresults.Location = New-Object System.Drawing.Point(10, 10)
					$panel_searchresults.AutoSize = $true
					$panel_searchresults.MaximumSize = '0,475'
					$panel_searchresults.TabIndex = 0
					$panel_searchresults.AutoScroll = $true
					
					# Add all of the controls to the form.
					$form.Controls.Add($panel_searchresults)
					$form.Controls.Add($padding)
					$form.Controls.Add($statusbar)
					$form.Controls.Add($copyButton)
					$form.Controls.Add($button_confirm)
					$form.Controls.Add($button_cancel)
					
					# Assign the Accept and Cancel options in the form to the corresponding buttons
					$form.AcceptButton = $button_confirm
					$form.CancelButton = $button_cancel
					
					# Initialize and show the form.
					$form.Add_Shown({ $form.Activate() })
					
					# Get the results from the button click
					$global:dialogResult = $form.ShowDialog()
					
					$global:queryloopcomplete = $false
				}
				
				if ($global:somethingfound -ne $true)
				{
					Write-Host ""
					Write-Host -ForegroundColor Red "   Search could not find $global:var_searchquery"
					Write-Host ""
				}
				
				while ($global:BackButtonAction -eq $true)
				{
					if ($global:abortdialog -ne $true)
					{
						& Search-Query
						$global:BackButtonAction = $false
						if ($global:abortdialog -ne $true)
						{
							if ($global:var_prop_value -eq "query")
							{
								& Search-QueryResult
								$global:BackButtonAction = $false
							}
						}
					}
				}
			}
			& Search-QueryResult
		}
		catch
		{
			Clear-Host
			Write-Host -ForegroundColor Red $_.Exception.Message
			Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
			pause
		}
	}
	end
	{
	}
}

function Prepare-TCIncident
{
	
	# Prompt for Incident Name
	if ($global:abortdialog -ne $true)
	{
		function Get-IncidentName
		{
			$global:var_prop_value = "incident"
			if (($global:var_incidentname = Read-SingleLineInputBoxDialog -Message "Enter a TC Incident Name:" -WindowTitle "PowerMM - TC Incident" -HelpText "Give the incident a name in 100 characters or less.`n`r`n`rThis name will be how the incident is shown on the ThreatConnect platform." -DefaultText $global:var_incidentname -Required $true -CheckboxID "1") -eq "")
			{
			}
			foreach ($value in $mask_sensitivevalues)
			{
				$global:var_incidentname = $global:var_incidentname -replace $value, "*******"
			}
		}
		& Get-IncidentName
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for the Evilness Rating
	if ($global:abortdialog -ne $true)
	{
		function Get-EvilnessRating
		{
			$global:var_prop_value = "evilness"
			if ($global:var_evilness -eq "" -or $global:var_evilness -eq $null)
			{
				$global:var_evilness = "4"
			}
			if (($global:var_evilness = Read-SingleLineInputBoxDialog -Message "Enter a TC Evilness Rating:" -WindowTitle "PowerMM - TC Evilness" -HelpText "Evilness rating options are (0 - 5):`n`r
0=Unknown | 1=Suspicious | 2=Unsophisticated | 3=Basic Skills | `n`r4=Advanced Skills | 5=Unlimited Skills/Resources`n`r`n`rThe default value is 4." -DefaultText $global:var_evilness -CheckboxID "2") -eq "")
			{
			}
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-IncidentName
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "incident")
						{
							& Get-EvilnessRating
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		& Get-EvilnessRating
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for the Confidence Rating
	if ($global:abortdialog -ne $true)
	{
		function Get-ConfidenceRating
		{
			$global:var_prop_value = "confidence"
			if ($global:var_confidence -eq "" -or $global:var_confidence -eq $null)
			{
				$global:var_confidence = "100"
			}
			if (($global:var_confidence = Read-SingleLineInputBoxDialog -Message "Enter a TC Confidence Rating:" -WindowTitle "PowerMM - TC Confidence" -HelpText "Confidence rating options are (0 - 100):`n`r                                                    
0=Unknown | 1=Discredited | <30=Improbable | 31->49=Doubtful | `n`r50->69=Possible | 70->89=Probable | 90->100=Confirmed`n`r`n`rThe default value is 100." -DefaultText $global:var_confidence -CheckboxID "3") -eq "")
			{
			}
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-EvilnessRating
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "evilness")
						{
							& Get-ConfidenceRating
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		& Get-ConfidenceRating
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for a TLP Level
	if ($global:abortdialog -ne $true)
	{
		function Get-TLPLevel
		{
			$global:var_prop_value = "TLP"
			if ($global:var_tlplabel -eq "" -or $global:var_tlplabel -eq $null)
			{
				$global:var_tlplabel = "TLP-Amber"
			}
			if (($global:var_tlplabel = Read-SingleLineInputBoxDialog -Message "Enter a TC TLP Level:" -WindowTitle "PowerMM - TC TLP Level" -HelpText "TLP Level options are (TLP-White, TLP-Green, TLP-Amber, TLP-Red):`n`r`n`rThe default value is TLP-Amber." -DefaultText $global:var_tlplabel -CheckboxID "4") -eq "")
			{
			}
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-TLPLevel
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "TLP")
						{
							& Get-TLPLevel
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		& Get-TLPLevel
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for an Incident Description
	if ($global:abortdialog -ne $true)
	{
		function Get-Description
		{
			$global:var_prop_value = "description"
			$global:var_description = $null
			if (($global:var_description = Read-MultiLineInputBoxDialog -Message "Enter a TC Incident Description:" -WindowTitle "PowerMM - TC Description" -HelpText "Give a description of the incident." -DefaultText $global:var_incidentname -Required $true -CheckboxID "5") -eq "")
			{
				$global:var_description = $global:var_description -replace "#.*"
			}
			foreach ($value in $mask_sensitivevalues)
			{
				$global:var_description = $global:var_description -replace $value, "*******"
			}
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-ConfidenceRating
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "confidence")
						{
							& Get-Description
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		& Get-Description
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for Tags
	if ($global:abortdialog -ne $true)
	{
		function Get-Tags
		{
			$global:var_prop_value = "tags"
			$global:BackButtonState = $true
			$global:var_tags = $var_industrysector
			if ($global:var_description -like "*phish*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Phishing")
			}
			if ($global:var_description -like "*malware*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Malware")
			}
			if ($global:var_description -like "*trojan*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Trojan")
			}
			if ($global:var_description -like "*scan*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Scanner")
			}
			if ($global:var_description -like "*ransom*" -or $global:var_description -like "*emotet*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Ransomware")
			}
			if ($global:var_description -like "*bitcoin*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Bitcoin")
			}
			if ($global:var_description -like "*dropbox*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Dropbox")
			}
			if ($global:var_description -like "*efax*")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "Efax")
			}
			if ($global:var_description -like "*bec *")
			{
				$global:var_tags = ($global:var_tags + "`n`r`n`r" + "BEC")
			}
			if (($global:var_tags = Read-MultiLineInputBoxDialog -Message "Enter TC tags (keywords), each on their own line:" -WindowTitle "PowerMM - TC Tags/Keywords" -HelpText "Assign tags (keywords) to the incident to assist other ThreatConnect platform users in locating or reporting on similar incidents and indicators.`n`r`n`rIt is important to include your industry sector as a tag so others know what sector observed a threat." -DefaultText $global:var_tags -Required $true -CheckboxID "6") -eq "")
			{
			}
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-Description
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "description")
						{
							& Get-Tags
							$global:BackButtonAction = $false
						}
					}
				}
			}
			if ($global:var_tags -eq $null -or $global:var_tags -eq "")
			{
			}
			else
			{
				Write-Output $null > $cachefile_tags
				foreach ($tag in $global:var_tags)
				{
					Write-Output $tag >> $cachefile_tags
				}
			}
		}
		& Get-Tags
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
}

function New-TCIncident
{
	<#
	.SYNOPSIS
		Creates a new incident in Threat Connect.

	.PARAMETER Name
		Name of the incident to create.

	.PARAMETER EventDate
		The date the Incident occurred. The code attempts to convert the provided date to the format required by the API, but uses the computer's time zone from which the script is being run.
		
	.EXAMPLE
		New-TCIncident -Name <IncidentName> -EventDate "2015-01-01T14:00:00-06:00"
		
	.EXAMPLE
		New-TCIncident -Name <IncidentName> -EventDate (Get-Date -Date "10/01/2014 15:00:03" -Format "yyyy-MM-ddThh:mm:sszzzz")

	.EXAMPLE
		New-TCIncident -Name <IncidentName> -EventDate "10/01/2014 15:00:03"
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$EventDate
	)
	$EventDate = Get-Date -Date $EventDate -Format "yyyy-MM-ddThh:mm:sszzzz" -ErrorAction Stop
	
	# Create a Custom Object and add the provided Name and Value variables to the object
	$CustomObject = "" | Select-Object -Property name, eventDate
	$CustomObject.name = $Name
	$CustomObject.eventDate = $EventDate
	
	# Convert the Custom Object to JSON format for use with the API
	$JSONData = $CustomObject | ConvertTo-Json -Compress
	
	# Child URL for Incident Creation
	$APIChildURL = ("/v2/groups/incidents?owner=" + $var_community)
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod 'POST' -URL $APIChildURL
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = New-Object System.Uri ($Script:APIBaseURL + $APIChildURL)
	
	# Manage API query speed
	Start-Sleep -Seconds $throttle
	
	try
	{
		$powershellRepresentation = ConvertFrom-Json $JSONData -ErrorAction Stop;
		$validJson = $true;
	}
	catch
	{
		$validJson = $false;
	}
	
	if ($validJson)
	{

	}
	else
	{
		Clear-Host
		Write-Host -ForegroundColor Red "IOC package is not valid JSON";
		Write-Output "IOC package is not valid JSON" >> $global:logfile
		pause
	}
	
	# Query the API
	$Response = Invoke-RestMethod -Method 'Post' -Uri $URI -Headers $AuthorizationHeaders -Body $JSONData -UserAgent '' -ContentType 'application/json; charset=utf-8' -ErrorAction SilentlyContinue
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }
		$global:IncidentID = $Response.data.incident.id
		Write-Host -ForegroundColor Green "Incident submitted successfully.."
		Write-Host ""
	}
	else
	{
		Write-Host -ForegroundColor Red "API New Incident Request failed with the following error:`n $($Response.Status)"
		Write-Host -ForegroundColor Red $_.ErrorDetails
		Write-Host ""
		if ($Response -ne $null)
		{
			$Statuscode = $Response.StatusCode
		}
		else
		{
			$Statuscode = "No Status Code"
		}
		if ($Response -ne $null)
		{
			$ErrorDetail = $Response.ErrorDetails
		}
		else
		{
			$ErrorDetail = "No Error Detail"
		}
		Write-Output ($Statuscode + " " + $URI + " " + $ErrorDetail) >> $global:logfile
	}
}

function Get-TCIncident
{
	<#
	.SYNOPSIS
		Gets a list of incidents from Threat Connect.  Default is all incidents for the API Key's organization

	.PARAMETER AdversaryID
		Optional parameter used to list all incidents linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all incidents linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to specify an Incident ID for which to query.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all incidents with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all incidents linked to a specific Signature ID.

	.PARAMETER TagName
		Optional parameter used to list all incidents with a specific Tag.

	.PARAMETER ThreatID
		Optional parameter used to list all incidents linked to a specific Threat ID.

	.PARAMETER VictimID
		Optional parameter used to list all incidents linked to a specific Victim ID.
		
	.PARAMETER IndicatorType
		Optional paramter used to list all incidents linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all incidents linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve incidents.
		This switch can be used alongside some of the other switches.

	.PARAMETER ResultStart
		Optional Parameter. Use when dealing with large number of results.
		if you use ResultLimit of 100, you can use a ResultStart value of 100 to show items 100 through 200.

	.PARAMETER ResultLimit
		Optional Parameter. Change the maximum number of results to display. Default is 100, Maximum is 500.

	.EXAMPLE
		Get-TCIncident
		
	.EXAMPLE
		Get-TCIncident -AdversaryID <AdversaryID>
		
	.EXAMPLE
		Get-TCIncident -EmailID <EmailID>
		
	.EXAMPLE
		Get-TCIncident -IncidentID <IncidentID>

	.EXAMPLE
		Get-TCIncident -SecurityLabel <SecurityLabel>
		
	.EXAMPLE
		Get-TCIncident -SignatureID <SignatureID>
		
	.EXAMPLE
		Get-TCIncident -TagName <TagName>
		
	.EXAMPLE
		Get-TCIncident -ThreatID <ThreatID>
		
	.EXAMPLE
		Get-TCIncident -VictimID <VictimID>
		
	.EXAMPLE
		Get-TCIncident -IndicatorType Address -Indicator <Indicator>

	.EXAMPLE
		Get-TCIncident -IndicatorType EmailAddress -Indicator <Indicator>

	.EXAMPLE
		Get-TCIncident -IndicatorType File -Indicator <Indicator>

	.EXAMPLE
		Get-TCIncident -IndicatorType Host -Indicator <Indicator>

	.EXAMPLE
		Get-TCIncident -IndicatorType URL -Indicator <Indicator>
	#>
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param (
		[Parameter(Mandatory = $True, ParameterSetName = 'AdversaryID')]
		[ValidateNotNullOrEmpty()]
		[String]$AdversaryID,
		[Parameter(Mandatory = $True, ParameterSetName = 'EmailID')]
		[ValidateNotNullOrEmpty()]
		[String]$EmailID,
		[Parameter(Mandatory = $True, ParameterSetName = 'IncidentID')]
		[ValidateNotNullOrEmpty()]
		[String]$IncidentID,
		[Parameter(Mandatory = $True, ParameterSetName = 'Indicator')]
		[ValidateSet('Address', 'EmailAddress', 'File', 'Host', 'URL')]
		[String]$IndicatorType,
		[Parameter(Mandatory = $True, ParameterSetName = 'Indicator')]
		[ValidateNotNullOrEmpty()]
		[String]$Indicator,
		[Parameter(Mandatory = $True, ParameterSetName = 'SecurityLabel')]
		[ValidateNotNullOrEmpty()]
		[String]$SecurityLabel,
		[Parameter(Mandatory = $True, ParameterSetName = 'SignatureID')]
		[ValidateNotNullOrEmpty()]
		[String]$SignatureID,
		[Parameter(Mandatory = $True, ParameterSetName = 'TagName')]
		[ValidateNotNullOrEmpty()]
		[String]$TagName,
		[Parameter(Mandatory = $True, ParameterSetName = 'ThreatID')]
		[ValidateNotNullOrEmpty()]
		[String]$ThreatID,
		[Parameter(Mandatory = $True, ParameterSetName = 'VictimID')]
		[ValidateNotNullOrEmpty()]
		[String]$VictimID,
		[Parameter(Mandatory = $False, ParameterSetName = 'Default')]
		[Parameter(Mandatory = $False, ParameterSetName = 'Indicator')]
		[Parameter(Mandatory = $False, ParameterSetName = 'SecurityLabel')]
		[Parameter(Mandatory = $False, ParameterSetName = 'TagName')]
		[ValidateNotNullOrEmpty()]
		[String]$Owner,
		[Parameter(Mandatory = $False, ParameterSetName = 'Default')]
		[Parameter(Mandatory = $False, ParameterSetName = 'Indicator')]
		[Parameter(Mandatory = $False, ParameterSetName = 'AdversaryID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'EmailID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'SecurityLabel')]
		[Parameter(Mandatory = $False, ParameterSetName = 'SignatureID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'TagName')]
		[Parameter(Mandatory = $False, ParameterSetName = 'ThreatID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'VictimID')]
		[ValidateRange('1', '500')]
		[int]$ResultLimit = 100,
		[Parameter(Mandatory = $False, ParameterSetName = 'Default')]
		[Parameter(Mandatory = $False, ParameterSetName = 'Indicator')]
		[Parameter(Mandatory = $False, ParameterSetName = 'AdversaryID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'EmailID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'SecurityLabel')]
		[Parameter(Mandatory = $False, ParameterSetName = 'SignatureID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'TagName')]
		[Parameter(Mandatory = $False, ParameterSetName = 'ThreatID')]
		[Parameter(Mandatory = $False, ParameterSetName = 'VictimID')]
		[ValidateNotNullOrEmpty()]
		[int]$ResultStart
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName)
	{
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/incidents"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/incidents"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID
		}
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType)
			{
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups/incidents"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups/incidents"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups/incidents"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups/incidents"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups/incidents"
				}
			}
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/incidents"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups/incidents"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/incidents"
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/groups/incidents"
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups/incidents"
		}
		
		Default
		{
			# Use this if nothing else is specified
			$APIChildURL = "/v2/groups/incidents"
		}
	}
	
	# Add to the URI if Owner, ResultStart, or ResultLimit was specified
	if ($Owner -and $ResultStart -and $ResultLimit -ne 100)
	{
		$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner) + "&resultStart=" + $ResultStart + "&resultLimit=" + $ResultLimit
	}
	elseif ($Owner -and $ResultStart -and $ResultLimit -eq 100)
	{
		$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner) + "&resultStart=" + $ResultStart
	}
	elseif ($Owner -and (-not $ResultStart) -and $ResultLimit -ne 100)
	{
		$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner) + "&resultLimit=" + $ResultLimit
	}
	elseif ($Owner -and (-not $ResultStart) -and $ResultLimit -eq 100)
	{
		$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner)
	}
	elseif ((-not $Owner) -and $ResultStart -and $ResultLimit -ne 100)
	{
		$APIChildURL = $APIChildURL + "?resultStart=" + $ResultStart + "&resultLimit=" + $ResultLimit
	}
	elseif ((-not $Owner) -and $ResultStart -and $ResultLimit -eq 100)
	{
		$APIChildURL = $APIChildURL + "?resultStart=" + $ResultStart
	}
	elseif ((-not $Owner) -and (-not $ResultStart) -and $ResultLimit -ne 100)
	{
		$APIChildURL = $APIChildURL + "?resultLimit=" + $ResultLimit
	}
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod "GET" -URL $APIChildURL
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = New-Object System.Uri ($Script:APIBaseURL + $APIChildURL)
	
	if ($IndicatorType -eq "URL" -and $Indicator) { [URLFix]::ForceCanonicalPathAndQuery($URI) }
	
	# Query the API
	Try
	{
		$Response = Invoke-WebRequest -Method 'GET' -Uri $URI -Headers $AuthorizationHeaders -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
	}
	catch
	{
		Clear-Host
		Write-Host -ForegroundColor Red $_.Exception.Message
		Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
		pause
	}
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }
	}
	else
	{
	}
}

function New-TCIndicator
{
	<#
	.SYNOPSIS
		Creates a new indicator in Threat Connect.

	.PARAMETER Host
		Host or domain name indicator to create.
		
	.PARAMETER URL
		URL indicator to create.
		
	.PARAMETER EmailAddress
		Email address indicator to create.

	.PARAMETER Address
		IP address indicator to create.
		
	.PARAMETER FileMD5, FileSHA1,FileSHA256
		File hash indicator to create.
		
	.EXAMPLE
		New-TCIndicator -Host malicious.badomain.com -Confidence "100" -Rating "4.0" -WhoisActive "true" -DnsActive "true"
		
	.EXAMPLE
		New-TCIndicator -URL http://malicious.badomain.com/baduri
		
	.EXAMPLE
		New-TCIndicator -EmailAddress hacker@badomain.com
		
	.EXAMPLE
		New-TCIndicator -Address 1.1.1.1
		
	.EXAMPLE (Creates a single file indicator containing an MD5 and a SHA1 hash for the same file)
		New-TCIndicator -FileMD5 "3ffade21da0dda18de71249c46164626" -FileSHA1 "d7bc2be9e80c5c8a9901034a8cc000f6ea8d9d00"
		
		#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, ParameterSetName = 'Hostname')]
		[ValidateNotNullOrEmpty()]
		[String]$Hostname,
		[Parameter(Mandatory = $True, ParameterSetName = 'URL')]
		[ValidateNotNullOrEmpty()]
		[String]$URL,
		[Parameter(Mandatory = $True, ParameterSetName = 'EmailAddress')]
		[ValidateNotNullOrEmpty()]
		[String]$EmailAddress,
		[Parameter(Mandatory = $True, ParameterSetName = 'Address')]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[Parameter(Mandatory = $False, ParameterSetName = 'FileMD5')]
		[ValidateNotNullOrEmpty()]
		[String]$FileMD5,
		[Parameter(Mandatory = $False, ParameterSetName = 'FileSHA1')]
		[ValidateNotNullOrEmpty()]
		[String]$FileSHA1,
		[Parameter(Mandatory = $False, ParameterSetName = 'FileSHA256')]
		[ValidateNotNullOrEmpty()]
		[String]$FileSHA256,
		[Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$whoisActive,
		[Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$dnsActive,
		[Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$rating,
		[Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$confidence
	)
	
	# Switch to construct Child URL based on the parameters that were provided
	switch ($PSCmdlet.ParameterSetName)
	{
		"Hostname" {
			$CustomObject = "" | Select-Object -Property hostName, whoisActive, dnsActive, rating, confidence
			$CustomObject.hostName = $Hostname.ToLower()
			$CustomObject.whoisActive = $WhoisActive
			$CustomObject.dnsActive = $DnsActive
			$CustomObject.rating = $rating
			$CustomObject.confidence = $confidence
			$APIChildURL = ("/v2/indicators/hosts?owner=" + $var_community)
		}
		"URL" {
			$CustomObject = "" | Select-Object -Property text, rating, confidence
			$CustomObject.text = $URL.ToLower()
			$CustomObject.rating = $Rating
			$CustomObject.confidence = $Confidence
			$APIChildURL = ("/v2/indicators/urls?owner=" + $var_community)
		}
		"EmailAddress" {
			$CustomObject = "" | Select-Object -Property address, rating, confidence
			$CustomObject.address = $EmailAddress.ToLower()
			$CustomObject.rating = $Rating
			$CustomObject.confidence = $Confidence
			$APIChildURL = ("/v2/indicators/emailAddresses?owner=" + $var_community)
		}
		"Address" {
			$CustomObject = "" | Select-Object -Property ip, rating, confidence
			$CustomObject.ip = $Address
			$CustomObject.rating = $Rating
			$CustomObject.confidence = $Confidence
			$APIChildURL = ("/v2/indicators/addresses?owner=" + $var_community)
		}
		"FileMD5" {
			$CustomObject = "" | Select-Object -Property md5, rating, confidence
			$CustomObject.md5 = $FileMD5.ToUpper()
			$CustomObject.rating = $Rating
			$CustomObject.confidence = $Confidence
			$APIChildURL = ("/v2/indicators/files?owner=" + $var_community)
		}
		
		"FileSHA1" {
			$CustomObject = "" | Select-Object -Property sha1, rating, confidence
			$CustomObject.sha1 = $FileSHA1.ToUpper()
			$CustomObject.rating = $Rating
			$CustomObject.confidence = $Confidence
			$APIChildURL = ("/v2/indicators/files?owner=" + $var_community)
		}
		
		"FileSHA256" {
			$CustomObject = "" | Select-Object -Property sha256, rating, confidence
			$CustomObject.sha256 = $FileSHA256.ToUpper()
			$CustomObject.rating = $Rating
			$CustomObject.confidence = $Confidence
			$APIChildURL = ("/v2/indicators/files?owner=" + $var_community)
		}
	}
	
	# Convert the Custom Object to JSON format for use with the API
	$JSONData = $CustomObject | ConvertTo-Json -Compress
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = New-Object System.Uri ($APIBaseURL + $APIChildURL)
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod 'POST' -URL $URI.PathAndQuery
	
	# Manage API query speed
	Start-Sleep -Seconds $throttle
	
	# Query the API
	$Response = Invoke-RestMethod -Method 'Post' -Uri $URI -Headers $AuthorizationHeaders -UserAgent '' -ContentType 'application/json; charset=utf-8' -Body $JSONData -ErrorAction SilentlyContinue
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		Write-Host -ForegroundColor Green "Indicator submitted successfully.."
		$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }
		
		if ($Hostname -ne $null -and $Hostname -ne "")
		{
			$global:IndicatorID = $Response.data.host.id
		}
		if ($URL -ne $null -and $URL -ne "")
		{
			$global:IndicatorID = $Response.data.url.text
		}
		if ($EmailAddress -ne $null -and $EmailAddress -ne "")
		{
			$global:IndicatorID = $Response.data.emailaddress.id
		}
		if ($Address -ne $null -and $Address -ne "")
		{
			$global:IndicatorID = $Response.data.id
		}
		if ($FileMD5 -ne $null -and $FileMD5 -ne "")
		{
			$global:IndicatorID = $Response.data.file.id
		}
		if ($FileSHA1 -ne $null -and $FileSHA1 -ne "")
		{
			$global:IndicatorID = $Response.data.file.id
		}
		if ($FileSHA256 -ne $null -and $FileSHA256 -ne "")
		{
			$global:IndicatorID = $Response.data.file.id
		}
	}
	else
	{
		Write-Host -ForegroundColor Red "API New Indicator Request failed with the following error:`n $($Response.Status)"
		Write-Host -ForegroundColor Red $_.ErrorDetails
		Write-Host ""
		if ($Response -ne $null)
		{
			$Statuscode = $Response.StatusCode
		}
		else
		{
			$Statuscode = "No Status Code"
		}
		if ($Response -ne $null)
		{
			$ErrorDetail = $Response.ErrorDetails
		}
		else
		{
			$ErrorDetail = "No Error Detail"
		}
		Write-Output ($Statuscode + " " + $URI + " " + $ErrorDetail) >> $global:logfile
	}
}

function New-TCAssociation
{
	<#
	.SYNOPSIS
		Associates indicators with incidents in Threat Connect.

	.PARAMETER IncidentID
		Incident ID to associate.

	.PARAMETER Host
		Host or domain name indicator to associate.
		
	.PARAMETER URL
		URL indicator to associate.
		
	.PARAMETER EmailAddress
		Email address indicator to associate.

	.PARAMETER Address
		IP address indicator to associate.
		
	.PARAMETER File(MD5,SHA1,SHA256)
		File hash indicator to associate.
		
	.EXAMPLE
		New-TCAssociation -IncidentID 127843 -URL http://malicious.badomain.com
		
		#>
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, ParameterSetName = 'Host')]
		[ValidateNotNullOrEmpty()]
		[String]$HostInd,
		[Parameter(Mandatory = $True, ParameterSetName = 'URL')]
		[ValidateNotNullOrEmpty()]
		[String]$URLInd,
		[Parameter(Mandatory = $True, ParameterSetName = 'EmailAddress')]
		[ValidateNotNullOrEmpty()]
		[String]$EmailAddressInd,
		[Parameter(Mandatory = $True, ParameterSetName = 'Address')]
		[ValidateNotNullOrEmpty()]
		[String]$AddressInd,
		[Parameter(Mandatory = $True, ParameterSetName = 'FileMD5')]
		[ValidateNotNullOrEmpty()]
		[String]$FileMD5Ind,
		[Parameter(Mandatory = $True, ParameterSetName = 'FileSHA1')]
		[ValidateNotNullOrEmpty()]
		[String]$FileSHA1Ind,
		[Parameter(Mandatory = $True, ParameterSetName = 'FileSHA256')]
		[ValidateNotNullOrEmpty()]
		[String]$FileSHA256Ind
	)
	
	# Switch to construct Child URL based on the parameters that were provided
	switch ($PSCmdlet.ParameterSetName)
	{
		"Host" {
			$HostInd = Get-EscapedURIString -String $HostInd
			$HostInd = $HostInd.ToLower()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/hosts/" + $HostInd)
		}
		
		"URL" {
			$URLInd = Get-EscapedURIString -String $URLInd
			$URLInd = $URLInd.ToLower()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/urls/" + $URLInd)
		}
		
		"EmailAddress" {
			$EmailAddressInd = Get-EscapedURIString -String $EmailAddressInd
			$EmailAddressInd = $EmailAddressInd.ToLower()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/emailAddresses/" + $EmailAddressInd)
		}
		
		"Address" {
			$AddressInd = $AddressInd.ToLower()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/addresses/" + $AddressInd)
		}
		
		"FileMD5" {
			$FileMD5Ind = Get-EscapedURIString -String $FileMD5Ind
			$FileMD5Ind = $FileMD5Ind.ToUpper()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/files/" + $FileMD5Ind)
		}
		
		"FileSHA1" {
			$FileSHA1Ind = Get-EscapedURIString -String $FileSHA1Ind
			$FileSHA1Ind = $FileSHA1Ind.ToUpper()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/files/" + $FileSHA1Ind)
		}
		
		"FileSHA256" {
			$FileSHA256Ind = Get-EscapedURIString -String $FileSHA256Ind
			$FileSHA256Ind = $FileSHA256Ind.ToUpper()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/indicators/files/" + $FileSHA256Ind)
		}
	}
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = ($APIBaseURL + $APIChildURL)
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod 'POST' -URL $APIChildURL
	
	# Manage API query speed
	Start-Sleep -Seconds $throttle
	
	# Fix the "/" URL-escaping default behavior in .NET so URL's can correctly be posted.
	UrlFix $URI
	
	# Query the API
	$Response = Invoke-RestMethod -Method 'Post' -Uri $URI -Headers $AuthorizationHeaders -UserAgent '' -ContentType 'application/json; charset=utf-8'
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		Write-Host -ForegroundColor Green "Association submitted successfully.."
		Write-Host ""
	}
	else
	{
		Write-Host -ForegroundColor Red "Incident association request failed for $ioc"
		Write-Host ""
		if ($Response -ne $null)
		{
			$Statuscode = $Response.StatusCode
		}
		else
		{
			$Statuscode = "No Status Code"
		}
		if ($Response -ne $null)
		{
			$ErrorDetail = $Response.ErrorDetails
		}
		else
		{
			$ErrorDetail = "No Error Detail"
		}
		Write-Output ($Statuscode + " " + $URI + " " + $ErrorDetail) >> $global:logfile
	}
}

function New-TCAttribute
{
	<#
	.SYNOPSIS
		Creates a new attribute in Threat Connect.

	.DESCRIPTION
		Must supply a specific "group" for which to add an attribute (Adversary, Email, Incident, Threat, Signature).

	.PARAMETER Name
		Name of the Attribute to add

	.PARAMETER Value
		Value of the Attribute to add

	.PARAMETER AdversaryID
		Adversary ID of the Adversary for which you want to create an attribute

	.PARAMETER EmailID
		Email ID of the Email for which you want to create an attribute

	.PARAMETER IncidentID
		Incident ID of the Incident for which you want to create an attribute

	.PARAMETER ThreatID
		Threat ID of the Threat for which you want to create an attribute

	.PARAMETER SignatureID
		Signature ID of the Signature for which you want to create an attribute
		
	.EXAMPLE
		New-TCAttribute -AdversaryID <AdversaryID> -Name Description -Value "Testing Description Creation"
			
	.EXAMPLE
		New-TCAttribute -EmailID <EmailID> -Name Description -Value "Testing Description Creation"
			
	.EXAMPLE
		New-TCAttribute -IncidentID <IncidentID> -Name Description -Value "Testing Description Creation"
			
	.EXAMPLE
		New-TCAttribute -ThreatID <ThreatID> -Name Description -Value "Testing Description Creation"
			
	.EXAMPLE
		New-TCAttribute -SignatureID <SignatureID> -Name Description -Value "Testing Description Creation"


	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, ParameterSetName = 'AdversaryID')]
		[ValidateNotNullOrEmpty()]
		[int]$AdversaryID,
		[Parameter(Mandatory = $True, ParameterSetName = 'EmailID')]
		[ValidateNotNullOrEmpty()]
		[int]$EmailID,
		[Parameter(Mandatory = $True, ParameterSetName = 'IncidentID')]
		[ValidateNotNullOrEmpty()]
		[int]$IncidentID,
		[Parameter(Mandatory = $True, ParameterSetName = 'ThreatID')]
		[ValidateNotNullOrEmpty()]
		[int]$ThreatID,
		[Parameter(Mandatory = $True, ParameterSetName = 'SignatureID')]
		[ValidateNotNullOrEmpty()]
		[int]$SignatureID,
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$Value,
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$Displayed
	)
	
	# Create a Custom Object and add the provided Name and Value variables to the object
	$CustomObject = "" | Select-Object -Property type, value, displayed
	$CustomObject.type = $Name
	$CustomObject.value = $Value
	$CustomObject.displayed = $Displayed
	
	# Convert the Custom Object to JSON format for use with the API
	$JSONData = $CustomObject | ConvertTo-Json -Compress
	
	# Switch to construct Child URL based on the parameters that were provided
	switch ($PSCmdlet.ParameterSetName)
	{
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries" + "/" + $AdversaryID + "/attributes"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails" + "/" + $EmailID + "/attributes"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents" + "/" + $IncidentID + "/attributes"
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats" + "/" + $ThreatID + "/attributes"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures" + "/" + $SignatureID + "/attributes"
		}
	}
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = New-Object System.Uri ($APIBaseURL + $APIChildURL)
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod 'POST' -URL $URI.PathAndQuery
	
	# Manage API query speed
	Start-Sleep -Seconds $throttle
	
	# Query the API
	$Response = Invoke-RestMethod -Method 'Post' -Uri $URI -Headers $AuthorizationHeaders -UserAgent '' -ContentType 'application/json; charset=utf-8' -Body $JSONData
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }
		Write-Host -ForegroundColor Green "Attribute submitted successfully.."
		Write-Host ""
	}
	else
	{
		Write-Host -ForegroundColor Red "API New Attribute Request failed with the following error:`n $($Response.Status)"
		Write-Host -ForegroundColor Red $_.ErrorDetails
		Write-Host ""
		if ($Response -ne $null)
		{
			$Statuscode = $Response.StatusCode
		}
		else
		{
			$Statuscode = "No Status Code"
		}
		if ($Response -ne $null)
		{
			$ErrorDetail = $Response.ErrorDetails
		}
		else
		{
			$ErrorDetail = "No Error Detail"
		}
		Write-Output ($Statuscode + " " + $URI + " " + $ErrorDetail) >> $global:logfile
	}
}

function New-TCTag
{
	<#
	.SYNOPSIS
		Creates a new tag in Threat Connect.

	.PARAMETER Tag
		Tag name to create.

	.EXAMPLE
		New-TCTag -Tag "phishing"
		
		#>
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $False, ParameterSetName = 'Hostname')]
		[ValidateNotNullOrEmpty()]
		[String]$Hostname,
		[Parameter(Mandatory = $False, ParameterSetName = 'URL')]
		[ValidateNotNullOrEmpty()]
		[String]$URL,
		[Parameter(Mandatory = $False, ParameterSetName = 'EmailAddress')]
		[ValidateNotNullOrEmpty()]
		[String]$EmailAddress,
		[Parameter(Mandatory = $False, ParameterSetName = 'Address')]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[Parameter(Mandatory = $False, ParameterSetName = 'File')]
		[ValidateNotNullOrEmpty()]
		[String]$File,
		[Parameter(Mandatory = $False, ParameterSetName = 'IncidentID')]
		[ValidateNotNullOrEmpty()]
		[String]$IncidentID,
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$Tag
	)
	
	# Switch to construct Child URL based on the parameters that were provided
	switch ($PSCmdlet.ParameterSetName)
	{
		
		"Hostname" {
			$Tag = Get-EscapedURIString -String $Tag
			$Tag = $Tag.ToLower()
			$Hostname = Get-EscapedURIString -String $Hostname
			$Hostname = $Hostname.ToLower()
			$APIChildURL = ("/v2/indicators/hosts/" + $Hostname + "/tags/" + $Tag + "?owner=" + $var_community)
		}
		"URL" {
			$Tag = Get-EscapedURIString -String $Tag
			$Tag = $Tag.ToLower()
			$URL = Get-EscapedURIString -String $URL
			$URL = $URL.ToLower()
			$APIChildURL = ("/v2/indicators/urls/" + $URL + "/tags/" + $Tag + "?owner=" + $var_community)
		}
		"EmailAddress" {
			$Tag = Get-EscapedURIString -String $Tag
			$Tag = $Tag.ToLower()
			#$EmailAddress = Get-EscapedURIString -String $EmailAddress
			$EmailAddress = $EmailAddress.ToLower()
			$APIChildURL = ("/v2/indicators/emailAddresses/" + $EmailAddress + "/tags/" + $Tag + "?owner=" + $var_community)
		}
		"Address" {
			$Tag = Get-EscapedURIString -String $Tag
			$Tag = $Tag.ToLower()
			$APIChildURL = ("/v2/indicators/addresses/" + $Address + "/tags/" + $Tag + "?owner=" + $var_community)
		}
		"File" {
			$Tag = Get-EscapedURIString -String $Tag
			$Tag = $Tag.ToLower()
			$File = Get-EscapedURIString -String $File
			$File = $File.ToUpper()
			$APIChildURL = ("/v2/indicators/files/" + $File + "/tags/" + $Tag + "?owner=" + $var_community)
		}
		"IncidentID" {
			$Tag = Get-EscapedURIString -String $Tag
			$Tag = $Tag.ToLower()
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/tags/" + $Tag + "?owner=" + $var_community)
		}
	}
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = ($APIBaseURL + $APIChildURL)
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod 'POST' -URL $APIChildURL
	
	# Manage API query speed
	Start-Sleep -Seconds $throttle
	
	# Fix the "/" URL-escaping default behavior in .NET so URL's can correctly be posted.
	UrlFix $URI
	
	# Query the API
	$Response = Invoke-RestMethod -Method 'Post' -Uri $URI -Headers $AuthorizationHeaders -UserAgent '' -ContentType 'application/json; charset=utf-8'
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		Write-Host -ForegroundColor Green "Tag submitted successfully.."
		Write-Host ""
	}
	else
	{
		Write-Host -ForegroundColor Red "Tag association request failed for $ioc"
		Write-Host ""
		if ($Response -ne $null)
		{
			$Statuscode = $Response.StatusCode
		}
		else
		{
			$Statuscode = "No Status Code"
		}
		if ($Response -ne $null)
		{
			$ErrorDetail = $Response.ErrorDetails
		}
		else
		{
			$ErrorDetail = "No Error Detail"
		}
		Write-Output ($Statuscode + " " + $URI + " " + $ErrorDetail) >> $global:logfile
	}
}

function New-TCLabelAssociation
{
	<#
	.SYNOPSIS
		Associates a security label to an indicator or incident in Threat Connect.

	.PARAMETER Label
		Label name to associate.

	.EXAMPLE
		New-TCLabelAssociation -Label "TLP-Amber" -Hostname "www.baddomain.com"
		
		#>
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, ParameterSetName = 'Hostname')]
		[ValidateNotNullOrEmpty()]
		[String]$Hostname,
		[Parameter(Mandatory = $True, ParameterSetName = 'URL')]
		[ValidateNotNullOrEmpty()]
		[String]$URL,
		[Parameter(Mandatory = $True, ParameterSetName = 'EmailAddress')]
		[ValidateNotNullOrEmpty()]
		[String]$EmailAddress,
		[Parameter(Mandatory = $True, ParameterSetName = 'Address')]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[Parameter(Mandatory = $True, ParameterSetName = 'File')]
		[ValidateNotNullOrEmpty()]
		[String]$File,
		[Parameter(Mandatory = $True, ParameterSetName = 'IncidentID')]
		[ValidateNotNullOrEmpty()]
		[String]$IncidentID,
		[Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Label
	)
	
	# Switch to construct Child URL based on the parameters that were provided
	switch ($PSCmdlet.ParameterSetName)
	{
		"Hostname" {
			$Label = Get-EscapedURIString -String $Label
			$Hostname = $Hostname.ToLower()
			$APIChildURL = ("/v2/indicators/hosts/" + $Hostname + "/securityLabels/" + $Label + "?owner=" + $var_community)
		}
		"URL" {
			$Label = Get-EscapedURIString -String $Label
			$URL = Get-EscapedURIString -String $URL
			$URL = $URL.ToLower()
			$APIChildURL = ("/v2/indicators/urls/" + $URL + "/securityLabels/" + $Label + "?owner=" + $var_community)
		}
		"EmailAddress" {
			$Label = Get-EscapedURIString -String $Label
			$EmailAddress = Get-EscapedURIString -String $EmailAddress
			$EmailAddress = $EmailAddress.ToLower()
			$APIChildURL = ("/v2/indicators/emailAddresses/" + $EmailAddress + "/securityLabels/" + $Label + "?owner=" + $var_community)
		}
		"Address" {
			$Label = Get-EscapedURIString -String $Label
			$APIChildURL = ("/v2/indicators/addresses/" + $Address + "/securityLabels/" + $Label + "?owner=" + $var_community)
		}
		"File" {
			$Label = Get-EscapedURIString -String $Label
			$File = Get-EscapedURIString -String $File
			$File = $File.ToUpper()
			$APIChildURL = ("/v2/indicators/files/" + $File + "/securityLabels/" + $Label + "?owner=" + $var_community)
		}
		"IncidentID" {
			$Label = Get-EscapedURIString -String $Label
			$APIChildURL = ("/v2/groups/incidents/" + $IncidentID + "/securityLabels/" + $Label)
		}
	}
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = ($APIBaseURL + $APIChildURL)
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeader -RequestMethod 'POST' -URL $APIChildURL
	
	# Manage API query speed
	Start-Sleep -Seconds 5
	
	# Query the API
	$Response = Invoke-RestMethod -Method 'Post' -Uri $URI -Headers $AuthorizationHeaders -UserAgent '' -ContentType 'application/json; charset=utf-8'
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success")
	{
		Write-Host -ForegroundColor Green "Label association submitted successfully.."
		Write-Host ""
	}
	else
	{
		Write-Host -ForegroundColor Red "Label association request failed for $ioc"
		Write-Host ""
		if ($Response -ne $null)
		{
			$Statuscode = $Response.StatusCode
		}
		else
		{
			$Statuscode = "No Status Code"
		}
		if ($Response -ne $null)
		{
			$ErrorDetail = $Response.ErrorDetails
		}
		else
		{
			$ErrorDetail = "No Error Detail"
		}
		Write-Output ($Statuscode + " " + $URI + " " + $ErrorDetail) >> $global:logfile
	}
}

function Main-Menu
{
	
	& Cleanup
	
	if
	(
		$server -eq $null -or $server -eq "" -or
		$Script:MMAccessID -eq $null -or $Script:MMAccessID -eq "" -or
		$encryptedpassword -eq $null -or $encryptedpassword -eq "" -or
		$Script:TCAccessID -eq $null -or $Script:TCAccessID -eq "" -or
		$tcencryptedpassword -eq $null -or $tcencryptedpassword -eq "" -or
		$community -eq $null -or $community -eq "" -or
		$nodesettings_bl_ipv4 -eq $null -or $nodesettings_bl_ipv4 -eq "" -or
		$nodesettings_watch_ipv4 -eq $null -or $nodesettings_watch_ipv4 -eq "" -or
		$nodesettings_bl_url -eq $null -or $nodesettings_bl_url -eq "" -or
		$nodesettings_watch_url -eq $null -or $nodesettings_watch_url -eq "" -or
		$nodesettings_bl_sha1 -eq $null -or $nodesettings_bl_sha1 -eq "" -or
		$nodesettings_watch_sha1 -eq $null -or $nodesettings_watch_sha1 -eq "" -or
		$nodesettings_bl_sha256 -eq $null -or $nodesettings_bl_sha256 -eq "" -or
		$nodesettings_watch_sha256 -eq $null -or $nodesettings_watch_sha256 -eq ""
	)
	{
		Clear-Host
		Write-Host ""
		Write-Host -ForegroundColor Red "A required setting is not configured. Please relaunch PowerMM to complete setup."
		Write-Host ""
		Pause
		Exit
	}
	
	[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
	[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
	
	$global:dialogResult = $null
	
	# Set the size of the form
	$Form_MainMenu = New-Object System.Windows.Forms.Form
	$Form_MainMenu.Text = ("PowerMM v" + $version + " - Main Menu")
	$Form_MainMenu.StartPosition = "CenterScreen"
	$Form_MainMenu.size = '615,530'
	
	# Set the font of the text to be used within the form
	$Font = New-Object System.Drawing.Font("Arial", 9)
	$Form_MainMenu.Font = $Font
	
	$mmcheckboxfont = New-Object System.Drawing.Font("Arial", 8)
	$hist_checkboxfont = New-Object System.Drawing.Font("Arial", 9)
	
	# Create a group that will contain your radio buttons
	$Textbox_ManagedServer = New-Object System.Windows.Forms.GroupBox
	$Textbox_ManagedServer.Size = '260,40'
	$Textbox_ManagedServer.Location = '20,20'
	$Textbox_ManagedServer.height = '50'
	$Textbox_ManagedServer.Text = "Attached To"
	
	# Create a group that will contain your radio buttons
	$Textbox_MenuOptions = New-Object System.Windows.Forms.GroupBox
	$Textbox_MenuOptions.Size = '260,40'
	$Textbox_MenuOptions.Location = '20,75'
	$Textbox_MenuOptions.Height = '120'
	$Textbox_MenuOptions.Text = "Select an option:"
	
	$statusbar = New-Object System.Windows.Forms.StatusBar
	$statusbarpanel = New-Object System.Windows.Forms.StatusBarPanel
	$statusbarpanel.width = 600
	$statusbar.text = ""
	$statusbarpanel.text = ""
	$statusbar.showpanels = $true
	$statusbar.Panels.Add($statusbarpanel) | Out-Null
	
	# Create a group that will contain your radio buttons
	$Groupbox_ManagedNodes = New-Object System.Windows.Forms.GroupBox
	$Groupbox_ManagedNodes.Location = New-Object System.Drawing.Size(290, 20)
	$Groupbox_ManagedNodes.Text = "Managed Miners"
	
	if ($flag_mmdisabled -ne "1")
	{
		# Create a collection of radio buttons
		$RadioButton_Option1 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option1.Size = '160,20'
		$RadioButton_Option1.Location = '20,25'
		$RadioButton_Option1.Checked = $true
		$RadioButton_Option1.Text = "Update Blacklist"
		
		# Create a collection of radio buttons
		$RadioButton_Option2 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option2.Size = '160,20'
		$RadioButton_Option2.Location = '20,45'
		$RadioButton_Option2.Checked = $false
		$RadioButton_Option2.Text = "Update Watchlist"
		
		# Create a collection of radio buttons
		$RadioButton_Option3 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option3.Size = '160,20'
		$RadioButton_Option3.Location = '20,65'
		$RadioButton_Option3.Checked = $false
		$RadioButton_Option3.Text = "Search Nodes"
		
		# Create a collection of radio buttons
		$RadioButton_Option4 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option4.Size = '160,20'
		$RadioButton_Option4.Location = '20,85'
		$RadioButton_Option4.Checked = $false
		$RadioButton_Option4.Text = "Populate a Node"
	}
	else
	{
		# Create a collection of radio buttons
		$RadioButton_Option1 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option1.Size = '160,20'
		$RadioButton_Option1.Location = '20,25'
		$RadioButton_Option1.Checked = $true
		$RadioButton_Option1.Enabled = $true
		$RadioButton_Option1.Text = "Update ThreatConnect"
		
		# Create a collection of radio buttons
		$RadioButton_Option2 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option2.Size = '160,20'
		$RadioButton_Option2.Location = '20,45'
		$RadioButton_Option2.Checked = $false
		$RadioButton_Option2.Visible = $false
		$RadioButton_Option2.Enabled = $false
		$RadioButton_Option2.Text = "Update Watchlist"
		
		# Create a collection of radio buttons
		$RadioButton_Option3 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option3.Size = '160,20'
		$RadioButton_Option3.Location = '20,65'
		$RadioButton_Option3.Checked = $false
		$RadioButton_Option3.Visible = $false
		$RadioButton_Option3.Enabled = $false
		$RadioButton_Option3.Text = "Search Nodes"
		
		# Create a collection of radio buttons
		$RadioButton_Option4 = New-Object System.Windows.Forms.RadioButton
		$RadioButton_Option4.Size = '160,20'
		$RadioButton_Option4.Location = '20,85'
		$RadioButton_Option4.Checked = $false
		$RadioButton_Option4.Visible = $false
		$RadioButton_Option4.Enabled = $false
		$RadioButton_Option4.Text = "Populate a Node"
	}
	
	$Checkboxes_ManagedNodes += New-Object System.Windows.Forms.CheckBox
	$nodelist2 = Import-Csv -Path (Get-ChildItem -Path $configdir -Filter 'node_*.conf').FullName
	$nodearray2 = @()
	$Checkboxes_ManagedNodes = @()
	$Groupbox_ManagedNodes_Offset = 17
	
	foreach ($node in $nodelist2)
	{
		$searchnodelist = New-Object System.Object
		$nodename = $node.name
		$nodetype = $node.type
		$nodeoutput = $node.output
		$searchnodelist | Add-Member -MemberType NoteProperty -name "IndicatorList" -Value $nodename
		$searchnodelist | Add-Member -MemberType NoteProperty -name "Type" -Value $nodetype
		$searchnodelist | Add-Member -MemberType NoteProperty -name "FeedList" -Value $nodeoutput
		$nodearray2 += $searchnodelist
	}
	
	foreach ($list in $nodearray2)
	{
		$listname = $list.IndicatorList
		$listtype = $list.Type
		$listoutput = $list.FeedList
		$Checkbox_ManagedNodes = New-Object System.Windows.Forms.CheckBox
		$Checkbox_ManagedNodes | Add-Member -NotePropertyName IndicatorList -NotePropertyValue $listname
		$Checkbox_ManagedNodes | Add-Member -NotePropertyName Type -NotePropertyValue $listtype
		$Checkbox_ManagedNodes | Add-Member -NotePropertyName FeedList -NotePropertyValue $listoutput
		$Checkbox_ManagedNodes.Text = $listname
		$Checkbox_ManagedNodes.Font = $mmcheckboxfont
		$Checkbox_ManagedNodes.Location = New-Object System.Drawing.Size(10, $Groupbox_ManagedNodes_Offset)
		$Groupbox_ManagedNodes_Offset += 17
		$Checkbox_ManagedNodes.AutoSize = $true
		$Checkbox_ManagedNodes.Checked = $true
		$Checkbox_ManagedNodes.Enabled = $false
		$Groupbox_ManagedNodes.Controls.Add($Checkbox_ManagedNodes)
		$Checkboxes_ManagedNodes += $Checkbox_ManagedNodes
	}
	
	$Groupbox_ManagedNodes.size = New-Object System.Drawing.Size(290, ((50) + (15 * $Checkboxes_ManagedNodes.Count)))
	
	# Create a collection of check boxes
	$Checkbox_ManagedServer = New-Object System.Windows.Forms.CheckBox
	$Checkbox_ManagedServer.Size = '235,20'
	$Checkbox_ManagedServer.Location = '20,20'
	$Checkbox_ManagedServer.Checked = $true
	$Checkbox_ManagedServer.Text = $server
	$Checkbox_ManagedServer.Enabled = $false
	
	# Add an OK button
	$button_confirm = new-object System.Windows.Forms.Button
	$button_confirm.Location = '20,207'
	$button_confirm.Size = '60,20'
	$button_confirm.FlatStyle = 'System'
	$button_confirm.Text = 'GO'
	$button_confirm.DialogResult = [System.Windows.Forms.DialogResult]::OK
	
	# Add a Cancel button
	$button_cancel = new-object System.Windows.Forms.Button
	$button_cancel.Location = '90,207'
	$button_cancel.Size = '60,20'
	$button_cancel.FlatStyle = 'System'
	$button_cancel.Text = "EXIT"
	$button_cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	
	# Define View Log button - This button will open the latest user's log file
	$button_viewlog = New-Object System.Windows.Forms.Button
	$button_viewlog.Location = New-Object System.Drawing.Size(10, 440)
	$button_viewlog.Size = New-Object System.Drawing.Size(200, 25)
	$button_viewlog.FlatStyle = 'Popup'
	$button_viewlog.Text = "View log file of my last action"
	$button_viewlog.ForeColor = "White"
	$button_viewlog.BackColor = "Blue"
	$button_viewlog.Add_Click({$file_logci = Get-ChildItem -Path $logsdir | Where-Object { $_.FullName -match $global:logonas } | Sort-Object LastWriteTime | Select-Object -last 1
			; & 'notepad.exe' $file_logci.FullName
		})
	
	# Define View Release Notes button - This button will open the release notes file
	$button_viewrn = New-Object System.Windows.Forms.Button
	$button_viewrn.Location = New-Object System.Drawing.Size(220, 440)
	$button_viewrn.Size = New-Object System.Drawing.Size(160, 25)
	$button_viewrn.FlatStyle = 'Popup'
	$button_viewrn.Text = "View Release Notes"
	$button_viewrn.ForeColor = "White"
	$button_viewrn.BackColor = "Gray"
	$button_viewrn.Add_Click({
			$file_rn = Get-ChildItem -Path $file_releasenotes; & 'notepad.exe' $file_rn.FullName
		})
	
	# Create a group that will contain your radio buttons
	$Groupbox_History = New-Object System.Windows.Forms.GroupBox
	$Groupbox_History.Text = "History (last 7 ingests)"
	$Groupbox_History.Autosize = $true
	
	$Checkboxes_History = @()
	$Checkboxes_History += New-Object System.Windows.Forms.CheckBox
	$Groupbox_History_Offset = 20
	
	# Get ingestion history
	$incidenthist_exists = test-path $incident_history
	if ($incidenthist_exists -eq $true)
	{
		$incident_hist_detail = Import-CSV -Path $incident_history | Select-Object -Property timestamp, user, desc -Last 7
		
		foreach ($list in $incident_hist_detail)
		{
			$hist_timestamp = $list.timestamp
			$hist_user = $list.user
			$hist_desc = $list.desc
			$Checkbox_History = New-Object System.Windows.Forms.CheckBox
			$Checkbox_History | Add-Member -NotePropertyName Timestamp -NotePropertyValue $hist_timestamp
			$Checkbox_History | Add-Member -NotePropertyName User -NotePropertyValue $hist_user
			$Checkbox_History | Add-Member -NotePropertyName Desc -NotePropertyValue $hist_desc
			$Checkbox_History.Text = ($hist_timestamp + " - " + $hist_user + " - " + $hist_desc)
			$Checkbox_History.Font = $hist_checkboxfont
			$Checkbox_History.Location = New-Object System.Drawing.Size(10, $Groupbox_History_Offset)
			$Groupbox_History_Offset += 20
			$Checkbox_History.AutoSize = $true
			$Checkbox_History.Checked = $true
			$Checkbox_History.CheckAlign = "BottomLeft"
			$Checkbox_History.Enabled = $true
			$Groupbox_History.Controls.Add($Checkbox_History)
			$Checkboxes_History += $Checkbox_History
		}
		$Groupbox_History.size = New-Object System.Drawing.Size(570, 180)
		
		$Panel_History = New-Object System.Windows.Forms.Panel
		$Panel_History.Controls.Add($groupBox_History)
		$Panel_History.Location = New-Object System.Drawing.Point(10, 255)
		$Panel_History.AutoSize = $true
		$Panel_History.MaximumSize = '0,200'
		$Panel_History.TabIndex = 0
		$Panel_History.AutoScroll = $true
		
	}
	else
	{
		$incident_hist_detail = $null
	}
	
	# Add all the Form controls on one line
	$Form_MainMenu.Controls.AddRange(@($Textbox_MenuOptions, $Groupbox_ManagedNodes, $Textbox_ManagedServer, $MyTextBox1, $Panel_History, $button_confirm, $button_cancel, $button_viewlog, $button_viewrn, $statusbar))
	
	# Add all the GroupBox controls on one line
	$Textbox_MenuOptions.Controls.AddRange(@($RadioButton_Option1, $RadioButton_Option2, $RadioButton_Option3, $RadioButton_Option4))
	$Textbox_ManagedServer.Controls.AddRange(@($Checkbox_ManagedServer))
	
	# Assign the Accept and Cancel options in the form to the corresponding buttons
	$Form_MainMenu.AcceptButton = $button_confirm
	$Form_MainMenu.CancelButton = $button_cancel
	
	# Activate the form
	$Form_MainMenu.Add_Shown({ $Form_MainMenu.Activate() })
	
	# Get the results from the button click
	$global:dialogResult = $Form_MainMenu.ShowDialog()
	
	# if the Cancel button is selected
	if ($global:dialogResult -eq "Cancel")
	{
		Exit
	}
	
	# if the OK button is selected
	if ($global:dialogResult -eq "OK")
	{
		
		# Check the current state of each radio button and respond accordingly
		if ($RadioButton_Option1.Checked)
		{
			$global:abortdialog = $false
			$global:watchlistsel = $false
			& MenuOption-Ingest
		}
		if ($RadioButton_Option2.Checked)
		{
			$global:abortdialog = $false
			$global:watchlistsel = $true
			& MenuOption-Watchlist
		}
		if ($RadioButton_Option3.Checked)
		{
			$global:abortdialog = $false
			& MenuOption-Search
		}
		if ($RadioButton_Option4.Checked)
		{
			$global:abortdialog = $false
			$global:watchlistsel = $true
			& MenuOption-Populate
		}
	}
}

function MenuOption-Ingest
{
	
	# Cleanup prior environment
	$global:var_prop_value = $null
	
	# URL-Encode the ThreatConnect Community
	$var_community = Get-EscapedURIString -String $community
	$community_unescaped = $community
	
	# Prompt for Description
	if ($global:abortdialog -ne $true)
	{
		function Get-IncidentName
		{
			$global:var_prop_value = "incident"
			if ($flag_mmdisabled -ne "1")
			{
				if (($global:var_incidentname = Read-SingleLineInputBoxDialog -Message "Enter a MineMeld IOC Description:" -WindowTitle ("PowerMM v" + $version + " - Description") -HelpText "Give the indicators a description in 100 characters or less." -DefaultText $global:var_incidentname -Required $true -CheckboxID "1") -eq "")
				{
				}
			}
			else
			{
				$global:var_incidentname = "None"
			}
		}
		& Get-IncidentName
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for Attack Indicators
	if ($global:abortdialog -ne $true)
	{
		function Check-Duplicates
		{
			$global:var_prop_value = "indicators"
			if ($global:var_indicators -eq $null)
			{
				$global:BackButtonState = $null
			}
			if (($global:var_indicators = Read-MultiLineInputBoxDialog -Message "Paste in attack indicators (IP, CIDR, Domain, URL, SHA1, or SHA256)." -WindowTitle ("PowerMM v" + $version + " - Attack Indicators") -HelpText "Type or paste in a list of attack indicators (IP, CIDR, Domain, URL, SHA1, or SHA256)." -DefaultText $global:var_indicators -Required $true) -eq "")
			{
				$global:var_indicators
			}
			
			# Prep indicators for submission
			& Build-Indicator-Files
			
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-IncidentName
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "incident")
						{
							& Check-Duplicates
							if ($global:activatetc -eq "1")
							{
								#$global:hideradio = "1"
								& Prepare-TCIncident
							}
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		& Check-Duplicates
		if ($global:activatetc -eq "1")
		{
			$global:hideradio = "1"
			& Prepare-TCIncident
		}
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Confirm and Execute Ingestion Logic
	if ($global:abortdialog -ne $true)
	{
		
		# Prepare tags
		$testpath_tags = Test-Path $cachefile_tags
		if ($testpath_tags -eq $true)
		{
			$importioccache_tags = Get-Content -Path $cachefile_tags
		}
		
		# Display final submission detail page
		if ($var_indicators -ne $null -and $var_indicators -ne "" -and $global:abortdialog -ne $true)
		{
			function Get-SubmissionForm
			{
				
				if ($cb -eq "1")
				{
					$domainarray = @()
					$exists_cachefile_hosts = Test-Path $cachefile_hosts
					if ($exists_cachefile_hosts -eq $true)
					{
						$global:ioccache1 = Get-Content $cachefile_hosts
					}
					foreach ($ioc in $global:ioccache1)
					{
						$domainarray += "$ioc"
						$domainarray += "*.$ioc"
					}
				}
				else
				{
					$domainarray = @()
					$exists_cachefile_hosts = Test-Path $cachefile_hosts
					if ($exists_cachefile_hosts -eq $true)
					{
						$global:ioccache1 = Get-Content $cachefile_hosts
					}
					foreach ($ioc in $global:ioccache1)
					{
						$domainarray += "$ioc"
					}
				}
				$domainarray = $domainarray -join "`r`n"
				
				if ($cb -eq "1")
				{
					$urlarray = @()
					$exists_cachefile_urls = Test-Path $cachefile_urls
					if ($exists_cachefile_urls -eq $true)
					{
						$global:ioccache2 = Get-Content $cachefile_urls
					}
					foreach ($ioc in $global:ioccache2)
					{
						$urlarray += "$ioc"
					}
				}
				else
				{
					$urlarray = @()
					$exists_cachefile_urls = Test-Path $cachefile_urls
					if ($exists_cachefile_urls -eq $true)
					{
						$global:ioccache2 = Get-Content $cachefile_urls
					}
					foreach ($ioc in $global:ioccache2)
					{
						$urlarray += "$ioc"
					}
				}
				$urlarray = $urlarray -join "`r`n"
				
				$addrarray = @()
				$exists_cachefile_addr = Test-Path $cachefile_addr
				if ($exists_cachefile_addr -eq $true)
				{
					$global:ioccache3 = Get-Content $cachefile_addr
				}
				foreach ($ioc in $global:ioccache3)
				{
					$addrarray += "$ioc"
				}
				$addrarray = $addrarray -join "`r`n"
				
				if ($cb -eq "1")
				{
					$sha1array = @()
					$exists_cachefile_sha1 = Test-Path $cachefile_sha1
					if ($exists_cachefile_sha1 -eq $true)
					{
						$global:ioccache4 = Get-Content $cachefile_sha1
					}
					foreach ($ioc in $global:ioccache4)
					{
						$sha1array += "$ioc"
					}
				}
				else
				{
					$sha1array = @()
					$exists_cachefile_sha1 = Test-Path $cachefile_sha1
					if ($exists_cachefile_sha1 -eq $true)
					{
						$global:ioccache4 = Get-Content $cachefile_sha1
					}
					foreach ($ioc in $global:ioccache4)
					{
						$sha1array += "$ioc"
					}
				}
				$sha1array = $sha1array -join "`r`n"
				
				if ($cb -eq "1")
				{
					$sha256array = @()
					$exists_cachefile_sha256 = Test-Path $cachefile_sha256
					if ($exists_cachefile_sha256 -eq $true)
					{
						$global:ioccache5 = Get-Content $cachefile_sha256
					}
					foreach ($ioc in $global:ioccache5)
					{
						$sha256array += "$ioc"
					}
				}
				else
				{
					$sha256array = @()
					$exists_cachefile_sha256 = Test-Path $cachefile_sha256
					if ($exists_cachefile_sha256 -eq $true)
					{
						$global:ioccache5 = Get-Content $cachefile_sha256
					}
					foreach ($ioc in $global:ioccache5)
					{
						$sha256array += "$ioc"
					}
				}
				$sha256array = $sha256array -join "`r`n"
				
				$cidrarray = @()
				$exists_cachefile_cidr = Test-Path $cachefile_cidr
				if ($exists_cachefile_cidr -eq $true)
				{
					$global:ioccache6 = Get-Content $cachefile_cidr
				}
				foreach ($ioc in $global:ioccache6)
				{
					$cidrarray += "$ioc"
				}
				$cidrarray = $cidrarray -join "`r`n"
				
				# To add date to the comments field for each indicator
				$Timestamp = Get-Date -Format "MM-dd-yyyy"
				$global:Comment = ($global:var_incidentname + " - PowerMM [" + $Script:MMAccessID + " - " + $Timestamp + "]")
				
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
				
				# Set the size of the form
				$Form = New-Object System.Windows.Forms.Form
				$Form.Text = "PowerMM - Confirmation"
				$Form.StartPosition = "CenterScreen"
				$Form.size = '580,520'
				
				# Set the font of the text to be used within the form
				$Font = New-Object System.Drawing.Font("Arial", 10)
				$Form.Font = $Font
				
				if ($global:mmttl -ne $null)
				{
					$expiredate = (Get-Date).AddDays($global:mmttl)
					$expirestring = ($global:mmttl + " Days (" + $expiredate + ")")
				}
				else
				{
					$expirestring = "No Expiration"
				}
				
				# Display Instructions
				$textbox = New-Object Windows.Forms.TextBox
				if ($global:var_prop_value -eq $null)
				{
					$textbox.add_TextChanged({ $button_confirm.Enabled = $true })
				}
				$textbox.AutoSize = $True
				$textbox.Location = New-Object System.Drawing.Size(10, 10)
				$textbox.Size = New-Object System.Drawing.Size(500, 400)
				$textbox.MultiLine = $True
				$textbox.scrollbars = 'Both'
				$textbox.wordwrap = $True
				$textbox.readonly = $True
				
				if ($global:activatetc -ne "1")
				{
					$textbox.text = "
------------------------------------------------------
MineMeld Detail
------------------------------------------------------

DESCRIPTION:  $global:Comment
	
IOC EXPIRATION:  $expirestring

------------------------------------------------------
Indicator Detail
------------------------------------------------------

DOMAINS:
    $domainarray

URLS:
    $urlarray

IPV4 ADDRESSES:
    $addrarray

IPV4 CIDR BLOCKS:
    $cidrarray

SHA1 HASHES:
    $sha1array
	
SHA256 HASHES:
	$sha256array"
				}
				else
				{
					$textbox.text = "
------------------------------------------------------
ThreatConnect Parameters
-----------------------------------------------------

Incident Name:  [ $global:var_incidentname ]
Sector:  [ $var_industrysector ]		
Sensitivity Level:  [ $global:var_tlplabel ]
Community:  [ $community_unescaped ]
Description:  [ $global:var_description ]
Evilness Rating:  [ $global:var_evilness ]
Confidence:  [ $global:var_confidence ]
Tags:  [ $global:var_tags ]

------------------------------------------------------
MineMeld Detail
------------------------------------------------------

DESCRIPTION:  $global:Comment
	
IOC EXPIRATION:  $expirestring

------------------------------------------------------
Indicator Detail
------------------------------------------------------

DOMAINS:
    $domainarray

URLS:
    $urlarray

IPV4 ADDRESSES:
    $addrarray

IPV4 CIDR BLOCKS:
    $cidrarray

SHA1 HASHES:
    $sha1array
	
SHA256 HASHES:
	$sha256array"
				}
				
				$form.controls.add($textbox)
				
				# Add an OK button
				$button_confirm = new-object System.Windows.Forms.Button
				if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "")
				{
					$button_confirm.Enabled = $true
				}
				if ($Required -eq $true -and $global:var_prop_value -eq $null)
				{
					$button_confirm.Enabled = $false
				}
				$button_confirm.Location = '10,430'
				$button_confirm.Size = '75,25'
				$button_confirm.Text = 'Confirm'
				$button_confirm.DialogResult = [System.Windows.Forms.DialogResult]::OK
				
				# Create the Back button.
				$button_back = New-Object System.Windows.Forms.Button
				if ($global:var_prop_value -eq $null)
				{
					$button_back.Enabled = $false
				}
				else
				{
					$button_back.Enabled = $true
				}
				$button_back.Location = '90,430'
				$button_back.Size = '75,25'
				$button_back.Text = "Back"
				$button_back.Add_Click({ $form.Tag = $null; $global:BackButtonAction = $true; $form.Close() })
				
				# Add a Cancel button
				$button_cancel = new-object System.Windows.Forms.Button
				$button_cancel.Location = '170,430'
				$button_cancel.Size = '75,25'
				$button_cancel.Text = "Cancel"
				$button_cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
				$button_cancel.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
				
				# Add all the Form controls on one line 
				$form.Controls.AddRange(@($button_confirm, $button_back, $button_cancel))
				
				# Assign the Accept and Cancel options in the form to the corresponding buttons
				$form.AcceptButton = $button_confirm
				$form.CancelButton = $button_cancel
				
				# Activate the form
				$form.Add_Shown({ $form.Activate() })
				
				# Get the results from the button click
				$global:Confirm = $form.ShowDialog()
				
				$global:BackButtonState = $true
				
				while ($global:BackButtonAction -eq $true)
				{
					if ($global:abortdialog -ne $true)
					{
						& Check-Duplicates
						$global:BackButtonAction = $false
						if ($global:abortdialog -ne $true)
						{
							if ($global:var_prop_value -eq "indicators")
							{
								& Get-SubmissionForm
								$global:BackButtonAction = $false
							}
						}
					}
				}
			}
			& Get-SubmissionForm
			$global:BackButtonAction = $false
			
			# if the Confirm button is selected
			if ($global:Confirm -eq "OK")
			{
				
				# Submit a new incident
				$global:BackButtonAction = $false
				
				# Set incident timestamp
				$global:Timestamp = Get-Date -Format "yyyy-MM-ddTHH-mm-sszz"
				$global:UTC = Get-Date -Format O
				
				# Create and update log files
				$global:logfile = ($logdir + "log-" + $global:logonas + "-" + $global:Timestamp + ".txt")
				Write-Output $global:Comment >> $global:logfile
				
				# Create and update incident history file
				$incidenthist_exists = test-path $incident_history
				if ($incidenthist_exists -eq $false)
				{
					Write-Output "timestamp,user,desc" > $incident_history
					Write-Output  ("`n`r" + $global:Timestamp + "," + $global:logonas + "," + [string]$global:var_incidentname) >> $incident_history
				}
				else
				{
					Write-Output  ("`n`r" + $global:Timestamp + "," + $global:logonas + "," + [string]$global:var_incidentname) >> $incident_history
				}
				
				if ($flag_mmdisabled -ne "1")
				{
					
					Write-Host "Updating the Blacklist:"
					
					# Create and associate the defined indicators
					$testpath = Test-Path $cachefile_hosts
					if ($testpath -eq $true)
					{
						$hosts = Get-Content $cachefile_hosts | Select-Object -Unique
						foreach ($ioc in $hosts)
						{
							if ($cb -eq "1")
							{
								try
								{
									New-MMIndicator -Server $server -Indicator $ioc -IncludeSubDomain -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -SkipDupCheck:$false -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
							else
							{
								try
								{
									New-MMIndicator -Server $server -Indicator $ioc -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -SkipDupCheck:$false -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
					}
					
					$testpath = Test-Path $cachefile_urls
					if ($testpath -eq $true)
					{
						$urls = Get-Content $cachefile_urls
						foreach ($ioc in $urls)
						{
							if ($cb -eq "1")
							{
								try
								{
									New-MMIndicator -Server $server -Indicator $ioc -IncludeSubDomain -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -SkipDupCheck:$false -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
							else
							{
								try
								{
									New-MMIndicator -Server $server -Indicator $ioc -Type URL -FeedList $global:urloutnode -IndicatorList $global:urlindlist -SkipDupCheck:$false -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
					}
					
					$testpath = Test-Path $cachefile_addr
					if ($testpath -eq $true)
					{
						$addr = Get-Content $cachefile_addr
						foreach ($ioc in $addr)
						{
							try
							{
								New-MMIndicator -Server $server -Indicator $ioc -Type IPv4 -FeedList $ipv4outnode -IndicatorList $ipv4indlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
					
					$testpath = Test-Path $cachefile_sha1
					if ($testpath -eq $true)
					{
						$sha1 = Get-Content $cachefile_sha1
						foreach ($ioc in $sha1)
						{
							try
							{
								New-MMIndicator -Server $server -Indicator $ioc -Type SHA1 -FeedList $sha1outnode -IndicatorList $sha1indlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
					
					$testpath = Test-Path $cachefile_sha256
					if ($testpath -eq $true)
					{
						$sha256 = Get-Content $cachefile_sha256
						foreach ($ioc in $sha256)
						{
							try
							{
								New-MMIndicator -Server $server -Indicator $ioc -Type SHA256 -FeedList $sha256outnode -IndicatorList $sha256indlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
					
					$testpath = Test-Path $cachefile_cidr
					if ($testpath -eq $true)
					{
						$cidr = Get-Content $cachefile_cidr
						foreach ($ioc in $cidr)
						{
							try
							{
								New-MMIndicator -Server $server -Indicator $ioc -Type IPv4 -FeedList $ipv4outnode -IndicatorList $ipv4indlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
					
					if ($cb2 -eq "1")
					{
						
						Write-Host "Updating the Watchlist:"
						
						# Create and associate the defined indicators
						$testpath = Test-Path $cachefile_hosts
						if ($testpath -eq $true)
						{
							$hosts = Get-Content $cachefile_hosts | Select-Object -Unique
							foreach ($ioc in $hosts)
							{
								try
								{
									New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type URL -FeedList $global:urlwloutnode -IndicatorList $global:urlwatchlist -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
						
						$testpath = Test-Path $cachefile_urls
						if ($testpath -eq $true)
						{
							$urls = Get-Content $cachefile_urls
							foreach ($ioc in $urls)
							{
								try
								{
									New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type URL -FeedList $global:urlwloutnode -IndicatorList $global:urlwatchlist -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
						
						$testpath = Test-Path $cachefile_addr
						if ($testpath -eq $true)
						{
							$addr = Get-Content $cachefile_addr
							foreach ($ioc in $addr)
							{
								try
								{
									New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type IPv4 -FeedList $global:ipv4wloutnode -IndicatorList $global:ipv4watchlist -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
						
						$testpath = Test-Path $cachefile_sha1
						if ($testpath -eq $true)
						{
							$sha1 = Get-Content $cachefile_sha1
							foreach ($ioc in $sha1)
							{
								try
								{
									New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type URL -FeedList $global:sha1wloutnode -IndicatorList $global:sha1watchlist -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
						
						$testpath = Test-Path $cachefile_sha256
						if ($testpath -eq $true)
						{
							$sha256 = Get-Content $cachefile_sha256
							foreach ($ioc in $sha256)
							{
								try
								{
									New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type URL -FeedList $global:sha256wloutnode -IndicatorList $global:sha256watchlist -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
						
						$testpath = Test-Path $cachefile_cidr
						if ($testpath -eq $true)
						{
							$cidr = Get-Content $cachefile_cidr
							foreach ($ioc in $cidr)
							{
								try
								{
									New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type IPv4 -FeedList $global:ipv4wloutnode -IndicatorList $global:ipv4watchlist -BypassSSL
								}
								catch
								{
									Clear-Host
									Write-Host -ForegroundColor Red $_.Exception.Message
									Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
									pause
								}
							}
						}
					}
					
					# Check for errors in the previous function and halt if any
					$bugcheck = Get-Content $global:logfile -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Measure-Object –Line
					
					if ($bugcheck -eq "1")
					{
						Clear-Host
						Write-Host -ForegroundColor Red "A bug prevented ingestion into MineMeld. Please report this to Jason."
						Pause
						exit
					}
					
				}
				# Generate TC Incident if selected
				if ($cb3 -eq "1")
				{
					
					Write-Host "Updating $community_unescaped in ThreatConnect:"
					
					# Submit a new incident
					$global:BackButtonAction = $false
					& New-TCIncident -Name $global:var_incidentname -EventDate (Get-Date -Format "yyyy-MM-ddThh:mm:sszzzz")
					$Timestamp = Get-Date -Format g
					
					# Append IncidentID to Description
					$global:var_description = ($global:var_description + "`n`r`n`rIncidentID: " + $IncidentID)
					
					# Write Attributes and Label Associations
					& New-TCAttribute -IncidentID $IncidentID -Name Description -Value $global:var_description -Displayed "true"
					& New-TCLabelAssociation -Label $global:var_tlplabel -IncidentID $IncidentID
					foreach ($Tag in $importioccache_tags)
					{
						if ($Tag -ne $null -and $Tag -ne "")
						{
							& New-TCTag -Tag $Tag -IncidentID $IncidentID
						}
					}
					
					# Create and associate the defined indicators
					$testpath = Test-Path $cachefile_hosts
					if ($testpath -eq $true)
					{
						$importioccache_hosts = Get-Content -Path $cachefile_hosts
						foreach ($ioc in $importioccache_hosts)
						{
							& New-TCIndicator -Host $ioc -Confidence $global:var_confidence -Rating $global:var_evilness -WhoisActive "true" -DnsActive "true"
							& New-TCAssociation -Host $ioc
							& New-TCLabelAssociation -Label $global:var_tlplabel -Hostname $ioc
							foreach ($Tag in $importioccache_tags)
							{
								if ($Tag -ne $null -and $Tag -ne "")
								{
									& New-TCTag -Tag $Tag -Hostname $ioc
								}
							}
						}
					}
					$testpath = Test-Path $cachefile_urls
					if ($testpath -eq $true)
					{
						$importioccache_urls = Get-Content -Path $cachefile_urls
						foreach ($ioc in $importioccache_urls)
						{
							& New-TCIndicator -URL $ioc -Confidence $global:var_confidence -Rating $global:var_evilness
							& New-TCAssociation -URL $ioc
							& New-TCLabelAssociation -Label $global:var_tlplabel -URL $ioc
							foreach ($Tag in $importioccache_tags)
							{
								if ($Tag -ne $null -and $Tag -ne "")
								{
									& New-TCTag -Tag $Tag -URL $ioc
								}
							}
						}
					}
					$testpath = Test-Path $cachefile_addr
					if ($testpath -eq $true)
					{
						$importioccache_addr = Get-Content -Path $cachefile_addr
						foreach ($ioc in $importioccache_addr)
						{
							& New-TCIndicator -Address $ioc -Confidence $global:var_confidence -Rating $global:var_evilness
							& New-TCAssociation -Address $ioc
							& New-TCLabelAssociation -Label $global:var_tlplabel -Address $ioc
							foreach ($Tag in $importioccache_tags)
							{
								if ($Tag -ne $null -and $Tag -ne "")
								{
									& New-TCTag -Tag $Tag -Address $ioc
								}
							}
						}
					}
					$testpath = Test-Path $cachefile_sha1
					if ($testpath -eq $true)
					{
						$importioccache_hashsha1 = Get-Content -Path $cachefile_sha1
						foreach ($ioc in $importioccache_hashsha1)
						{
							& New-TCIndicator -FileSHA1 $ioc -Confidence $global:var_confidence -Rating $global:var_evilness
							& New-TCAssociation -FileSHA1Ind $ioc
							& New-TCLabelAssociation -Label $global:var_tlplabel -File $ioc
							foreach ($Tag in $importioccache_tags)
							{
								if ($Tag -ne $null -and $Tag -ne "")
								{
									& New-TCTag -Tag $Tag -File $ioc
								}
							}
						}
					}
					$testpath = Test-Path $cachefile_sha256
					if ($testpath -eq $true)
					{
						$importioccache_hashsha256 = Get-Content -Path $cachefile_sha256
						foreach ($ioc in $importioccache_hashsha256)
						{
							& New-TCIndicator -FileSHA256 $ioc -Confidence $global:var_confidence -Rating $global:var_evilness
							& New-TCAssociation -FileSHA256Ind $ioc
							& New-TCLabelAssociation -Label $global:var_tlplabel -File $ioc
							foreach ($Tag in $importioccache_tags)
							{
								if ($Tag -ne $null -and $Tag -ne "")
								{
									& New-TCTag -Tag $Tag -File $ioc
								}
							}
						}
					}
					$testpath = Test-Path $cachefile_cidr
					if ($testpath -eq $true)
					{
						$importioccache_cidr = Get-Content -Path $cachefile_cidr
						foreach ($ioc in $importioccache_cidr)
						{
							& New-TCIndicator -Address $ioc -Confidence $global:var_confidence -Rating $global:var_evilness
							& New-TCAssociation -Address $ioc
							& New-TCLabelAssociation -Label $global:var_tlplabel -Address $ioc
							foreach ($Tag in $importioccache_tags)
							{
								if ($Tag -ne $null -and $Tag -ne "")
								{
									& New-TCTag -Tag $Tag -Address $ioc
								}
							}
						}
					}
				}
				else
				{
					
				}
				
				Write-Host -ForegroundColor Green "Operation Completed. Returning to the Main Menu.."
				& Main-Menu
				break
			}
			# if the Cancel button is selected
			if ($global:Confirm -eq "Cancel")
			{
				Write-Host -ForegroundColor Red "Operation Cancelled. Returning to the Main Menu.."
				& Main-Menu
				break
			}
		}
		else
		{
			& Main-Menu
			break
		}
	}
	else
	{
		& Main-Menu
		break
	}
}

function MenuOption-Search
{
	$global:abortdialog = $false
	$global:BackButtonAction = $null
	$global:var_prop_value = $null
	$global:var_searchquery = $null
	$global:queryloopcomplete = $false
		
	# Prompt for Search Query
	if ($global:abortdialog -ne $true)
	{
		function Search-Query
		{
			$global:var_prop_value = "query"
			if (($global:var_searchquery = Read-SingleLineInputBoxDialog -Message "Search for indicator:" -WindowTitle ("PowerMM v" + $version + " - Search Query") -HelpText "In 100 characters or less, enter an IP, CIRD, Domain, or URL to perform a search on." -DefaultText $global:var_searchquery -Required $true -CheckboxID "2") -eq "")
			{
			}
		}
		& Search-Query
	}
	else
	{
		& Main-Menu
		break
	}
	
	# Confirm and Execute Search Query Logic
	if ($global:abortdialog -ne $true)
	{
		$global:enableform = $false
		Search-MMIndicator -Server $Server -Indicator $global:var_searchquery -BypassSSL
	}
	else
	{
		& Main-Menu
		break
	}
	Write-Host -ForegroundColor Green "Returning to the Main Menu.."
	& Main-Menu
	break
}

function MenuOption-Watchlist
{
	
	# Cleanup prior environment
	$global:var_prop_value = $null
	
	# Prompt for Description
	if ($global:abortdialog -ne $true)
	{
		function Get-IncidentName
		{
			$global:var_prop_value = "incident"
			if (($global:var_incidentname = Read-SingleLineInputBoxDialog -Message "Enter a Description:" -WindowTitle ("PowerMM v" + $version + " - Description") -HelpText "Give the indicators a description in 100 characters or less." -DefaultText $global:var_incidentname -Required $true -CheckboxID "1") -eq "")
			{
			}
		}
		& Get-IncidentName
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Prompt for Attack Indicators
	if ($global:abortdialog -ne $true)
	{
		function Search-MMIndicator
		{
			$global:var_prop_value = "indicators"
			if ($global:var_indicators -eq $null)
			{
				$global:BackButtonState = $null
			}
			if (($global:var_indicators = Read-MultiLineInputBoxDialog -Message "Paste in attack indicators (IP, CIDR, Domain, URL, SHA1, or SHA256)." -WindowTitle ("PowerMM v" + $version + " - Attack Indicators") -HelpText "Type or paste in a list of attack indicators (IP, CIDR, Domain, URL, SHA1, or SHA256)." -DefaultText $global:var_indicators -Required $true) -eq "")
			{
				$global:var_indicators
			}
			
			# Prep indicators for submission
			& Build-Indicator-Files
			
			while ($global:BackButtonAction -eq $true)
			{
				if ($global:abortdialog -ne $true)
				{
					& Get-IncidentName
					$global:BackButtonAction = $false
					if ($global:abortdialog -ne $true)
					{
						if ($global:var_prop_value -eq "incident")
						{
							& Search-MMIndicator
							$global:BackButtonAction = $false
						}
					}
				}
			}
		}
		& Search-MMIndicator
		$global:BackButtonAction = $false
	}
	else
	{
		& Main-Menu
	}
	
	# Confirm and Execute Ingestion Logic
	if ($global:abortdialog -ne $true)
	{
		
		# Display final submission detail page
		if ($var_indicators -ne $null -and $var_indicators -ne "" -and $global:abortdialog -ne $true)
		{
			function Get-SubmissionForm
			{
				
				if ($cb -eq "1")
				{
					$domainarray = @()
					$exists_cachefile_hosts = Test-Path $cachefile_hosts
					if ($exists_cachefile_hosts -eq $true)
					{
						$global:ioccache1 = Get-Content $cachefile_hosts
					}
					foreach ($ioc in $global:ioccache1)
					{
						$domainarray += "$ioc"
						$domainarray += "*.$ioc"
					}
				}
				else
				{
					$domainarray = @()
					$exists_cachefile_hosts = Test-Path $cachefile_hosts
					if ($exists_cachefile_hosts -eq $true)
					{
						$global:ioccache1 = Get-Content $cachefile_hosts
					}
					foreach ($ioc in $global:ioccache1)
					{
						$domainarray += "$ioc"
					}
				}
				$domainarray = $domainarray -join "`r`n"
				
				if ($cb -eq "1")
				{
					$urlarray = @()
					$exists_cachefile_urls = Test-Path $cachefile_urls
					if ($exists_cachefile_urls -eq $true)
					{
						$global:ioccache2 = Get-Content $cachefile_urls
					}
					foreach ($ioc in $global:ioccache2)
					{
						$urlarray += "$ioc"
					}
				}
				else
				{
					$urlarray = @()
					$exists_cachefile_urls = Test-Path $cachefile_urls
					if ($exists_cachefile_urls -eq $true)
					{
						$global:ioccache2 = Get-Content $cachefile_urls
					}
					foreach ($ioc in $global:ioccache2)
					{
						$urlarray += "$ioc"
					}
				}
				$urlarray = $urlarray -join "`r`n"
				
				$addrarray = @()
				$exists_cachefile_addr = Test-Path $cachefile_addr
				if ($exists_cachefile_addr -eq $true)
				{
					$global:ioccache3 = Get-Content $cachefile_addr
				}
				foreach ($ioc in $global:ioccache3)
				{
					$addrarray += "$ioc"
				}
				$addrarray = $addrarray -join "`r`n"
				
				if ($cb -eq "1")
				{
					$sha1array = @()
					$exists_cachefile_sha1 = Test-Path $cachefile_sha1
					if ($exists_cachefile_sha1 -eq $true)
					{
						$global:ioccache4 = Get-Content $cachefile_sha1
					}
					foreach ($ioc in $global:ioccache4)
					{
						$sha1array += "$ioc"
					}
				}
				else
				{
					$sha1array = @()
					$exists_cachefile_sha1 = Test-Path $cachefile_sha1
					if ($exists_cachefile_sha1 -eq $true)
					{
						$global:ioccache4 = Get-Content $cachefile_sha1
					}
					foreach ($ioc in $global:ioccache4)
					{
						$sha1array += "$ioc"
					}
				}
				$sha1array = $sha1array -join "`r`n"
				
				if ($cb -eq "1")
				{
					$sha256array = @()
					$exists_cachefile_sha256 = Test-Path $cachefile_sha256
					if ($exists_cachefile_sha256 -eq $true)
					{
						$global:ioccache5 = Get-Content $cachefile_sha256
					}
					foreach ($ioc in $global:ioccache5)
					{
						$sha256array += "$ioc"
					}
				}
				else
				{
					$sha256array = @()
					$exists_cachefile_sha256 = Test-Path $cachefile_sha256
					if ($exists_cachefile_sha256 -eq $true)
					{
						$global:ioccache5 = Get-Content $cachefile_sha256
					}
					foreach ($ioc in $global:ioccache5)
					{
						$sha256array += "$ioc"
					}
				}
				$sha256array = $sha256array -join "`r`n"
				
				$cidrarray = @()
				$exists_cachefile_cidr = Test-Path $cachefile_cidr
				if ($exists_cachefile_cidr -eq $true)
				{
					$global:ioccache6 = Get-Content $cachefile_cidr
				}
				foreach ($ioc in $global:ioccache6)
				{
					$cidrarray += "$ioc"
				}
				$cidrarray = $cidrarray -join "`r`n"
				
				# To add date to the comments field for each indicator
				$Timestamp = Get-Date -Format "MM-dd-yyyy"
				$global:Comment = ($global:var_incidentname + " - PowerMM [" + $Script:MMAccessID + " - " + $Timestamp + "]")
				
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
				
				# Set the size of the form
				$Form = New-Object System.Windows.Forms.Form
				$Form.Text = "PowerMM - Confirmation"
				$Form.StartPosition = "CenterScreen"
				$Form.size = '580,520'
				
				# Set the font of the text to be used within the form
				$Font = New-Object System.Drawing.Font("Arial", 10)
				$Form.Font = $Font
				
				# Display Instructions
				$textbox = New-Object Windows.Forms.TextBox
				if ($global:var_prop_value -eq $null)
				{
					$textbox.add_TextChanged({ $button_confirm.Enabled = $true })
				}
				
				if ($global:mmttl -ne $null)
				{
					$expiredate = (Get-Date).AddDays($global:mmttl)
					$expirestring = ($global:mmttl + " Days (" + $expiredate + ")")
				}
				else
				{
					$expirestring = "No Expiration"
				}
				
				$textbox.AutoSize = $True
				$textbox.Location = New-Object System.Drawing.Size(10, 10)
				$textbox.Size = New-Object System.Drawing.Size(500, 400)
				$textbox.MultiLine = $True
				$textbox.scrollbars = 'Both'
				$textbox.wordwrap = $True
				$textbox.readonly = $True
				$textbox.text = "
DESCRIPTION:  $global:Comment
	
IOC EXPIRATION:  $expirestring

DOMAINS:

    $domainarray

URLS:

    $urlarray

IPV4 ADDRESSES:

    $addrarray

IPV4 CIDR BLOCKS:

    $cidrarray

SHA1 HASHES:

    $sha1array
	
SHA256 HASHES:

    $sha256array"
				
				$form.controls.add($textbox)
				
				# Add an OK button
				$button_confirm = new-object System.Windows.Forms.Button
				if ($global:var_prop_value -ne $null -and $global:var_prop_value -ne "")
				{
					$button_confirm.Enabled = $true
				}
				if ($Required -eq $true -and $global:var_prop_value -eq $null)
				{
					$button_confirm.Enabled = $false
				}
				$button_confirm.Location = '10,430'
				$button_confirm.Size = '75,25'
				$button_confirm.Text = 'Confirm'
				$button_confirm.DialogResult = [System.Windows.Forms.DialogResult]::OK
				
				# Create the Back button.
				$button_back = New-Object System.Windows.Forms.Button
				if ($global:var_prop_value -eq $null)
				{
					$button_back.Enabled = $false
				}
				else
				{
					$button_back.Enabled = $true
				}
				$button_back.Location = '90,430'
				$button_back.Size = '75,25'
				$button_back.Text = "Back"
				$button_back.Add_Click({ $form.Tag = $null; $global:BackButtonAction = $true; $form.Close() })
				
				# Add a Cancel button
				$button_cancel = new-object System.Windows.Forms.Button
				$button_cancel.Location = '170,430'
				$button_cancel.Size = '75,25'
				$button_cancel.Text = "Cancel"
				$button_cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
				$button_cancel.Add_Click({ $global:abortdialog = $true; $form.Tag = $null; $form.Close() })
				
				# Add all the Form controls on one line 
				$form.Controls.AddRange(@($button_confirm, $button_back, $button_cancel))
				
				# Assign the Accept and Cancel options in the form to the corresponding buttons
				$form.AcceptButton = $button_confirm
				$form.CancelButton = $button_cancel
				
				# Activate the form
				$form.Add_Shown({ $form.Activate() })
				
				# Get the results from the button click
				$global:Confirm = $form.ShowDialog()
				
				$global:BackButtonState = $true
				
				while ($global:BackButtonAction -eq $true)
				{
					if ($global:abortdialog -ne $true)
					{
						& Search-MMIndicator
						$global:BackButtonAction = $false
						if ($global:abortdialog -ne $true)
						{
							if ($global:var_prop_value -eq "indicators")
							{
								& Get-SubmissionForm
								$global:BackButtonAction = $false
							}
						}
					}
				}
			}
			& Get-SubmissionForm
			$global:BackButtonAction = $false
			
			# if the Confirm button is selected
			if ($global:Confirm -eq "OK")
			{
				
				# Submit a new incident
				$global:BackButtonAction = $false
				
				# Set incident timestamp
				$global:Timestamp = Get-Date -Format "yyyy-MM-ddTHH-mm-sszz"
				$global:UTC = Get-Date -Format O
				
				# Create and update log files
				$global:logfile = ($logdir + "log-" + $global:logonas + "-" + $global:Timestamp + ".txt")
				Write-Output $global:Comment >> $global:logfile
				
				# Create and associate the defined indicators
				$testpath = Test-Path $cachefile_hosts
				if ($testpath -eq $true)
				{
					$hosts = Get-Content $cachefile_hosts | Select-Object -Unique
					foreach ($ioc in $hosts)
					{
						if ($cb -eq "1")
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -IncludeSubDomain -Type URL -FeedList $global:urlwloutnode -IndicatorList $global:urlwatchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
						else
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type URL -FeedList $global:urlwloutnode -IndicatorList $global:urlwatchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
				}
				
				$testpath = Test-Path $cachefile_urls
				if ($testpath -eq $true)
				{
					$urls = Get-Content $cachefile_urls
					foreach ($ioc in $urls)
					{
						if ($cb -eq "1")
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -IncludeSubDomain -Type URL -FeedList $global:urlwloutnode -IndicatorList $global:urlwatchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
						else
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type URL -FeedList $global:urlwloutnode -IndicatorList $global:urlwatchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
				}
				
				$testpath = Test-Path $cachefile_addr
				if ($testpath -eq $true)
				{
					$addr = Get-Content $cachefile_addr
					foreach ($ioc in $addr)
					{
						try
						{
							New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type IPv4 -FeedList $global:ipv4wloutnode -IndicatorList $global:ipv4watchlist -BypassSSL
						}
						catch
						{
							Clear-Host
							Write-Host -ForegroundColor Red $_.Exception.Message
							Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
							pause
						}
						
					}
				}
				
				$testpath = Test-Path $cachefile_sha1
				if ($testpath -eq $true)
				{
					$sha1 = Get-Content $cachefile_sha1
					foreach ($ioc in $sha1)
					{
						if ($cb -eq "1")
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -IncludeSubDomain -Type SHA1 -FeedList $global:sha1wloutnode -IndicatorList $global:sha1watchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
						else
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type SHA1 -FeedList $global:sha1wloutnode -IndicatorList $global:sha1watchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
				}
				
				$testpath = Test-Path $cachefile_sha256
				if ($testpath -eq $true)
				{
					$sha256 = Get-Content $cachefile_sha256
					foreach ($ioc in $sha256)
					{
						if ($cb -eq "1")
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -IncludeSubDomain -Type SHA256 -FeedList $global:sha256wloutnode -IndicatorList $global:sha256watchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
						else
						{
							try
							{
								New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type SHA256 -FeedList $global:sha256wloutnode -IndicatorList $global:sha256watchlist -BypassSSL
							}
							catch
							{
								Clear-Host
								Write-Host -ForegroundColor Red $_.Exception.Message
								Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
								pause
							}
						}
					}
				}
				
				$testpath = Test-Path $cachefile_cidr
				if ($testpath -eq $true)
				{
					$cidr = Get-Content $cachefile_cidr
					foreach ($ioc in $cidr)
					{
						try
						{
							New-MMIndicator -Server $server -Indicator ($ioc + "," + $global:UTC + "," + $global:comment) -Type IPv4 -FeedList $global:ipv4wloutnode -IndicatorList $global:ipv4watchlist -BypassSSL
						}
						catch
						{
							Clear-Host
							Write-Host -ForegroundColor Red $_.Exception.Message
							Write-Output ("ERROR: " + $_.Exception.Message) >> $global:logfile
							pause
						}
						
					}
				}
				
				# Check for errors in the previous function and halt if any
				$bugcheck = Select-String -Path $global:logfile -Pattern "ERROR"
				
				if ($bugcheck -ne $null)
				{
					Clear-Host
					Write-Host -ForegroundColor Red "An ERROR has occured. Please see your last log file for more information: $global:logfile"
					Pause
					exit
				}
				
				Write-Host -ForegroundColor Green "Operation Completed. Returning to the Main Menu.."
				& Main-Menu
				break
			}
			# if the Cancel button is selected
			if ($global:Confirm -eq "Cancel")
			{
				Write-Host -ForegroundColor Red "Operation Cancelled. Returning to the Main Menu.."
				& Main-Menu
				break
			}
		}
		else
		{
			& Main-Menu
			break
		}
	}
	else
	{
		& Main-Menu
		break
	}
}

function MenuOption-Populate
{
	
	$global:var_prop_value = $null
	$global:var_Populate = $null
	$global:queryloopcomplete = $false
	
	# Prompt for Populate Query
	if ($global:abortdialog -ne $true)
	{
		function Populate-Query
		{
			$global:var_prop_value = "query"
			if (($global:var_populate_srcurl = Read-SingleLineInputBoxDialog -Message "Source URL:" -WindowTitle ("PowerMM v" + $version + " - Populate") -HelpText "Enter a URL containing indicators you want to populate to a node." -DefaultText $global:var_populate_srcurl -Required $true -CheckboxID "1") -eq "")
			{
			}
			if ($global:abortdialog -eq $true)
			{
				& Main-Menu
				break
			}
			if (($global:var_Populate_destnode = Read-SingleLineInputBoxDialog -Message "Destination Node Name:" -WindowTitle ("PowerMM v" + $version + " - Populate") -HelpText "Enter a destination node name." -DefaultText $global:var_Populate_destnode -Required $true -CheckboxID "1") -eq "")
			{
			}
			if ($global:abortdialog -eq $true)
			{
				& Main-Menu
				break
			}
			if (($global:var_Populate_type = Read-SingleLineInputBoxDialog -Message "Indicator type:" -WindowTitle ("PowerMM v" + $version + " - Populate") -HelpText "Enter the type of indicator that will be Populated (IPv4, CIDR, URL, SHA1, or SHA256)." -DefaultText $global:var_Populate_type -Required $true -CheckboxID "1") -eq "")
			{
			}
			if ($global:abortdialog -eq $true)
			{
				& Main-Menu
				break
			}
		}
		& Populate-Query
	}
	else
	{
		& Main-Menu
		break
	}
	
	# Confirm and Execute Migration
	if ($global:abortdialog -ne $true)
	{
		Populate-MMNode -Server $Server -SourceURL $global:var_populate_srcurl -DestNode $global:var_Populate_destnode -Type $global:var_Populate_type -BypassSSL
	}
	else
	{
		& Main-Menu
		break
	}
	Write-Host -ForegroundColor Green "Returning to the Main Menu.."
	& Main-Menu
	break
}

& Main-Menu