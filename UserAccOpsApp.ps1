

<#

This script builds a control panel for account operations.
It writes input-files to scripts UserAccOpsBatch that performs the operations.
Set encryption key below and in UserAccOpsBatch. 


Author 
Josef Ereq


Version 2.1


#> 


# - Set error-handling to stop execution, if error occurs. This is to prevent processing upon errors.
$ErrorActionPreference = "stop"


# - Import Active Directory Powershell-module
import-module activedirectory

# - Specify variables:

    ## - Specify path to where the application local config file is located.    
    $ConfigPath = ".\"

    ## - Build an array of all regex-names for special ASCII characters.
    $RegExSet = @("REGEXENT040","REGEXENT041","REGEXENT042","REGEXENT043","REGEXENT044","REGEXENT045","REGEXENT046","REGEXENT047","REGEXENT050","REGEXENT051","REGEXENT052","REGEXENT053","REGEXENT054","REGEXENT055","REGEXENT056","REGEXENT057","REGEXENT072","REGEXENT073","REGEXENT074","REGEXENT075","REGEXENT076","REGEXENT077","REGEXENT100","REGEXENT133","REGEXENT134","REGEXENT135","REGEXENT136","REGEXENT137","REGEXENT140","REGEXENT173","REGEXENT174","REGEXENT175","REGEXENT176","REGEXENT177")

    ## - Specify path to output-path.(Users must have modify-rights to share.)  
    $ScriptData = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.type -eq "OutputPath"}).value

    ## - Specify path to static data input.(Users must have read-rights to config files.)  
    $GlobalData = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.type -eq "ConfigPath"}).value

    ## - Specify domain FQDN.
    $DOMFQDN = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.type -eq "DomainName"}).value

    ## - Set the variable for which domain controller to fetch users from.
    $server = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.type -eq "DomainController"}).value

    ## - Specify User-OU distinguished name.
    $OU = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.type -eq "UserAccounts"}).value
    
    ## - Build the regex-string for disable-stamps in account description.
    $DisableStamp = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.Type -eq "DisableStamp"}).value
    $DisableStampRegEx = $DisableStamp -replace "\133" -replace "\135"

    # - Loop troug each of the regex-names and replace special characters in Inactivity-stamp with it.
    foreach($RegExEnt in $RegExSet)
        {
        $RegExreal = $RegExEnt -replace "REGEXENT","\"
        $DisableStampRegEx = $DisableStampRegEx -replace $RegExreal,$RegExEnt

        }
    $DisableStampRegEx = $DisableStampRegEx -replace "REGEXENT","\"
    $DisableStampRegEx = $DisableStampRegEx -replace "DISABLEDATE","(\d){8}"

    ## - Build the regex-string for inactivity-disable-stamps  in account description.
    $InactivityStamp = (import-csv (join-path $ConfigPath "AppADSettings.csv") -Delimiter ";" | where {$_.Type -eq "InactiveStamp"}).value
    $InactivityStampRegEx = $InactivityStamp -replace "\133" -replace "\135"
    # - Loop troug each of the regex-names and replace special characters in Inactivity-stamp with it.
    foreach($RegExEnt in $RegExSet)
        {
        $RegExreal = $RegExEnt -replace "REGEXENT","\"
        $InactivityStampRegEx = $InactivityStampRegEx -replace $RegExreal,$RegExEnt

        }
    $InactivityStampRegEx = $InactivityStampRegEx -replace "REGEXENT","\"
    $InactivityStampRegEx = $InactivityStampRegEx -replace "DISABLEDATE","(\d){8}"
    $InactivityStampRegEx = $InactivityStampRegEx -replace "INACTIVEDAYS","(\d)+"

    ## - Specify the name of the authorized AD-group. The group members will be authorized to perform application presented operations.
    $Rolename = (import-csv (join-path $GlobalData "AppAccessGroups.csv") -Delimiter ";" | where {$_.App -eq "UserAccOps"}).GroupName

    ## - Specify the name of the authorized fallback AD-group. Its group members will be authorized to perform application presented operations, in fail-over situations.
    $FallBackGrp = (import-csv (join-path $GlobalData "AppAccessFallback.csv") -Delimiter ";" | where {$_.Type -eq "Group"}).Name

    ## - Specify the name of the authorized fallback AD-user. Its user will be authorized to perform application presented operations, in fail-over situations.
    $FallBackUsr = (import-csv (join-path $GlobalData "AppAccessFallback.csv") -Delimiter ";" | where {$_.Type -eq "User"}).Name


    ## - Create a array for the encryption key for when encrypting the password.
    $aes = New-Object "System.Security.Cryptography.AesManaged"
    $aes.IV = ""
    $aes.key = ""

    ## - Specify varaible for importing accepted input-date ranges.
    $DateRange = (import-csv (join-path $GlobalData "AppDateRange.csv") -Delimiter ";")

    ## - Set the path to the output-files in variables. These files will be picked up and executed by the back-end scripts.
        
        ### - The output-file for the password-reset back-end script.
        $InputFilePWRes = (join-path $ScriptData "INPUT_UserAccPWReset.txt")

        ### - The output-file for unlock-account back-end script.
        $InputFileUnlock = (join-path $ScriptData "INPUT_UnlockUsrAcc.txt")

        ### - The output-file for the disable-account back-end script.
        $InputFileDisable = (join-path $ScriptData "INPUT_DisableUsrAcc.txt")

        ### - The output-file for the set expiration-date back-end script.
        $InputFileDate = (join-path $ScriptData "INPUT_SetUsrAccDate.txt")

        ### - The output-file for the clear expiration date back-end script.
        $InputFilRemDate = (join-path $ScriptData "INPUT_ClearUsrAccDate.txt")

        ### - The output-file for the recover-acccount back-end script.
        $InputFileRecover = (join-path $ScriptData "INPUT_RecUsrAcc.txt")

        ## - The output-file for the password-change-enforcement back-end script.
        $InputFileEnfPWChange = (join-path $ScriptData "INPUT_EnfPWChange.txt")
        
        ## - The output-file for the account deletion back-end script.
        $InputFileDelete = (join-path $ScriptData "INPUT_DeleteUsrAcc.txt")

# - Load the FQDN of the domain in the current network, into a varaible.
$CurDOM = (Get-ADDomain).DNSRoot

# - Check if the domain in the current network is the same as the pre-specified authorized domain. If so, runt the script block.
if($CurDOM -eq $DOMFQDN)
    {
    # - Load the Netbios name of the domain.
    $DOMNetBios = (Get-ADDomain).NetBiosname

    }
# - If the the domain in the current network is not the same as the pre-specified authorized domain, run the script block.
else
    {
    # - Output exit-message
    Write-host "Home domain not found. Exiting.."

    # - Close the form and quit the powershell-session.
    $form.close()
    exit  
    }

# - Check if the running user's domain is the same as the pre-authorized authorized domain. If so, run the script block.
if($Env:Userdomain -ne $DOMNetBios)
    {
    # - Output exit-message
    Write-host "User domain not found. Exiting.."

    # - Close the form and quit the powershell-session.
    $form.close()
    exit   
    }



# - Load the running admin username, state, group memberships and related variables. This will be used to check if runtime person is authorized to perform selected operation, and for logging purpose.
New-variable SecGrps -scope global -value ("")
set-variable EndN -scope global -value (0)
New-variable RunN -scope global -value (0)
New-variable ADSAM -scope Global -value ($env:Username)
New-variable ADState -scope Global -value (Get-aduser -filter {sAMAccountName -like $ADSAM} -server $server)
New-variable AuthzSwitch -scope global -value ($false)
New-variable RunnerUPN -scope global -value ((Get-ADUser -server $server $env:UserName -Properties userprincipalname).userprincipalname)


# - Check if the running user is enabled in Active Directory. If so, run the script block.
if($AdState.Enabled -eq $false)
    {
    # - Close the form and quit the powershell-session.
    $form.close()
    exit 
                        
                                
    }      
   

# - Create the function that checks if running user has authorization.
function AuthzFunc
    {
    # - Rmove the user-status information boxes.
    $Form.Controls.Remove($Statbox1)
	$Form.Controls.Remove($Statbox2)
    $Form.Controls.Remove($Statbox3)
    # - Add the authorization information box.
    $Form.Controls.Add($AuthzBox)
    # - Set authorization-status text in its box.
    $AuthzBox.text = "Loading.."
    sleep -Seconds 0.5

    # - Check if the variable for running user AD-distinguished name exists, if not, load it.
    if(!$Runnerdn)
        {
        # - Load the running ad-user distinguished name, into a variable. This will be used to check operation authorization when submitting an action. 
        new-variable RunnerDN -scope global -value ((Get-ADUser -server $server $env:UserName -Properties distinguishedname).distinguishedname)
        }

    # - Load the running admin user state, group memberships and related variables. This will be used to check if runtime person is authorized to perform selected operation.
    set-variable SecGrps -scope global -value ((Get-ADGroup -server $server -LDAPFilter ("(member:1.2.840.113556.1.4.1941:={0})" -f $RunnerDN)).name)
    set-variable EndN -scope global -value ($SecGrps.count)
    set-variable RunN -scope global -value (0)
    Set-variable ADSAM -scope Global -value ($env:Username)
    Set-variable ADState -scope Global -value (Get-aduser -filter {sAMAccountName -like $ADSAM} -server $server)
    set-variable AuthzSwitch -scope global -value ($false)

    # - Check if the running user is disabled in Active Directory. If so, run the script block.
    if($AdState.Enabled -eq $false)
        {
        # - Close the application form.                             
        $form.close()
        # - Quit the powershell-session.
        exit
                        
                                
        } 
    # - Check if the variable containing the running user group memberships contains the authorized role-group.
    if($Secgrps -contains $Rolename)
        {
        # - Set the variable used to signal authorization to TRUE
        set-variable AuthzSwitch -scope global -value ($true)
        }     
                                                                                      
        
    # - If the check above fails, check if the variable containing the running user group memberships contains the authorized fallback-group.
    elseif($SecGrps -contains $FallBackGrp)
        {
    
        # - Set the variable used to signal authorization to TRUE
        set-variable AuthzSwitch -scope global -value ($true)
        
        }
    # - If the check above fails, check if the running user is the fallback-user.
    elseif($ADSAM -eq $FallBackUsr)
        {
        # - Set the variable used to signal authorization to TRUE
        set-variable AuthzSwitch -scope global -value ($true)
        } 
    # - If all the checks above fails, run the script block.
    else
        {  
        # - Close the application form.                             
        $form.close()

        # - Exit and quit the powershell-session.
        exit                               
                
        }                           

         

    # - Clear authorization-status box    
    $AuthzBox.text = "" 
    # - Remove the authorization-status information box.
    $Form.Controls.Remove($AuthzBox)
    # - Add the user-status information boxes.
    $Form.Controls.Add($Statbox1)
    $Form.Controls.Add($Statbox2)
    $Form.Controls.Add($Statbox3)
    }            

# - Create a function used for searching users by entered text-input in the form.
function SearchUsers
    {
    # - Set the user search-string parameter for the function.
    Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string]$UserStr
    )

    # - If theres more than one character entered in the search-box, run the script block.
     if(($UserStr -ne $SearchPlaceHolder) -and $UserStr) 
        {
        # - Clear the dropdown box.
        $UserBoxList.items.Clear()
        # - Loop trough the array of users. And run the sript block for each.
        foreach($user in $users)
                {                       
                # - If the entered string in the search-box does not match any string in the name of the loaded user, and the dropdown-box do contian the user, run the script block.
                if($user -like "*$UserStr*")
                    {
                    # - Add to the user dropdown-box.
                    [void]$UserBoxList.items.Add($user)
                    # - Enable the user dropdown-box.
                    $UserBoxList.Enabled = $True                          
                    }
                }
        # - If the number of users found is 1, run the script block.
        if($UserBoxList.items.count -eq 1)
                {
                # - Set the text-color for the user status-information box.
                $Statbox1.forecolor = "white"
                # - Set the text-string of the information box accordingly.
                $Statbox1.text = "$($UserBoxList.items.count) user found"
                }
        # - If the number of users found greater than 1, run the script block.
        elseif($UserBoxList.items.count -gt 1)
                {
                # - Set the text-color for the user status-information box
                $Statbox1.forecolor = "white"
                # - Set the text-string of the information box accordingly.
                $Statbox1.text = "$($UserBoxList.items.count) users found"
                }
        # - If no users are found, run the script block.
        elseif($UserBoxList.items.count -eq 0)
                {
                # - Set the text-color for the user status-information box.
                $Statbox1.forecolor = "white"
                # - Set the text-string of the information box accordingly.
                $Statbox1.text = "User not found"
                }

        }
    }      

# - Create a function that will be used to verify that the AD-account expiration date is valid.
function Verify-AccExpDate
    {

   # - Set the expirate-date to test as parameter for the function.
   Param(
   [Parameter(Mandatory=$true,Position=0)]
   [string]$InputDate
   )
   # - Clear the variable used for signaling correct or incorrect date-format.
   $ValidDate = $null
   # - Replace any non-digits in the input-date, and load the rest into a variable used for testing the date.
   $Digits = $InputDate -replace "\D"
   # - Set the minimum date to allow in the expiration-date.
   $MinDate = (get-date -Hour 00 -Minute 00 -Second 00).AddSeconds(-1)
   # - Load the maximum date to allow in the expiration-date.
   $MaxDate = (get-date).AddDays(($daterange | where {$_.name -eq "MaxDateAccountExp"}).days)


      # - If the date to test consists of 8 digits, run the script block.
      if($Digits.length -eq 8)
        {
        # - Format the date into a testable date-format, into a new variable.
        $DateForm = "$($digits.Substring(0,4))-$($digits.Substring(4,2))-$($digits.Substring(6,2))"
        # - Test the date and load the result into a variable.
        $TestDate = get-date $DateForm
        #- Check that the valid-date variable contains a date, and that it is within allowed minimum and maximum. If so, run the script block.
        if(($TestDate) -and ($TestDate -ge $MinDate) -and ($TestDate -lt $MaxDate))
            {
            # - Set the variabel used to signal correct date to TRUE.
            $ValidDate = $true

            }
        # - If the tested date doesnt meet the conditions in the IF-statement above, run the script block.
        else
            {
            # - Set the variabel used to signal correct date to FALSE.
            $ValidDate = $false

            }

        }
    # - If the date doesnt consist of 8 digits, run the script block.
    else
        {
        # - Set the variabel used to signal correct date to FALSE.
        $ValidDate = $false
        }
  # - Return the valid date to the function-calling script block.
  return $ValidDate

  }

# - Create a function that clears all the input boxes in the form.
function ClearOutput{

                # - Clear the user search textbox.
                $UserBoxSearch.text = $null 
                # - Disable the user dropdown-box.
                $UserBoxList.Enabled = $False

                # - Remove the authorization-status information box.
                $Form.Controls.Remove($AuthzBox)
                # - Clear the text in the user-status information boxes.
                $Statbox1.text = ""
                $Statbox2.text = ""
                $Statbox3.text = ""
                # - Set the textcolor of the user-status information boxes to blue.
                $Statbox1.forecolor = "blue"
                $Statbox2.forecolor = "blue"
                $Statbox3.forecolor = "blue"

                # - Remove the password-boxes.
                $Form.controls.remove($PWBOX)
                $Form.controls.remove($PWBOXTitle)

                # - Loop trough each of the operation-submit buttions and disable each one.
                foreach($button in $OKButtons)
                    {
                    $Button.enabled = $False

                    }


                }

# - Create the variables used for saving input-data, performing checks, operations and authorization.
New-variable Usr -scope global
New-variable PW -scope global
New-variable PWSEC -scope global
New-variable PWBOX -scope global
New-variable AuthzBOX -scope global
New-variable PWBOXTitle -scope global
New-variable Form -scope global
New-variable ADUsr -scope global
New-variable ExpDate -scope global


# - Fetch all user objects. This wil be used to build the user drop-down selector.
New-variable Users -scope global -value ((get-aduser -filter * -server $server -searchbase $OU).name)
           
  
# - Create the function that build the GUI for user-input.
function inputform
    {
    # - Import the .Net assemblies used for the main-form and style-properties.
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.web")
 
    New-variable OKButtons -scope global -value(@())

    # - Create a new variable for the form.
    $Form = New-Object System.Windows.Forms.Form
    # - Set form style-properties.
    $Form.width = 610
    $Form.height = 600        
    $Form.FormBorderStyle = 'FixedSingle'
    $Form.Text = 'AD Account Operations'
    $Form.BackColor = 'gray'
    $Form.MaximizeBox = $false
    $form.autoscroll = $true
    $FontAll = New-Object System.Drawing.Font("Arial",8,[System.Drawing.FontStyle]::Bold)
    $Form.Font = $FontAll
  
    # - Create a label for the app title.
    New-Variable -name Headlabel -scope global -value (new-object System.Windows.Forms.label)
    $Headlabel.Location = new-object System.Drawing.Size(12,12)
    $Headlabel.Size = new-object System.Drawing.Size(260,40)
    $Headlabel.text = "AD Account Operations"
    $Headlabel.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $Headlabel.ForeColor = "white"
    $Form.Controls.Add($Headlabel)

    # - Create a variable consiting of a Form-button for User-mode switch.
    New-Variable -name UserBtn -scope global -value (new-object System.Windows.Forms.RadioButton)
    $UserBtn.Location = new-object System.Drawing.Size(430,45)
    $UserBtn.Size = new-object System.Drawing.Size(70,30)
    $UserBtn.forecolor = "Black"
    $UserBtn.Text = "Users"
    $UserBtn.checked = $true
    $UserBtn.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    # - Load the button into the form.
    $Form.Controls.Add($UserBtn)  

    # - Create a variable consiting of a Form-button for Admin-mode switch.
    New-Variable -name AdmBtn -scope global -value (new-object System.Windows.Forms.RadioButton)
    $AdmBtn.Location = new-object System.Drawing.Size(500,45)
    $AdmBtn.Size = new-object System.Drawing.Size(85,30)
    $AdmBtn.checked = $false
    $AdmBtn.forecolor = "Silver"
    $AdmBtn.Text = "Admins"
    $AdmBtn.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    # - Load the button into the form.
    $Form.Controls.Add($AdmBtn) 
    # - Add a click event to the radio-button.
    $AdmBtn.Add_Click({
                     # - Fall back to checking user-button. Admin-button is a placeholder for future administration.
                     $UserBtn.checked = $true
                     $AdmBtn.checked = $false
                     })



    # - Create a new label used for when refreshing user-list. 
    New-Variable -name LoadingBox -scope global -value (new-object System.Windows.Forms.label)
    $LoadingBox.Location = new-object System.Drawing.Size(95,152)
    $LoadingBox.Size = new-object System.Drawing.Size(73,30)
    $LoadingBox.Font = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Bold)
    $LoadingBox.ForeColor = "DarkOrange"
    # - Load the loading-label into the form.
    $Form.Controls.Add($LoadingBox)

    # - Create a new label used for when checking admin authorization.
    set-Variable -name AuthzBox -scope global -value (new-object System.Windows.Forms.Label)
    $AuthzBox.Location = new-object System.Drawing.Size(216,105)
    $AuthzBox.Size = new-object System.Drawing.Size(300,20)
    $AuthzBox.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $AuthzBox.ForeColor = "DarkOrange"
    # - Load the auhtorization-label into the form.
    $Form.Controls.Add($AuthzBox)


    # - Create a variable consiting of a button for reloading user-list from AD.
    New-Variable -name UserRefresh -scope global -value (new-object System.Windows.Forms.Button)
    $UserRefresh.Location = new-object System.Drawing.Size(175,145)
    $UserRefresh.Size = new-object System.Drawing.Size(30,30)
    $UserRefresh.text = "↺"
    $UserRefresh.Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    $UserRefresh.ForeColor = "white"
    $UserRefresh.BackColor = "Dodgerblue"
    $UserRefresh.FlatStyle = "Flat"
    $UserRefresh.FlatAppearance.BorderColor = "blue"     
    # - Add a click-handler to the refresh-button.
    $UserRefresh.Add_Click({
                              # - Set the loading-label text.
                              $LoadingBox.text = "Loading.."
                              sleep -seconds 0.5
                              
                              # - Clear password and status boxes from any previous string.
                              ClearOutput
            
                              # - Fetch all user objects and load it into a variable.                             
                              set-variable Users -scope global -value ((get-aduser -filter * -server $server -searchbase $OU).name)
                              # - Clear the loading-label text.                              
                              $LoadingBox.text = ""

                             })
    # - Load the refresh-button into the form.
    $Form.Controls.Add($UserRefresh)

    # - Create a new textbox used for searching for users by full name.
    New-Variable -name UserBoxSearch -scope global -value (new-object System.Windows.Forms.TextBox)
    $UserBoxSearch.Location = new-object System.Drawing.Size(220,140)
    $UserBoxSearch.Size = new-object System.Drawing.Size(150,20)
    $UserBoxSearch.text = "Type name to search"
    $SearchPlaceHolder = $UserBoxSearch.text
    $UserBoxSearch.Font = New-Object System.Drawing.Font("Arial",7.5,[System.Drawing.FontStyle]::Bold)
    $UserBoxSearch.ForeColor = "RoyalBlue"

    # - Add a handler for pressing keys to the user-search box.
     $UserBoxSearch.Add_KeyDown({
                            # - If the pressed key is ENTER and searchbox contains text, run the script block.
                            if(($_.KeyCode -eq "Enter") -and ("$(($UserBoxSearch).text)"))
                                {
                                # - Run the function that searches for users based on the search-string input.
                                SearchUsers "$(($UserBoxSearch).text)"
                                }

                             }) 

    # - Add a click-handler to the user search-box.
    $UserBoxSearch.Add_Click({
                            # - Clear output and display execution-status.
                            ClearOutput

                            })

    # - Create a new button for searching users.
    New-Variable -name UserSearchBtn -scope global -value (new-object System.Windows.Forms.Button)
    $UserSearchBtn.Location = new-object System.Drawing.Size(370,140)
    $UserSearchBtn.Size = new-object System.Drawing.Size(70,20)
    $UserSearchBtn.text = "Search"
    $UserSearchBtn.Font = New-Object System.Drawing.Font("Arial",7.5,[System.Drawing.FontStyle]::Bold)
    $UserSearchBtn.ForeColor = "Black"
    $UserSearchBtn.BackColor = "White"

    # - Add a text changed-handler to the user-search button.
    $UserSearchBtn.Add_Click({
                             # - If the searchbox contains text, run the script block.
                            if(("$(($UserBoxSearch).text)"))
                                {
                                # - Run the function that searches for users based on the search-string input.
                                SearchUsers "$(($UserBoxSearch).text)"
                                }
                            }) 

    # - Create a new drop-down textbox that lists users based on search-string in the textbox above.
    New-Variable -name UserBoxList -scope global -value (new-object System.Windows.Forms.ComboBox)
    $UserBoxList.DropDownStyle = "DropDownList"
    $UserBoxList.Location = new-object System.Drawing.Size(220,155)
    $UserBoxList.Size = new-object System.Drawing.Size(150,20)
    $UserBoxList.Enabled = $False
    $UserBoxList.Add_SelectedValueChanged({
                                          # - Clear output and display execution-status.
                                           $Form.Controls.Add($StatBoxPre)
                                           $StatBoxPre.text = "Checking status.."
                                           # - Set restriction-trigger value to its initial value FALSE.
                                           $RestCheck = $False
                                           $PWChange = $False
                                           $StatUsr = (((get-variable -name "UserBoxList").Value.text))
                                           $Date = Get-date

                                           set-variable ADUsr -scope global -value (get-aduser -filter {name -eq $StatUsr} -Server $server -Properties pwdlastset,enabled,PasswordExpired,AccountLockoutTime,AccountExpires,description)
                                           
                                           # - Set expiration-date variable to it's intitial value of NULL.
                                           set-variable expdate -scope global -value ($NULL) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                           
                                           
                                           # - Test if account-expiration date is set, if so, set the ExpDate-variable.
                                           if(($ADUsr.AccountExpires -ne "9223372036854775807") -and ($ADUsr.AccountExpires -ne "0"))
                                                {
                                                try
                                                    {
                                                    set-variable expdate -scope global -value ([datetime]::FromFileTime(($ADUsr.AccountExpires))) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                                    }
                                                catch
                                                    {
                                                    set-variable expdate -scope global -value ([datetime]::FromFileTime(($ADUsr.AccountExpires))) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                                    
                                                    }
                                                }


                                        # - Check if any type relevant account restriction, or other type of limitations from the user variables, and output in the window.
                                        ## - The checks and outputs are arranged by importance, with the most important information at the top.
                                        $statbox1.text = ""
                                        $statbox2.text = ""
                                        $statbox3.text = ""
                                        If(($ADUsr.enabled) -eq $false)
                                            {
                                            if($ADUsr.Description -match $InactivityStampRegEx)
                                                {
                                                $Form.Controls.Remove($StatBoxPre)
                                                $TimeStamp = $ADUsr.Description | select-string -Pattern "(\d){8}" -AllMatches | %{$_.matches.value | where {$_}}                              
                                                $StatBox1.text = "Inactive $($TimeStamp)"  
                                                $statbox1.forecolor = "Yellow"
                                                $RestCheck = $True
                                                
                                                }
                                            elseif($ADUsr.Description -match $DisableStampRegEx)
                                                {
                                                
                                                $Form.Controls.Remove($StatBoxPre)
                                                $TimeStamp = $ADUsr.Description | select-string -Pattern "(\d){8}" -AllMatches | %{$_.matches.value | where {$_}} 
                                                $StatBox1.text = "Disabled $($TimeStamp)"  
                                                $statbox1.forecolor = "Red"
                                                $RestCheck = $True                                               
                                                }
                                            else
                                                {
                                                
                                                $Form.Controls.Remove($StatBoxPre)
                                                $StatBox1.text = "Disabled!"  
                                                $statbox1.forecolor = "Red"
                                                $RestCheck = $True                                                
                                                }
                                            }
                                        If(($ADUsr.pwdlastset) -eq "0")
                                            {
                                            if(($StatBox1.text))
                                              {
                                              $Form.Controls.Remove($StatBoxPre)
                                              $StatBox2.text = "Change password!"
                                              $PWChange = $True 
                                              $statbox2.forecolor = "Red"
                                              $RestCheck = $True
                                              }
                                            else
                                                {
                                                $Form.Controls.Remove($StatBoxPre)
                                                $StatBox1.text = "Change password!" 
                                                $PWChange = $True
                                                $statbox1.forecolor = "Red"
                                                $RestCheck = $True
                                                }

                                            }
                                          If(($ADUsr.AccountLockoutTime))
                                                {                                                
                                                $TodayDate = get-date -Hour 00 -Minute 00 -Second 00
                                                if($TodayDate -gt ($ADUsr.AccountLockoutTime))
                                                    {
                                                    $LockoutDisp = get-date ($ADUsr.AccountLockoutTime) -Format yyyyMMdd
                                                    }
                                                else
                                                    {
                                                    $LockoutDisp = get-date ($ADUsr.AccountLockoutTime) -Format HH:mm
                                                    }
                                                if(($StatBox1.text))
                                                    {
                                                    if(($StatBox2.text))
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $StatBox3.text = "Locked $LockoutDisp"
                                                        $statbox3.forecolor = "Red"
                                                        $RestCheck = $True
                                                        }
                                                    else
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $StatBox2.text = "Locked $LockoutDisp"
                                                        $statbox2.forecolor = "Red"
                                                        $RestCheck = $True
                                                        }
                                                  
                                                    }
                                                  else
                                                    {
                                                    $Form.Controls.Remove($StatBoxPre)
                                                    $StatBox1.text = "Locked $LockoutDisp"
                                                    $statbox1.forecolor = "Red"
                                                    $RestCheck = $True

                                                    }

         
                                                }

                                           If($ExpDate -and ($ExpDate -lt $Date))
                                                {
                                                $DispExpDate = get-date $ExpDate -Format yyyyMMdd                
                                                if(($statbox1.text))
                                                    {
                                                    if(($statbox2.text))
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $StatBox3.text = "+Expired $DispExpDate"
                                                        $StatBox3.forecolor = "Blue"
                                                        $RestCheck = $True
                                                        }
                                                    else
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $statbox2.text = "+Expired $DispExpDate"
                                                        $statbox2.forecolor = "Blue"
                                                        $RestCheck = $True
                                                        }
                                                    }
                                                else
                                                    {
                                                    $Form.Controls.Remove($StatBoxPre)
                                                    $StatBox1.text = "Expired $DispExpDate"
                                                    $StatBox1.forecolor = "Blue"
                                                    $RestCheck = $True
                                                    }
                                                
                                                }
                                           elseIf($ExpDate)
                                                {
                                                $DispExpDate = get-date $ExpDate -Format yyyyMMdd                
                                                if(($statbox1.text))
                                                    {
                                                    if(($statbox2.text))
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $StatBox3.text = "Expires $DispExpDate"
                                                        $StatBox3.forecolor = "LawnGreen"
                                                        $RestCheck = $True
                                                        }
                                                    else
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $statbox2.text = "Expires $DispExpDate"
                                                        $statbox2.forecolor = "LawnGreen"
                                                        $RestCheck = $True
                                                        }
                                                    }
                                                else
                                                    {
                                                    $Form.Controls.Remove($StatBoxPre)
                                                    $StatBox1.text = "Expires $DispExpDate"
                                                    $StatBox1.forecolor = "LawnGreen"
                                                    $RestCheck = $True
                                                    }
                                                
                                                }
                                         

                                            If((($ADUsr.PasswordExpired) -eq "0") -and ($PWChange -eq $False))
                                                {
                                                if(($statbox1.text))
                                                    {
                                                    if(($statbox2.text))
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $StatBox3.text = "+Password expired"
                                                        $StatBox3.forecolor = "Blue"
                                                        $RestCheck = $True
                                                        }
                                                    else
                                                        {
                                                        $Form.Controls.Remove($StatBoxPre)
                                                        $StatBox2.text = "+Password expired"
                                                        $StatBox2.forecolor = "Blue"
                                                        $RestCheck = $True
                                                        }
                                                    }
                                                else
                                                    {
                                                    $Form.Controls.Remove($StatBoxPre)
                                                    $StatBox1.text = "Password expired"
                                                    $StatBox1.forecolor = "Blue"
                                                    $RestCheck = $True
                                                    }
                                                }
                                            if($RestCheck -eq $False)                                           

                                                {
                                                $Form.Controls.Remove($StatBoxPre)
                                                $StatBox1.forecolor = "LawnGreen" 
                                                $StatBox1.text = "No restrictions"

                                                }
                                            # - Loop trough each operation-submit button, and enable each one.
                                            foreach($button in $OKButtons)
                                                {
                                                $Button.enabled = $True

                                                }
           
                                            
                                           })

    # - Create a border for the user input field-area.
    New-Variable -name BorL -scope global -value (new-object System.Windows.Forms.Label)
    $BorL.BackColor = "DodgerBlue"
    $BorL.ForeColor = "DodgerBlue"
    $BorL.Location = new-object System.Drawing.Size(218,138)
    $BorL.Size = new-object System.Drawing.Size(2,42)

    # - Create a border for the user input field-area.
    New-Variable -name BorR -scope global -value (new-object System.Windows.Forms.Label)
    $BorR.BackColor = "DodgerBlue"
    $BorR.ForeColor = "DodgerBlue"
    $BorR.Location = new-object System.Drawing.Size(370,160)
    $BorR.Size = new-object System.Drawing.Size(2,18)

    # - Create a border for the user input field-area.
    New-Variable -name BorEdgeR -scope global -value (new-object System.Windows.Forms.Label)
    $BorEdgeR.BackColor = "DodgerBlue"
    $BorEdgeR.ForeColor = "DodgerBlue"
    $BorEdgeR.Location = new-object System.Drawing.Size(440,138)
    $BorEdgeR.Size = new-object System.Drawing.Size(2,24)

    # - Create a border for the user input field-area.
    New-Variable -name BorEdgeB -scope global -value (new-object System.Windows.Forms.Label)
    $BorEdgeB.BackColor = "DodgerBlue"
    $BorEdgeB.ForeColor = "DodgerBlue"
    $BorEdgeB.Location = new-object System.Drawing.Size(370,160)
    $BorEdgeB.Size = new-object System.Drawing.Size(70,2)

    # - Create a border for the user input field-area.
    New-Variable -name BorT -scope global -value (new-object System.Windows.Forms.Label)
    $BorT.BackColor = "DodgerBlue"
    $BorT.ForeColor = "DodgerBlue"
    $BorT.Location = new-object System.Drawing.Size(218,138)
    $BorT.Size = new-object System.Drawing.Size(224,2)

    # - Create a border for the user input field-area.
    New-Variable -name BorB -scope global -value (new-object System.Windows.Forms.Label)
    $BorB.BackColor = "DodgerBlue"
    $BorB.ForeColor = "DodgerBlue"
    $BorB.Location = new-object System.Drawing.Size(218,178)
    $BorB.Size = new-object System.Drawing.Size(154,2)
  

    # - Load the user search-box, dropdown-box and borders into the form.
    $Form.Controls.Add($UserBoxSearch)
    $Form.Controls.Add($UserBoxList)
    $Form.Controls.Add($UserSearchBtn)
    $Form.Controls.Add($BorL)
    $Form.Controls.Add($BorR)
    $Form.Controls.Add($BorEdgeR)
    $Form.Controls.Add($BorEdgeB)
    $Form.Controls.Add($BorT)
    $Form.Controls.Add($BorB)

    # - Create a variable consiting of a Form-label for the password-string title.
    $PWBOXTitle = new-object System.Windows.Forms.label  
    $PWBOXTitle.Location = new-object System.Drawing.Size(115,191)
    $PWBOXTitle.Size = new-object System.Drawing.Size(104,28)
    $PWBOXTitle.font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $PWBOXTitle.ForeColor = "white"
    $Form.Controls.Add($PWBOXTitle) 

    # - Create a variable consiting of a Form-textbox for prompting the password-string. Set it to read-only. 
    $PWBOX = new-object System.Windows.Forms.textbox  
    $PWBOX.Location = new-object System.Drawing.Size(220,188)
    $PWBOX.Size = new-object System.Drawing.Size(150,30)
    $PWBOX.font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $PWBOX.ForeColor = "blue"
    $PWBOX.ReadOnly = $True

    # - Create a variable consiting of a Form-label for prompting the user-status in.
    $StatBoxPre = new-object System.Windows.Forms.label  
    $StatBoxPre.Location = new-object System.Drawing.Size(20,105)
    $StatBoxPre.Size = new-object System.Drawing.Size(173,20)
    $StatBoxPre.font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $StatBoxPre.ForeColor = "DarkOrange"
    $StatBoxPre.text = ""


      # - Create a variable consiting of a Form-label for prompting the user-status in.
    $StatBox1 = new-object System.Windows.Forms.label  
    $StatBox1.Location = new-object System.Drawing.Size(230,105)
    $StatBox1.Size = new-object System.Drawing.Size(173,20)
    $StatBox1.font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $StatBox1.ForeColor = "blue"
    $StatBox1.text = ""
    $Form.Controls.Add($StatBox1)

    # - Create a variable consiting of a Form-label for prompting the user-status in.
    $Statbox2 = new-object System.Windows.Forms.label  
    $Statbox2.Location = new-object System.Drawing.Size(400,105)
    $Statbox2.Size = new-object System.Drawing.Size(200,20)
    $Statbox2.font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $Statbox2.ForeColor = "blue"
    $Statbox2.text = ""
    $Form.Controls.Add($Statbox2)
 


     # - Create a variable consiting of a Form-label for prompting the user-status in.
    $StatBox3 = new-object System.Windows.Forms.label  
    $StatBox3.Location = new-object System.Drawing.Size(20,105)
    $StatBox3.Size = new-object System.Drawing.Size(210,20)
    $StatBox3.font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
    $StatBox3.ForeColor = "blue"
    $StatBox3.text = ""
    $Form.Controls.Add($StatBox3)
 

    # - Create a submit-button for enabling users.
    $OKButtonRecover = new-object System.Windows.Forms.Button
    $OKButtonRecover.Location = new-object System.Drawing.Size(30,220)
    $OKButtonRecover.Size = new-object System.Drawing.Size(100,40)
    $OKButtonRecover.Text = "Recover"
    $OKButtonRecover.BackColor = "DodgerBlue"
    $OKButtonRecover.ForeColor = "white"
    $OKButtonRecover.FlatStyle = "Flat"
    $OKButtonRecover.FlatAppearance.BorderColor = "blue"   
    $OKButtonRecover.enabled = $False
    $OkButtons += $OKButtonRecover
   
    # - Add a click handler to the recover-button.
    $OKButtonRecover.Add_Click({                         

                        # - Clear password and status boxes from any previous string.
                        ClearOutput
                        # - Set the user and password variables and encrypt the password string into a separate variable.
                        set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global         

                                             
                        # - Check if the selected-user variable contains data.
                        if($Usr)
                            { 
                            # - Prompt question about enforcing password change.
                            $ForcePWChangeTag = $Null
                            $ForcePWChangeTag = [System.Windows.Forms.MessageBox]::Show('Do you want to enforce a change of the new password?','Confirm deletion','YesNo','Info') 
                            # - Run the authoriation function.
                            AuthzFunc  
                            # - Set the password variables.
                            set-variable -name PW -value "PW$(( [char[]]([char]97..[char]122) + [char[]]([char]65..[char]90) + ([char[]]([char]97..[char]122)) + 0..9 | sort {Get-Random})[0..2] -join '')" -Scope global
                            set-variable -name PWSEC -value (ConvertTo-SecureString $pw -AsPlainText -Force) -scope global 
                            # - Set the logging date-varaible.
                            $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"           
                            # - Save the name of the user and the password hash to the input-file, for the back-end script.
                            "$($Usr)&&&$(ConvertFrom-SecureString $PWSEC -Key $aes.key)&&&$ForcePWChangeTag&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFileRecover                     
                            
                            # - Prompt the password in the app
                            $PWBOX.text = "$($PW)"
                            $Form.Controls.Add($PWBOXTitle)
                            $PWBOXTitle.text = "PASSWORD"
                            $Form.Controls.Add($PWBOX)

                 
                            clear-variable Usr -scope global
                            clear-variable PW -scope global
                            clear-variable PWSEC -scope global 
                              
                            # - Clear the user search-box.
                            $UserBoxSearch.text = $null 
                            # - Clear the user dropdown-box.
                            $UserBoxList.items.Clear()
                            }                         
                        })

    # - Load the recover-button into the form.
    $form.Controls.Add($OKButtonRecover)
    

    # - Create a forms-button for the disable-button.
    $OKButtonDisable = new-object System.Windows.Forms.Button
    $OKButtonDisable.Location = new-object System.Drawing.Size(140,220)
    $OKButtonDisable.Size = new-object System.Drawing.Size(100,40)
    $OKButtonDisable.Text = "Disable"
    $OKButtonDisable.BackColor = "DodgerBlue"
    $OKButtonDisable.ForeColor = "White"
    $OKButtonDisable.FlatStyle = "Flat"
    $OKButtonDisable.FlatAppearance.BorderColor = "blue"  
    $OKButtonDisable.enabled = $False
    $OkButtons += $OKButtonDisable
   
    # - Add a click-handler to the disable-button. 
    $OKButtonDisable.Add_Click({ 
                                # - Clear password and status boxes from any previous string.
                                ClearOutput
                                # - Check if a user is selected.
                                if(((get-variable -name "UserBoxList").Value.text))
                                    {
                                    # - Run the authoriation function.
                                    AuthzFunc   
                                        
                                
                                    # - Set the user variable.                                    
                                    set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global
                                    # - Set the logging date-varaible.
                                    $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"  
                                    # - Save the name of the user to the input-file, for the back-end script.
                                    "$($Usr)&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFileDisable                            
                                    clear-variable -name Usr -Scope global 
                                    write-host "Account disabled!"
                                    # - Clear the user search-box.
                                    $UserBoxSearch.text = $null 
                                    # - Clear the user dropdown-box.
                                    $UserBoxList.items.Clear()
                                    }                               
                        })

    # - Load the disable-button into the form.
    $form.Controls.Add($OKButtonDisable)

    # - Create a forms-button for the unlock-button.
    $OKButtonUnlock = new-object System.Windows.Forms.Button    
    $OKButtonUnlock.Location = new-object System.Drawing.Size(250,220)
    $OKButtonUnlock.Size = new-object System.Drawing.Size(100,40)
    $OKButtonUnlock.Text = "Unlock"
    $OKButtonUnlock.BackColor = "DodgerBlue"
    $OKButtonUnlock.ForeColor = "White"
    $OKButtonUnlock.FlatStyle = "Flat"
    $OKButtonUnlock.FlatAppearance.BorderColor = "blue"  
    $OKButtonUnlock.enabled = $False
    $OkButtons += $OKButtonUnlock

    # - Add a click-handler to the unlock-button. It will load the string of selected user name, into a variable.
    $OKButtonUnlock.Add_Click({                         
                            # - Clear password and status boxes from any previous string.
                            ClearOutput
                            # - Set the user variable, save it to the input-file for the back-end script, write status output and clear the user variable.                                          
                            set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global
                            if($Usr)
                                {
                                # - Run the authoriation function.
                                AuthzFunc
                                # - Set the logging date-varaible.        
                                $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"  
                                # - Save the name of the user to the input-file, for the back-end script. 
                                "$($Usr)&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFileUnlock                            
                                clear-variable -name Usr -Scope global
                                write-host "Account unlocked!"
                                # - Clear the user search-box.
                                $UserBoxSearch.text = $null 
                                # - Clear the user dropdown-box.
                                $UserBoxList.items.Clear()
                                }
                              
                        })

    # - Load the unlock-button into the form.
    $form.Controls.Add($OKButtonUnlock)
    
    # - Create a forms-button for the enforce password change-button.
    $OKButtonPWChange = new-object System.Windows.Forms.Button
    $OKButtonPWChange.Location = new-object System.Drawing.Size(360,220)
    $OKButtonPWChange.Size = new-object System.Drawing.Size(100,40)
    $OKButtonPWChange.Text = "Force PW-reset"
    $OKButtonPWChange.BackColor = "DodgerBlue"
    $OKButtonPWChange.ForeColor = "White"
    $OKButtonPWChange.FlatStyle = "Flat"
    $OKButtonPWChange.FlatAppearance.BorderColor = "blue"  
    $OKButtonPWChange.enabled = $False
    $OkButtons += $OKButtonPWChange

    # - Add a click-handler to the enforce password change-button.
    $OKButtonPWChange.Add_Click({ 
                                # - Clearpassword and status boxes from any previous string.
                                ClearOutput

                                # - Check if a user is selected.
                                if(((get-variable -name "UserBoxList").Value.text))
                                    {
                                    # - Run the authoriation function.
                                    AuthzFunc                                        
                                
                                    # - Set the user variable.                                   
                                    set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global
                                    # - Set the logging date-varaible.
                                    $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"  
                                    # - Save the name of the user to the input-file, for the back-end script.
                                    "$($Usr)&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFileEnfPWChange                            
                                    clear-variable -name Usr -Scope global 
                                    write-host "Password change enforced on account!"
                                    # - Clear the user search-box.
                                    $UserBoxSearch.text = $null 
                                    # - Clear the user dropdown-box.
                                    $UserBoxList.items.Clear()
                                    }                               
                        })

    # - Load the enforce password change-button into the form.
    $form.Controls.Add($OKButtonPWChange)


   # - Create a forms-button for the reset-button.
    $OKButtonPWReset = new-object System.Windows.Forms.Button
    $OKButtonPWReset.Location = new-object System.Drawing.Size(470,220)
    $OKButtonPWReset.Size = new-object System.Drawing.Size(100,40)
    $OKButtonPWReset.Text = "Reset PW"
    $OKButtonPWReset.BackColor = "DodgerBlue"
    $OKButtonPWReset.ForeColor = "White"
    $OKButtonPWReset.FlatStyle = "Flat"
    $OKButtonPWReset.FlatAppearance.BorderColor = "blue" 
    $OKButtonPWReset.enabled = $False
    $OkButtons += $OKButtonPWReset

    # - Add a click-handler to the reset-button. It will load the string of selected user name and password, into new variables.
    $OKButtonPWReset.Add_Click({ 

                        # - Set variable used for each reset-operation.
                        set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global
                        
                        # - If the variable for user name contains data, run the script block.
                        if($Usr)
                            {        

                            
                            # - Prompt question about enforcing password change.
                            $ForcePWChangeTag = $Null
                            $ForcePWChangeTag = [System.Windows.Forms.MessageBox]::Show('Do you want to enforce a change of the new password AS WELL?','Force PW-reset','YesNo','Info')
                            # - Clear password and status boxes from any previous string.
                            ClearOutput
                            # - Set the password variable.         
                            set-variable -name PW -value "PW$(( [char[]]([char]97..[char]122) + [char[]]([char]65..[char]90) + ([char[]]([char]97..[char]122)) + 0..9 | sort {Get-Random})[0..2] -join '')" -Scope global
                            set-variable -name PWSEC -value (ConvertTo-SecureString $pw -AsPlainText -Force) -scope global 
                            # - Run the authoriation function.
                            AuthzFunc
                            # - Set the variable for logging-date.
                            $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"  
                            # - Output the name of the user and password, into the input-file used by the back-end script.
                            "$($Usr)&&&$(ConvertFrom-SecureString $PWSEC -Key $aes.key)&&&$ForcePWChangeTag&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFilePWRes


                            # - Prompt the password in the app.
                            $PWBOX.text = "$($PW)"
                            $Form.Controls.Add($PWBOXTitle)
                            $PWBOXTitle.text = "PASSWORD"
                            $Form.Controls.Add($PWBOX)

                            # - Clear the variables used for user name and password.
                            clear-variable Usr -scope global
                            clear-variable PW -scope global
                            clear-variable PWSEC -scope global 
                                                  
                            # - Clear the user search-box.
                            $UserBoxSearch.text = $null 
                            # - Clear the user dropdown-box.
                            $UserBoxList.items.Clear()    
                            }

                                
                        })

    # - Load the reset-button into the form.
    $form.Controls.Add($OKButtonPWReset)
  
    # - Create a submit-button for deleting users.
    $OKButtonDelete = new-object System.Windows.Forms.Button
    $OKButtonDelete.Location = new-object System.Drawing.Size(30,282)
    $OKButtonDelete.Size = new-object System.Drawing.Size(100,40)
    $OKButtonDelete.Text = "Delete"
    $OKButtonDelete.BackColor = "#FF5733"
    $OKButtonDelete.ForeColor = "White"
    $OKButtonDelete.FlatStyle = "Flat"
    $OKButtonDelete.FlatAppearance.BorderColor = "blue" 
    $OKButtonDelete.enabled = $False
    $OkButtons += $OKButtonDelete

    # - Add a click handler to the delete-button.
    $OKButtonDelete.Add_Click({                         

                        # - Load the name of the user into a separate variable.
                        set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global    
  
                        # - Check if the selected-user variable contains data.
                        if($Usr)
                            { 
                            $DeleteConfirm = $Null
                            $DeleteConfirm = [System.Windows.Forms.MessageBox]::Show('Are you sure you want to delete the selected users?','Confirm deletion','YesNo','Warning')
                            if($DeleteConfirm -eq "Yes")
                                {
                                # - Clear password and status boxes from any previous string.
                                ClearOutput
                                # - Run the authoriation function.
                                AuthzFunc  
                                # - Set the logging date-varaible.
                                $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"            
                                # - Save the name of the user to the input-file, for the back-end script.
                                "$($Usr)&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFileDelete                      
                 
                                clear-variable Usr -scope global
                                write-host "Account deleted!"
                                # - Clear the user search-box.
                                $UserBoxSearch.text = $null 
                                # - Clear the user dropdown-box.
                                $UserBoxList.items.Clear()
                                }
                            }                         
                        })

    # - Load the delete-button into the form.
    $form.Controls.Add($OKButtonDelete)
      
    # - Create a left-border for the date input-area.
    New-Variable -name DateBorL -scope global -value (new-object System.Windows.Forms.Label)
    $DateBorL.BackColor = "white"
    $DateBorL.ForeColor = "white"
    $DateBorL.Location = new-object System.Drawing.Size(181,280)
    $DateBorL.Size = new-object System.Drawing.Size(2,228)

    # - Create a right-border for the date input-area.
    New-Variable -name DateBorR -scope global -value (new-object System.Windows.Forms.Label)
    $DateBorR.BackColor = "white"
    $DateBorR.ForeColor = "white"
    $DateBorR.Location = new-object System.Drawing.Size(405,280)
    $DateBorR.Size = new-object System.Drawing.Size(2,228)

    # - Create a top-border for the date input-area.
    New-Variable -name DateBorT -scope global -value (new-object System.Windows.Forms.Label)
    $DateBorT.BackColor = "white"
    $DateBorT.ForeColor = "white"
    $DateBorT.Location = new-object System.Drawing.Size(181,278)
    $DateBorT.Size = new-object System.Drawing.Size(226,2)

    # - Create a bottom-border for the date input-area.
    New-Variable -name DateBorB -scope global -value (new-object System.Windows.Forms.Label)
    $DateBorB.BackColor = "white"
    $DateBorB.ForeColor = "white"
    $DateBorB.Location = new-object System.Drawing.Size(181,507)
    $DateBorB.Size = new-object System.Drawing.Size(226,2)
  
    # - Load the date-borders into the form.
    $form.Controls.Add($DateBorL)
    $form.Controls.Add($DateBorR)
    $form.Controls.Add($DateBorT)
    $form.Controls.Add($DateBorB)



    # - Create a variable consiting of calendar-box for the date-string.
    New-Variable -name DateBox -scope global -value (new-object System.Windows.Forms.MonthCalendar)
    $DateBox.Location = new-object System.Drawing.Size(202,285)
    $DateBox.Size = New-object System.Drawing.Size(100,50)
    # - Load the textbox into the form.
    $Form.Controls.Add($DateBox) 


    # - Create a forms-button for the setting a expiration-date.
    $OKButtonDate = new-object System.Windows.Forms.Button
    $OKButtonDate.Location = new-object System.Drawing.Size(250,455)
    $OKButtonDate.Size = new-object System.Drawing.Size(100,40)
    $OKButtonDate.Text = "Set expiration"
    $OKButtonDate.BackColor = "DodgerBlue"
    $OKButtonDate.enabled = $False
    $OKButtonDate.ForeColor = "White"
    $OKButtonDate.FlatStyle = "Flat"
    $OKButtonDate.FlatAppearance.BorderColor = "blue" 
    $OkButtons += $OKButtonDate
   
    # - Add a click-handler to the date-button. It will load the string of selected user name, into new variables.
    $OKButtonDate.Add_Click({ 
                       
                        # - Clear password and status boxes from any previous string.
                        ClearOutput
                        # - Set the variables for user name and expiration-date.
                        set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global         
                      
        
                        # - Set expiration-date variable to it's intitial value of NULL.
                        set-variable expdate -scope global -value ($NULL) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        try
                        {
                        set-variable ExpDate -scope global -value (get-date ($datebox.Selectionstart) -Format yyyy-MM-dd) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        }
                        catch
                        {
                        set-variable ExpDate -scope global -value (get-date ($datebox.Selectionstart) -Format yyyy-MM-dd) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        }
                        # - If the variable for user name and expiration date contains data, run the script block.
                        if(($Usr) -and ($ExpDate))
                            {                           

                            if((Verify-AccExpDate $ExpDate) -eq $true)
                                {
                                # - Run the authoriation function.
                                AuthzFunc
                                # - Set the logging date-varaible.
                                $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"    
                                # - Output the name of the user and expiration-date, into the input-file used by the back-end script.
                                "$($Usr)&&&$($ExpDate)&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFileDate
                                # - Clear the variables used for the user name and expiration-date.
                                clear-variable Usr -scope global
                                clear-variable ExpDate -scope global
                                # - Clear the date-textbox.
                                $Datebox.text = ""
                                write-host "Account expiration set!"

                                # - Clear the user search-box.
                                $UserBoxSearch.text = $null 
                                # - Clear the user dropdown-box.
                                $UserBoxList.items.Clear()          
                                }
                            else
                                {
                                $CurDate = (get-date).ToString("yyyyMMdd")
                                $MaxDate = (get-date).AddDays(($daterange | where {$_.name -eq "MaxDateAccountExp"}).days).ToString("yyyyMMdd")
                                write-host "Date must be equal/greater than $($CurDate) and no greater than $($MaxDate)!"
                                }           
                                                   

                            }

                                
                        })

    # - Load the date-button into the main-form.
    $form.Controls.Add($OKButtonDate)
    
    # - Create a forms-button for clearing account expiration-date.
    $OKButtonRemDate = new-object System.Windows.Forms.Button
    $OKButtonRemDate.Location = new-object System.Drawing.Size(250,520)
    $OKButtonRemDate.Size = new-object System.Drawing.Size(100,40)
    $OKButtonRemDate.Text = "Clear expiration"
    $OKButtonRemDate.BackColor = "DodgerBlue"
    $OKButtonRemDate.enabled = $False
    $OKButtonRemDate.ForeColor = "White"
    $OKButtonRemDate.FlatStyle = "Flat"
    $OKButtonRemDate.FlatAppearance.BorderColor = "blue" 
    $OkButtons += $OKButtonRemDate
   
    # - Add a click-handler to the clearing account expiration-date button. It will load the string of selected user name, into new variables.
    $OKButtonRemDate.Add_Click({ 
                       
                        # - Clear password and status boxes from any previous string.
                        ClearOutput
                        # - Set the variables for user name and expiration-date.
                        set-variable -name Usr -value (((get-variable -name "UserBoxList").Value.text)) -scope global         
                      

                        # - If the variable for user name contains data, run the script block.
                        if($Usr)
                            {                          

                            # - Run the authoriation function.
                            AuthzFunc
                            # - Set the logging date-varaible.
                            $TimeExec = get-date -Format "yyyy-MM-dd HH:mm"    
                            # - Output the name of the user, into the input-file used by the back-end script.
                            "$($Usr)&&&$($RunnerUPN)&&&$($TimeExec);" | out-file -Append -Encoding utf8 -Confirm:$false -FilePath $InputFilRemDate
                            # - Clear the variables used for the user name.
                            clear-variable Usr -scope global
                            clear-variable ExpDate -scope global

                            write-host "Account expiration cleared!"

                            # - Clear the user search-box.
                            $UserBoxSearch.text = $null 
                            # - Clear the user dropdown-box.
                            $UserBoxList.items.Clear()         
                             
                 

                            }

                                
                        })

    # - Load the clear expiration-date button into the main-form.
    $form.Controls.Add($OKButtonRemDate)


    # - Activate the form
    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog() 


   

    }
# - Run the form-function.
inputform


