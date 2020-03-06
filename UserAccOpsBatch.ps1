

<#

This script performs accounts operations based on input files.
It picks up the input-file from the UserAccOpsApp.
Set encryption key below and in UserAccOpsApp.

Author 
Josef Ereq


Version 1.2

#>

# - Specify path to the hashed AES encryption key and IV files. 
$aes.IV = Import-CliXml -Path "outputkeyIVhash.aeshash"
$aes.key = Import-CliXml -Path  "Outputkeyhash.aeshash"

# - Specify the directory path for the settings-file.
$ConfigPath = ".\AppADSettings.csv"

# - Specify the directory path for the log file.
$LogPath = (import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "LogPath"}).value

# - Set the variable for the data input-path.
$InputPath = (import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "OutputPath"}).value

# - Set the variable for which domain controller to fetch users from.
$Server = (import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "DomainController"}).value

# - Import list of attributes to clear when disabling or enabling a user.
$AttributeClearOnDisable = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AttributeClearOnDisable"}).value).Split(",")
$AttributeClearOnEnable = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AttributeClearOnEnable"}).value).Split(",")


# - Specify the home organizational unit for disabled and enabled user accounts.
$OUDisabledUserAccounts = (import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "DisabledUserAccounts"}).value
$OUEnabledUserAccounts = (import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "UserAccounts"}).value


# - Specify names for output files used for second stage of each account operation.
$AccEnable2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccEnable2ndBatchOutput"}).value)
$AccPWReset2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccPWReset2ndBatchOutput"}).value)
$AccUnlock2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccUnlock2ndBatchOutput"}).value)
$AccSetDate2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccSetDate2ndBatchOutput"}).value)
$AccClearDate2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccClearDate2ndBatchOutput"}).value)
$AccEnfPWChange2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccEnfPWChange2ndBatchOutput"}).value)
$AccDisable2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccDisable2ndBatchOutput"}).value)
$AccDelete2ndBatch = ((import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "AccDelete2ndBatchOutput"}).value)

# - Create a credential object for the service account that performs the account operations.
$cred = Import-CliXml -Path "upn+hash.cred"

# - Load todays date into  variable, in the specified format. It will be as for time-stamping disabled accounts.
$Date = get-date -Format yyyyMMdd

# - Build the description-stamp for when disabling users, based in input from the config-file.
$DabStamp = (import-csv $ConfigPath -Delimiter ";" | where {$_.type -eq "DisableStamp"}).value
$DabStampForm = $DabStamp -replace "(\133DISABLEDATE\135)",$date

# - Specify the name of the input-files for each account operation.
$InputfileDeleteAcc = "INPUT_DeleteUsrAcc.txt"
$InputfileDisableAcc = "INPUT_DisableUsrAcc.txt"
$InputfileEnfPWChange = "INPUT_EnfPWChange.txt"
$InputfileSetAccDate = "INPUT_SetUsrAccDate.txt"
$InputfileClearAccDate = "INPUT_ClearUsrAccDate.txt"
$InputfileUnlockAcc = "INPUT_UnlockUsrAcc.txt"
$InputfileAccPWReset = "INPUT_UserAccPWReset.txt"
$InputfileAccEnable = "INPUT_RecUsrAcc.txt"

# - Create a function for deleting accounts.
Function AccDelete()
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileDeleteAcc

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining name of users to disable.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $usr = $null
            $Usr = ($Entry -split "&&&")[0]

            # - Get the executing user-part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[1] 
        
            # - Get the time executed-part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[2] 

            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime
        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {
                # - Load the AD-user object into variable.
                $ADusr = $null
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server -Credential $Cred


                # - Delete the AD-user.
                $ADUsr | Remove-ADUser -server $server -confirm:$false -Credential $Cred

                }
            }
            if($AccDelete2ndBatch)
                {
                copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccDelete2ndBatch) 
                }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }
    }

# - Create a function for disabling accounts.
Function AccDisable()
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileDisableAcc

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining name of users to disable.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $usr = $null
            $Usr = ($Entry -split "&&&")[0]

            # - Get the executing user-part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[1] 

            # - Get the time executed-part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[2] 
        
            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime
        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {
        
                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server -Credential $Cred

                # - Disable the user account.
                $ADUsr | Disable-ADAccount -Server $server -Credential $Cred

                # - Append the disabling stamp on the user description.
                $ADUsr | Set-ADUser -server $server -Description "$DabStampForm" -Credential $Cred
                
                # - Loop trough each entry of attributes to clear when disabling a user, and clear that attribute.
                foreach($AttributeClear in $AttributeClearOnDisable)
                    {
                    $ADUsr | Set-ADUser -Server $Server -clear $AttributeClear -Credential $Cred
                    }
                
                # - Move the user acount to the OU for disabled user accounts.
                $ADUsr | Move-ADObject -Server $Server -TargetPath $OUDisabledUserAccounts -Credential $Cred

                }
            }
        if($AccDisable2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccDisable2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }
    }

# - Create a function for enforcing password-change on accounts.
Function AccEnfPWChange()
    {

    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileEnfPWChange 

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining name of users to enforce password change on.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {


            # - Get the user name-part in the loaded string.
            $usr = $null
            $Usr = ($Entry -split "&&&")[0]

            # - Get the executing user-part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[1] 

            # - Get the time executed-part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[2] 
        
            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime

        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {

                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server -Credential $Cred

                # - Enforce password change on the user account.
                $ADUsr | Set-aduser -ChangePasswordAtLogon $true -server $server -Credential $Cred

                }


            }
        if($AccEnfPWChange2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccEnfPWChange2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }

    }

# - Create a function for setting expiration-date on accounts.
Function AccSetDate()
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileSetAccDate

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining users.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $usr = $null
            $Usr = ($Entry -split "&&&")[0]
        
            # - Get the date-part in the loaded string.
            $ExpDate = $null
            $ExpDate = ($Entry -split "&&&")[1]

            # - Get the executing user-part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[2] 

            # - Get the time executed-part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[3] 

            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime

        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {

                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server -Credential $Cred

                # - Set expiration-date on the user.
                $ADUsr | Set-aduser -Server $server -AccountExpirationDate $ExpDate -Credential $cred

                }


            }
        if($AccSetDate2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccSetDate2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }

    }


# - Create a function for clearing expiration-date on accounts.
Function AccClearDate()
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileClearAccDate

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining users.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $usr = $null
            $Usr = ($Entry -split "&&&")[0]
        
            # - Get the executing user-part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[1] 

            # - Get the time executed-part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[2] 

            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime

        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {

                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server -Credential $Cred

                # - Set expiration-date on the user.
                $ADUsr | Clear-ADAccountExpiration -Server $server -Credential $cred

                }

            }
        if($AccClearDate2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccClearDate2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }

    }

# - Create a function for unlocking accounts.
Function AccUnlock()
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileUnlockAcc

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining name of users to disable.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $usr = $null
            $Usr = ($Entry -split "&&&")[0]

            # - Get the executing user-part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[1] 

            # - Get the time executed-part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[2] 

            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime

        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {

                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server -Credential $Cred

                # - Unlock the user account.
                $ADUsr | Unlock-ADAccount -Server $server -Credential $Cred

                }

            }

        if($AccUnlock2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccUnlock2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }
    }

# - Create a function for reseting password on accounts.
Function AccPWReset()
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileAccPWReset

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining users.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $Usr = $null
            $Usr = ($Entry -split "&&&")[0]
                
            # - Get the password-part in the loaded string.
            $PWBAT = $null
            $PWBAT = ($Entry -split "&&&")[1]

            # - Get the password-change-enforcement part in the loaded string.
            $EnforceChange = $null
            $EnforceChange = ($Entry -split "&&&")[2] 

            # - Get the executing user part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[3] 

            # - Get the time-executed part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[4] 

            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime
        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {
                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server

                # - Reset the password on the user.
                $ADUsr | Set-ADAccountPassword -Server $server -Reset -NewPassword (ConvertTo-SecureString $PWBAT -key $aes.key) -Credential $cred

                # - If the tag for enforcing password change is "Yes", run the script block that enforces user to change the password.
                if($EnforceChange -eq "Yes")
                    {
                    # - Enforce password change on the user account.
                    $ADUsr | Set-aduser -ChangePasswordAtLogon $true -server $server -Credential $Cred
                    }

                }
        
            }
        if($AccPWReset2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccPWReset2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }
    }


# - Create a function that enables the user in on-prem AD.
Function AccEnable
    {
    # - Load the name of the input file, into a separate variable.
    $InputFile = $InputfileAccEnable

    # - Check if the Input-file exists.
    $FileExist = Test-Path (join-path $InputPath $Inputfile)

    # - If the variable for testing existence of input-file is TRUE, then the file exists and procedd with running the script block.
    If($FileExist -eq $true)
        {
        # - Set the variable used for time-stamping the log-file.
        $FileDate = (get-date -Format yyyyMMdd_HHmmss)

        # - Build the name of the to-be-created work-file, based on the name of the input-file.
        $WorkFile = $InputFile -replace "INPUT_","Work_"
    
        # - Build the name of the to-be-created log-file, based on the timestamp and input-file.
        $LogFile = "Log_$($FileDate)_$($Inputfile)"

        # - Get the content of the work-file and load it into a new variable.
        $Entries = (Get-Content (join-path $InputPath $Inputfile)).Split(";")

        # - Rename the input-file to the new name for the work-file.
        rename-item -path (join-path $InputPath $Inputfile) -newname $WorkFile -force -Confirm:$false

        # - Remove empty strings in the variable cotaining users.
        $Entries = $Entries | where {$_}

        # - Run the script block for each string in the user-variable.
        foreach ($Entry in $Entries)
            {

            # - Get the user name-part in the loaded string.
            $Usr = $null
            $Usr = ($Entry -split "&&&")[0]
                
            # - Get the password-part in the loaded string.
            $PWBAT = $null
            $PWBAT = ($Entry -split "&&&")[1]

            # - Get the password-change-enforcement part in the loaded string.
            $EnforceChange = $null
            $EnforceChange = ($Entry -split "&&&")[2] 

            # - Get the executing user part in the loaded string.
            $RunningUsr = $null
            $RunningUsr = ($Entry -split "&&&")[3] 

            # - Get the time-executed part in the loaded string.
            $ExecTime = $null
            $ExecTime = ($Entry -split "&&&")[4] 

            # - Load the AD-user of the running user.
            $RunningADUsr = $null
            $RunningADUsr = get-aduser -server $server -filter {userprincipalname -eq $RunningUsr}

            # - Load the date of the input time-stamp into a variable.
            $RealExecTime = $null
            $RealExecTime = get-date $ExecTime
        
            # - Test that the running user exists and timestamp is valid. If so, run the script block.
            If($RunningADUsr -and $RealExecTime)
                {
                # - Load the AD-user object into variable.
                $ADUsr = get-aduser -filter {name -eq $usr} -server $server
                # - Loop trough each entry of attributes to clear when enabling a user, and clear that attribute.
                foreach($AttributeClear in $AttributeClearOnEnable)
                    {
                    $ADUsr | Set-ADUser -Server $Server -clear $AttributeClear -Credential $Cred
                    }

                # - Set the password on the user.
                $ADUsr | Set-ADAccountPassword -Server $server -Reset -NewPassword (ConvertTo-SecureString $PWBAT -key $aes.key) -Credential $cred

                # - Enable user and clear the description.
                $ADUsr | Set-ADUser -Server $Server -Enabled $true -Credential $cred
                $ADUsr | Set-ADUser -Server $Server -Clear {description} -Credential $cred
                            
                # - If the tag for enforcing password change is YES, run the script-block that enforces password change on the user.
                if($EnforceChange -eq "Yes")
                    {
                    # - Enforce password change on the user account.
                    $ADUsr | Set-aduser -ChangePasswordAtLogon $true -server $server -Credential $Cred
                    }
                # - Move the users to its home-OU.
                $ADUsr | Move-ADObject -Server $Server -TargetPath $OUEnabledUserAccounts -Credential $Cred                

                }
            }
        if($AccEnable2ndBatch)
            {
            copy-item (join-path $InputPath $WorkFile) (join-path $InputPath $AccEnable2ndBatch) 
            }
        # - Rename the work-file to the log file-name and move it to the log directory.
        rename-Item -path (join-path $InputPath $WorkFile) $LogFile -Force -Confirm:$false
        move-Item (join-path $InputPath $LogFile) -Destination $LogPath -Force -Confirm:$false
        }
    }

# - Run all the account operation-functions.
AccEnable
AccPWReset
AccUnlock
AccSetDate
AccClearDate
AccEnfPWChange
AccDisable
AccDelete
 

