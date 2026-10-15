# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-SHA512Hash
{
<#
    .SYNOPSIS
        Gets the SHA512 hash of the requested string.

    .DESCRIPTION
        Gets the SHA512 hash of the requested string.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER PlainText
        The plain text that you want the SHA512 hash for.

    .EXAMPLE
        Get-SHA512Hash -PlainText "Hello World"

        Returns back the string "2C74FD17EDAFD80E8447B0D46741EE243B7EB74DD2149A0AB1B9246FB30382F27E853D8585719E0E67CBDA0DAA8F51671064615D645AE27ACB15BFB1447F459B"
        which represents the SHA512 hash of "Hello World"

    .OUTPUTS
        System.String - A SHA512 hash of the provided string
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $PlainText
    )

    $sha512= New-Object -TypeName System.Security.Cryptography.SHA512CryptoServiceProvider
    $utf8 = New-Object -TypeName System.Text.UTF8Encoding
    return [System.BitConverter]::ToString($sha512.ComputeHash($utf8.GetBytes($PlainText))) -replace '-', ''
}


function Write-Log
{
<#
    .SYNOPSIS
        Writes logging information to screen and log file simultaneously.

    .DESCRIPTION
        Writes logging information to screen and log file simultaneously.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Message
        The message(s) to be logged. Each element of the array will be written to a separate line.

        This parameter supports pipelining but there are no
        performance benefits to doing so. For more information, see the .NOTES for this
        cmdlet.

    .PARAMETER Level
        The type of message to be logged.

    .PARAMETER Indent
        The number of spaces to indent the line in the log file.

    .PARAMETER Path
        The log file path.
        Defaults to $env:USERPROFILE\Documents\PowerShellForGitHub.log

    .PARAMETER Exception
        If present, the exception information will be logged after the messages provided.
        The actual string that is logged is obtained by passing this object to Out-String.

    .EXAMPLE
        Write-Log -Message "Everything worked." -Path C:\Debug.log

        Writes the message "Everything worked." to the screen as well as to a log file at "c:\Debug.log",
        with the caller's username and a date/time stamp prepended to the message.

    .EXAMPLE
        Write-Log -Message ("Everything worked.", "No cause for alarm.") -Path C:\Debug.log

        Writes the following message to the screen as well as to a log file at "c:\Debug.log",
        with the caller's username and a date/time stamp prepended to the message:

        Everything worked.
        No cause for alarm.

    .EXAMPLE
        Write-Log -Message "There may be a problem..." -Level Warning -Indent 2

        Writes the message "There may be a problem..." to the warning pipeline indented two spaces,
        as well as to the default log file with the caller's username and a date/time stamp
        prepended to the message.

    .EXAMPLE
        try { $null.Do() }
        catch { Write-Log -Message ("There was a problem.", "Here is the exception information:") -Exception $_ -Level Error }

        Logs the message:

        Write-Log : 2018-01-23 12:57:37 : dabelc : There was a problem.
        Here is the exception information:
        You cannot call a method on a null-valued expression.
        At line:1 char:7
        + try { $null.Do() } catch { Write-Log -Message ("There was a problem." ...
        +       ~~~~~~~~~~
            + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
            + FullyQualifiedErrorId : InvokeMethodOnNull

    .INPUTS
        System.String

    .NOTES
        The "LogPath" configuration value indicates where the log file will be created.
        The "" determines if log entries will be made to the log file.
           If $false, log entries will ONLY go to the relevant output pipeline.

        Note that, although this function supports pipeline input to the -Message parameter,
        there is NO performance benefit to using the pipeline. This is because the pipeline
        input is simply accumulated and not acted upon until all input has been received.
        This behavior is intentional, in order for a statement like:
            "Multiple", "messages" | Write-Log -Exception $ex -Level Error
        to make sense.  In this case, the cmdlet should accumulate the messages and, at the end,
        include the exception information.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "", Justification="We need to be able to access the PID for logging purposes, and it is accessed via a global variable.")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidOverwritingBuiltInCmdlets", "", Justification="Write-Log is an internal function being incorrectly exported by PSDesiredStateConfiguration.  See PowerShell/PowerShell#7209")]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]] $Message = @(),

        [ValidateSet('Error', 'Warning', 'Informational', 'Verbose', 'Debug')]
        [string] $Level = 'Informational',

        [ValidateRange(1, 30)]
        [Int16] $Indent = 0,

        [IO.FileInfo] $Path = (Get-GitHubConfiguration -Name LogPath),

        [System.Management.Automation.ErrorRecord] $Exception
    )

    begin
    {
        # Accumulate the list of Messages, whether by pipeline or parameter.
        $messages = @()
    }

    process
    {
        foreach ($m in $Message)
        {
            $messages += $m
        }
    }

    end
    {
        if ($null -ne $Exception)
        {
            # If we have an exception, add it after the accumulated messages.
            $messages += Out-String -InputObject $Exception
        }
        elseif ($messages.Count -eq 0)
        {
            # If no exception and no messages, we should early return.
            return
        }

        # Finalize the string to be logged.
        $finalMessage = $messages -join [Environment]::NewLine

        # Build the console and log-specific messages.
        $date = Get-Date
        $dateString = $date.ToString("yyyy-MM-dd HH:mm:ss")
        if (Get-GitHubConfiguration -Name LogTimeAsUtc)
        {
            $dateString = $date.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ssZ")
        }

        $consoleMessage = '{0}{1}' -f
            (" " * $Indent),
            $finalMessage

        if (Get-GitHubConfiguration -Name LogProcessId)
        {
            $maxPidDigits = 10 # This is an estimate (see https://stackoverflow.com/questions/17868218/what-is-the-maximum-process-id-on-windows)
            $pidColumnLength = $maxPidDigits + "[]".Length
            $logFileMessage = "{0}{1} : {2, -$pidColumnLength} : {3} : {4} : {5}" -f
                (" " * $Indent),
                $dateString,
                "[$global:PID]",
                $env:username,
                $Level.ToUpper(),
                $finalMessage
        }
        else
        {
            $logFileMessage = '{0}{1} : {2} : {3} : {4}' -f
                (" " * $Indent),
                $dateString,
                $env:username,
                $Level.ToUpper(),
                $finalMessage
        }

        # Write the message to screen/log.
        # Note that the below logic could easily be moved to a separate helper function, but a conscious
        # decision was made to leave it here. When this cmdlet is called with -Level Error, Write-Error
        # will generate a WriteErrorException with the origin being Write-Log. If this call is moved to
        # a helper function, the origin of the WriteErrorException will be the helper function, which
        # could confuse an end user.
        switch ($Level)
        {
            # Need to explicitly say SilentlyContinue here so that we continue on, given that
            # we've assigned a script-level ErrorActionPreference of "Stop" for the module.
            'Error'   { Write-Error $consoleMessage -ErrorAction SilentlyContinue }
            'Warning' { Write-Warning $consoleMessage }
            'Verbose' { Write-Verbose $consoleMessage }
            'Debug'   { Write-Debug $consoleMessage }
            'Informational'    {
                # We'd prefer to use Write-Information to enable users to redirect that pipe if
                # they want, unfortunately it's only available on v5 and above.  We'll fallback to
                # using Write-Host for earlier versions (since we still need to support v4).
                if ($PSVersionTable.PSVersion.Major -ge 5)
                {
                    Write-Information $consoleMessage -InformationAction Continue
                }
                else
                {
                    Write-InteractiveHost $consoleMessage
                }
            }
        }

        try
        {
            if (-not (Get-GitHubConfiguration -Name DisableLogging))
            {
                if ([String]::IsNullOrWhiteSpace($Path))
                {
                    Write-Warning 'Logging is currently enabled, however no path has been specified for the log file.  Use "Set-GitHubConfiguration -LogPath" to set the log path, or "Set-GitHubConfiguration -DisableLogging" to disable logging.'
                }
                else
                {
                    $logFileMessage | Out-File -FilePath $Path -Append -WhatIf:$false -Confirm:$false
                }
            }
        }
        catch
        {
            $output = @()
            $output += "Failed to add log entry to [$Path]. The error was:"
            $output += Out-String -InputObject $_

            if (Test-Path -Path $Path -PathType Leaf)
            {
                # The file exists, but likely is being held open by another process.
                # Let's do best effort here and if we can't log something, just report
                # it and move on.
                $output += "This is non-fatal, and your command will continue.  Your log file will be missing this entry:"
                $output += $consoleMessage
                Write-Warning ($output -join [Environment]::NewLine)
            }
            else
            {
                # If the file doesn't exist and couldn't be created, it likely will never
                # be valid.  In that instance, let's stop everything so that the user can
                # fix the problem, since they have indicated that they want this logging to
                # occur.
                throw ($output -join [Environment]::NewLine)
            }
        }
    }
}

$script:alwaysRedactParametersForLogging = @(
    'AccessToken' # Would be a security issue
)

$script:alwaysExcludeParametersForLogging = @(
)

function Write-InvocationLog
{
<#
    .SYNOPSIS
        Writes a log entry for the invoke command.

    .DESCRIPTION
        Writes a log entry for the invoke command.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER InvocationInfo
        The '$MyInvocation' object from the calling function.
        No need to explicitly provide this if you're trying to log the immediate function this is
        being called from.

    .PARAMETER RedactParameter
        An optional array of parameter names that should be logged, but their values redacted.

    .PARAMETER ExcludeParameter
        An optional array of parameter names that should simply not be logged.

    .EXAMPLE
        Write-InvocationLog -Invocation $MyInvocation

    .EXAMPLE
        Write-InvocationLog -Invocation $MyInvocation -ExcludeParameter @('Properties', 'Metrics')

    .NOTES
        The actual invocation line will not be _completely_ accurate as converted parameters will
        be in JSON format as opposed to PowerShell format.  However, it should be sufficient enough
        for debugging purposes.

        ExcludeParameter will always take precedence over RedactParameter.
#>
    [CmdletBinding()]
    param(
        [Management.Automation.InvocationInfo] $Invocation = (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly),

        [string[]] $RedactParameter,

        [string[]] $ExcludeParameter
    )

    $jsonConversionDepth = 20 # Seems like it should be more than sufficient

    # Build up the invoked line, being sure to exclude and/or redact any values necessary
    $params = @()
    foreach ($param in $Invocation.BoundParameters.GetEnumerator())
    {
        if ($param.Key -in ($script:alwaysExcludeParametersForLogging + $ExcludeParameter))
        {
            continue
        }

        if ($param.Key -in ($script:alwaysRedactParametersForLogging + $RedactParameter))
        {
            $params += "-$($param.Key) <redacted>"
        }
        else
        {
            if ($param.Value -is [switch])
            {
                $params += "-$($param.Key):`$$($param.Value.ToBool().ToString().ToLower())"
            }
            else
            {
                $params += "-$($param.Key) $(ConvertTo-Json -InputObject $param.Value -Depth $jsonConversionDepth -Compress)"
            }
        }
    }

    Write-Log -Message "[$($Invocation.MyCommand.Module.Version)] Executing: $($Invocation.MyCommand) $($params -join ' ')" -Level Verbose
}

function DeepCopy-Object
{
<#
    .SYNOPSIS
        Creates a deep copy of a serializable object.

    .DESCRIPTION
        Creates a deep copy of a serializable object.
        By default, PowerShell performs shallow copies (simple references)
        when assigning objects from one variable to another.  This will
        create full exact copies of the provided object so that they
        can be manipulated independently of each other, provided that the
        object being copied is serializable.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER InputObject
        The object that is to be copied.  This must be serializable or this will fail.

    .EXAMPLE
        $bar = DeepCopy-Object -InputObject $foo
        Assuming that $foo is serializable, $bar will now be an exact copy of $foo, but
        any changes that you make to one will not affect the other.

    .RETURNS
        An exact copy of the PSObject that was just deep copied.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "", Justification="Intentional.  This isn't exported, and needed to be explicit relative to Copy-Object.")]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $InputObject
    )

    $serialData = [System.Management.Automation.PSSerializer]::Serialize($InputObject, 64)
    return [System.Management.Automation.PSSerializer]::Deserialize($serialData)
}

function New-TemporaryDirectory
{
<#
    .SYNOPSIS
        Creates a new subdirectory within the users's temporary directory and returns the path.

    .DESCRIPTION
        Creates a new subdirectory within the users's temporary directory and returns the path.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .EXAMPLE
        New-TemporaryDirectory
        Creates a new directory with a GUID under $env:TEMP

    .OUTPUTS
        System.String - The path to the newly created temporary directory
#>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "", Justification="Methods called within here make use of PSShouldProcess, and the switch is passed on to them inherently.")]
    param()

    $parentTempPath = [System.IO.Path]::GetTempPath()
    $tempFolderPath = [String]::Empty
    do
    {
        $guid = [System.Guid]::NewGuid()
        $tempFolderPath = Join-Path -Path $parentTempPath -ChildPath $guid
    }
    while (Test-Path -Path $tempFolderPath -PathType Container)

    Write-Log -Message "Creating temporary directory: $tempFolderPath" -Level Verbose
    New-Item -ItemType Directory -Path $tempFolderPath
}

function Write-InteractiveHost
{
<#
    .SYNOPSIS
        Forwards to Write-Host only if the host is interactive, else does nothing.

    .DESCRIPTION
        A proxy function around Write-Host that detects if the host is interactive
        before calling Write-Host. Use this instead of Write-Host to avoid failures in
        non-interactive hosts.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .EXAMPLE
        Write-InteractiveHost "Test"
        Write-InteractiveHost "Test" -NoNewline -f Yellow

    .NOTES
        Boilerplate is generated using these commands:
        # $Metadata = New-Object System.Management.Automation.CommandMetaData (Get-Command Write-Host)
        # [System.Management.Automation.ProxyCommand]::Create($Metadata) | Out-File temp
#>

    [CmdletBinding(
        HelpUri='http://go.microsoft.com/fwlink/?LinkID=113426',
        RemotingCapability='None')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "", Justification="This provides a wrapper around Write-Host. In general, we'd like to use Write-Information, but it's not supported on PS 4.0 which we need to support.")]
    param(
        [Parameter(
            Position=0,
            ValueFromPipeline,
            ValueFromRemainingArguments)]
        [System.Object] $Object,

        [switch] $NoNewline,

        [System.Object] $Separator,

        [System.ConsoleColor] $ForegroundColor,

        [System.ConsoleColor] $BackgroundColor
    )

    begin
    {
        $hostIsInteractive = ([Environment]::UserInteractive -and
            ![Bool]([Environment]::GetCommandLineArgs() -like '-noni*') -and
            ((Get-Host).Name -ne 'Default Host'))
    }

    process
    {
        # Determine if the host is interactive
        if ($hostIsInteractive)
        {
            # Special handling for OutBuffer (generated for the proxy function)
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }

            Write-Host @PSBoundParameters
        }
    }
}

function Resolve-UnverifiedPath
{
<#
    .SYNOPSIS
        A wrapper around Resolve-Path that works for paths that exist as well
        as for paths that don't (Resolve-Path normally throws an exception if
        the path doesn't exist.)

    .DESCRIPTION
        A wrapper around Resolve-Path that works for paths that exist as well
        as for paths that don't (Resolve-Path normally throws an exception if
        the path doesn't exist.)

        The Git repo for this module can be found here: https://aka.ms/PowerShellForGitHub

    .EXAMPLE
        Resolve-UnverifiedPath -Path 'c:\windows\notepad.exe'

        Returns the string 'c:\windows\notepad.exe'.

    .EXAMPLE
        Resolve-UnverifiedPath -Path '..\notepad.exe'

        Returns the string 'c:\windows\notepad.exe', assuming that it's executed from
        within 'c:\windows\system32' or some other sub-directory.

    .EXAMPLE
        Resolve-UnverifiedPath -Path '..\foo.exe'

        Returns the string 'c:\windows\foo.exe', assuming that it's executed from
        within 'c:\windows\system32' or some other sub-directory, even though this
        file doesn't exist.

    .OUTPUTS
        [string] - The fully resolved path

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [string] $Path
    )

    process
    {
        $resolvedPath = Resolve-Path -Path $Path -ErrorVariable resolvePathError -ErrorAction SilentlyContinue

        if ($null -eq $resolvedPath)
        {
            Write-Output -InputObject ($resolvePathError[0].TargetObject)
        }
        else
        {
            Write-Output -InputObject ($resolvedPath.ProviderPath)
        }
    }
}

function Ensure-Directory
{
<#
    .SYNOPSIS
        A utility function for ensuring a given directory exists.

    .DESCRIPTION
        A utility function for ensuring a given directory exists.

        If the directory does not already exist, it will be created.

    .PARAMETER Path
        A full or relative path to the directory that should exist when the function exits.

    .NOTES
        Uses the Resolve-UnverifiedPath function to resolve relative paths.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "", Justification = "Unable to find a standard verb that satisfies describing the purpose of this internal helper method.")]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    try
    {
        $Path = Resolve-UnverifiedPath -Path $Path

        if (-not (Test-Path -PathType Container -Path $Path))
        {
            Write-Log -Message "Creating directory: [$Path]" -Level Verbose
            New-Item -ItemType Directory -Path $Path | Out-Null
        }
    }
    catch
    {
        Write-Log -Message "Could not ensure directory: [$Path]" -Level Error

        throw
    }
}

function Get-HttpWebResponseContent
{
<#
    .SYNOPSIS
        Returns the content that may be contained within an HttpWebResponse object.

    .DESCRIPTION
        Returns the content that may be contained within an HttpWebResponse object.

        This would commonly be used when trying to get the potential content
        returned within a failing WebResponse.  Normally, when you call
        Invoke-WebRequest, it returns back a BasicHtmlWebResponseObject which
        directly contains a Content property, however if the web request fails,
        you get a WebException which contains a simpler WebResponse, which
        requires a bit more effort in order to access the raw response content.

    .PARAMETER WebResponse
        An HttpWebResponse object, typically the Response property on a WebException.

    .OUTPUTS
        System.String - The raw content that was included in a WebResponse; $null otherwise.
#>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [System.Net.HttpWebResponse] $WebResponse
    )

    $streamReader = $null

    try
    {
        $content = $null

        if (($null -ne $WebResponse) -and ($WebResponse.ContentLength -gt 0))
        {
            $stream = $WebResponse.GetResponseStream()
            $encoding = [System.Text.Encoding]::UTF8
            if (-not [String]::IsNullOrWhiteSpace($WebResponse.ContentEncoding))
            {
                $encoding = [System.Text.Encoding]::GetEncoding($WebResponse.ContentEncoding)
            }

            $streamReader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($stream, $encoding)
            $content = $streamReader.ReadToEnd()
        }

        return $content
    }
    finally
    {
        if ($null -ne $streamReader)
        {
            $streamReader.Close()
        }
    }
}

function New-ErrorRecord
{
<#
    .SYNOPSIS
        Returns an ErrorRecord object for use by $PSCmdlet.ThrowTerminatingError

    .DESCRIPTION
        Returns an ErrorRecord object for use by $PSCmdlet.ThrowTerminatingError

    .PARAMETER ErrorMessage
        The message that describes the error

    .PARAMETER ErrorId
        The Id to be used to construct the FullyQualifiedErrorId property of the error record.

    .PARAMETER ErrorCategory
        This is the ErrorCategory which best describes the error.

    .PARAMETER TargetObject
        This is the object against which the cmdlet was operating when the error occurred. This is optional.

    .OUTPUTS
        System.Management.Automation.ErrorRecord

    .NOTES
        ErrorRecord Class - https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.errorrecord
        Exception Class - https://docs.microsoft.com/en-us/dotnet/api/system.exception
        Cmdlet.ThrowTerminationError - https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.cmdlet.throwterminatingerror
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This function is non state changing.')]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)]
        [System.String] $ErrorMessage,

        [System.String] $ErrorId,

        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorCategory] $ErrorCategory,

        [System.Management.Automation.PSObject] $TargetObject
    )

    $exception = New-Object -TypeName System.Exception -ArgumentList $ErrorMessage
    $errorRecordArgumentList = $exception, $ErrorId, $ErrorCategory, $TargetObject
    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $errorRecordArgumentList

    return $errorRecord
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBoKSiSrAo86pJw
# nNfC4i23OpKSRGmtKJ0N/K4XoQWo8KCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGg8wghoLAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMFdNPkGSjdtcoXH2LcqinGo
# GGpCEEW5PDn+QoJK4d5kMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBj16vQYsA3Os8puDdH0nO6Ad6M67kvbbzoi/oZ3tjkyTfbJa38WmNN
# iZzrr3UrPX4OW8gQb13D4eJu3o9HlcFTHcKmJzYSFuV3BKMD+EbD5QHLGO6Kl+3z
# 0q2giI9Mr3/P8SL1Co2FZ/7o51puIQefSriaQfilMARUi6+HVULpFCm0tZBdby7/
# RK6PqD8lYYUy2qvz/DuAY3k/tKPJ/V3SgybnTK1Qg+X6TywmlTUS+QZiH+DLnP3B
# ZdezFxfxOjOUtq2j1s77mLvG3ZUWRut7al+6BOqKqzSXI7BLFWindjAcuQw7PR8X
# hFiJJ0qRLzljAgxB2vZoXfcSnAM1A+WzoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIACENBCgz9mRz2rVLDsC5JypgxN8w3Gpg5BpoBFjNzKtAgZlVsEy
# iLsYEzIwMjMxMTIxMTczNjA5LjU1N1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNDAw
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAAB1idp/3ItVsiuAAEAAAHWMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIzNFoXDTI0MDIwMTE5MTIzNFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNDAwLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAM8szY6byvm7d9xsMQ5fJ0m1uRblTfgoVp+0L7xD
# I2qmUwjNJMLVOgTTNzB5AK88h+li3I8HeO3p89Gmu+HAKSxTD2nQ5+ZnNY8O+S3j
# QFRK27zXdCWuWhF2mUvPbGmTb2Mg5nj6sFsppmQE9nhHgtdCGSQed7Rj9iHzlmow
# xFoxaQEzqdTBXloOLBep0T0nKXSLVpZhsKrPAFF03sJOUAnGsnjui/e5/+UWD2Gd
# VBypBiBGtEWkM0Uw4/SDDPk2PprbgZmdwUQZGYrAiYv7kpY+dWC9p0lJGnpmqthX
# cWZsGZm2wXSFKVWMtA7yfF6UZXtO+oghIiy/ZtAyBQFUTPzAcXJTfzreAePwEJsS
# knObvl8smwvc/rqUlQ1E3sJGx80Rsd1f93qOilU4XAXuiaZNCOlTfsD/thHTAkNO
# 3pmxdT6P/BiWj1vba3WpS2GqNGzfagZ/ZNFMKhBYuEl7dwAhhGWVr+AQqVu4MOwb
# f3brLgQwcXFOOyOtxkRsNbCMHfCunXUPKDVApwPItSzZqcGiW9DAlM3SYw65c7y0
# HPbSeD/5fD7jD5b08yS9bV9piLjflWMpFmwd/Eg+MjNnTB/gWJuZU8kdn5pPEaxU
# k/HJ0KG+8YJ/h97xd9hj0/mVuf1Jwpzhp1N3jgYKsGUn8k6ygDg680djpb5dwpVw
# ggZbAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUYZpUNjtNAGIwIqDb6P/NFNxixk4w
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBANS/5GM2J3AnFJsyTUi9Lwt/E0zxVpWG
# nFHVKRb4VFjoAqSfazc6fb2cYRWVq1uUi/WpVMqStTEtgxnTP5EDqaZ9e57Zjv9g
# FvMzmRR5SBTbLUyZuKfrFp1P0PMQJ4TsTj7eTYOZnG5X4YsVhCyqQNt7yjLv7cFK
# JTb2rJkBhP29EMAs9QLlnDKg+Q18puqOXdWAVOoi5sRCvnozRh0xaWoKqrTJWWf2
# Y9uEcfNcc6NpCy6uiEcJ/tVPxy3v2mjfgV3xdyyqbKF0oHLWN3KSeuKT4Xe8SX/3
# Spqifk3wpNmga04WVokU+dnYOpC1vZZaR+4CgZasZIDjczKXv49htSyuL82sy8B3
# 1n4n0WWqwzBdAXEAHu6MmLiE/wEfyPqqSbLi66VTlJJBrpeQSVxopBhKklxKOSPJ
# MMg6l/otkFNoXHp56ioNnSVRGGJGo77XKjy5c7z17qSAF4Ly3VY3khOpeeOhxiAO
# /IWmm2xQOCdFSIjUz9CX87b31WS0yQgvvaLpB3gEGyuPdn6IsSco/16lTCiw/Wbc
# 3a/3KFdDUeK6wmXrch9cjJ8Elpa9AOBTcmTh4hlKv/YoiPim1e3j3oJGIdOLTXWR
# zAOl2NAsBCIK+iPWm7KF/BV/YblnAGm0heK81FtrfgqQPmiqYSgXXJEVDziIOx/+
# CLKf9chPthj/MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+
# F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU
# 88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqY
# O7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzp
# cGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0Xn
# Rm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1
# zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZN
# N3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLR
# vWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTY
# uVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUX
# k8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB
# 2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKR
# PEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0g
# BFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQM
# MAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQ
# W9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBa
# BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOX
# PTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6c
# qYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/z
# jj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz
# /AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyR
# gNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdU
# bZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo
# 3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4K
# u+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10Cga
# iQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9
# vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGC
# A1AwggI4AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTQwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# APmvcNVGkAZCj2xMtQd4ELzs2kr6oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpBy4NMCIYDzIwMjMxMTIxMTMy
# NDI5WhgPMjAyMzExMjIxMzI0MjlaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# Lg0CAQAwCgIBAAICARQCAf8wBwIBAAICE1IwCgIFAOkIf40CAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAV6ZEDMTL1Oil5CA8On/YGXBr5lLzWe8K3HmzwRK7
# cSyw8oYrlQxKR+/jmm91G3KDDH10VSVHhO+vZfv/W6iQWDew4mHbhLzF9thdmbA6
# Urs3G1MDbOMP385tf58jbFHHs0sTPyjhyK0+X0YpAlPZIWYtLcXsFBLSfDAz2em9
# cqs0eBHpsST6aUvzRSHYSso5SGYRQPoZb2uIssZCYIhEafYf3J/U+d+lhdfIrTjN
# q4mFtj7X223SRF8Z8AWXI26HIoVGb9C3bHmz9VejBbMbjRUjl9Gsq+c+zK8DBZuh
# w/gdS7B+8UHFfgjJgv/xUBGNWTPLp2Kp7kISqpBmMiv9HjGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB1idp/3ItVsiuAAEA
# AAHWMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIOEK65Hu2Onmeyr/CELCjp41GX/0or1OnFh+xXzO
# Q0TzMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1stNDVd40z4QGKc4QkyN
# l3SMw0O6v4Ar47w/XaPlJPwwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAdYnaf9yLVbIrgABAAAB1jAiBCA31rAZghduxT8BdG6P7Rl6
# biGg0w08eWGJDY7WRis5CjANBgkqhkiG9w0BAQsFAASCAgAM3yBm7ZndeDlo/3TW
# FUhgraR/DE0yOLsIVauVSpLp1wUKiL+gYX+erx53dg97WltGXQDfIZZqNndaS+TB
# POKEZcg5+nKJJcmFxHzkvNizawdVee9hwaPf6XIPxfXtViHOHbVg2F8GUu+tPRD5
# IPybleyL3apz86HNJxjEL3uLGqDq4BO/jMqfhl+jzoDiVopgEJrGj229PauHJ4Qj
# w0DfcLYZHpHWOF7UhRKmXHu1CmKJZqg7QKBTvc7Hpe09THR7wv7eIUgSFQIlfxOh
# a5k+4NFYt+0jmF1wD50Ymxi43HcSsbRIzq62+6ar4cfyMXko45zBW3Agbe+mcIBm
# JL4SMhC6sALHU2/667XsmXjp5utWnSsHMtqbHL/OmZk/V9wyvjJZ4l8260FyKwEJ
# kZoCcsNwu9k5FqYlfe+hRfN4IjdvCDDM0qdnY55wbL4yufhbqp5+Y013ciw1Barr
# sjDXrK/8u9FRysHUsJbjdIev+OrJR9AnTQcCWoibMFTAd57/n8sf2N4v6in9lowF
# Lt/MywYI1Q6MkDov0kxQeYYaowPdcqUuTRog7gK89J7ER8bIyZp/ohsuUfw28eIl
# mfxAXF0bwALavTiw2eIcZ2ctNkjuC4EEIeLB0uQypgL2vmKudiGXv5dWUT11rzGS
# 3eaoquJFqonGPEzb7gW1KQ1i8A==
# SIG # End signature block
