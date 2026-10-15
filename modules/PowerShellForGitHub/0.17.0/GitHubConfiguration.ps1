# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# The GitHub API token is stored in the password field.
[PSCredential] $script:accessTokenCredential = $null

# The location of the file that we'll store any settings that can/should roam with the user.
[string] $script:configurationFilePath = [System.IO.Path]::Combine(
    [System.Environment]::GetFolderPath('ApplicationData'),
    'Microsoft',
    'PowerShellForGitHub',
    'config.json')

# The location of the file that we'll store the Access Token SecureString
# which cannot/should not roam with the user.
[string] $script:accessTokenFilePath = [System.IO.Path]::Combine(
    [System.Environment]::GetFolderPath('LocalApplicationData'),
    'Microsoft',
    'PowerShellForGitHub',
    'accessToken.txt')

# Only tell users about needing to configure an API token once per session.
$script:seenTokenWarningThisSession = $false

# The session-cached copy of the module's configuration properties
[PSCustomObject] $script:configuration = $null

function Initialize-GitHubConfiguration
{
<#
    .SYNOPSIS
        Populates the configuration of the module for this session, loading in any values
        that may have been saved to disk.

    .DESCRIPTION
        Populates the configuration of the module for this session, loading in any values
        that may have been saved to disk.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .NOTES
        Internal helper method.  This is actually invoked at the END of this file.
#>
    [CmdletBinding()]
    param()

    $script:seenTokenWarningThisSession = $false
    $script:configuration = Import-GitHubConfiguration -Path $script:configurationFilePath
}

function Set-GitHubConfiguration
{
<#
    .SYNOPSIS
        Change the value of a configuration property for the PowerShellForGitHub module,
        for the session only, or globally for this user.

    .DESCRIPTION
        Change the value of a configuration property for the PowerShellForGitHub module,
        for the session only, or globally for this user.

        A single call to this method can set any number or combination of properties.

        To change any of the boolean/switch properties to false, specify the switch,
        immediately followed by ":$false" with no space.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER ApiHostName
        The hostname of the GitHub instance to communicate with. Defaults to 'github.com'. Provide a
        different hostname when using a GitHub Enterprise server. Do not include the HTTP/S prefix,
        and do not include 'api'. For example, use "github.contoso.com".

    .PARAMETER ApplicationInsightsKey
        Change the Application Insights instance that telemetry will be reported to (if telemetry
        hasn't been disabled via DisableTelemetry).

    .PARAMETER DefaultOwnerName
        The owner name that should be used with a command that takes OwnerName as a parameter
        when no value has been supplied.

    .PARAMETER DefaultPassThru
        Sets what the default PassThru behavior should be for commands that have a PassThru
        switch.  By default, those commands will not return the result of the command unless
        the user passes in -PassThru.  By setting this value to $true, those commands will
        always behave as if -PassThru had been specified, unless you explicitly specify
        -PassThru:$false on an individual command.

    .PARAMETER DefaultRepositoryName
        The repository name that should be used with a command that takes RepositoryName as a parameter
        when no value has been supplied.

    .PARAMETER DisableLogging
        Specify this switch to stop the module from logging all activity to a log file located
        at the location specified by LogPath.

    .PARAMETER DisablePiiProtection
        Specify this switch to disable the hashing of potential PII data prior to submitting the
        data to telemetry (if telemetry hasn't been disabled via DisableTelemetry).

    .PARAMETER DisablePipelineSupport
        By default, this module will modify all objects returned by the API calls by adding
        additional, consistent properties to those objects which ease pipelining those objects
        into other functions.  This is highly convenient functionality.  You would only want to
        disable this functionality if you are experiencing some edge case problems and are awaiting
        a proper fix.

    .PARAMETER DisableSmarterObjects
        By default, this module will modify all objects returned by the API calls to update
        any properties that can be converted to objects (like strings for Date/Time's being
        converted to real DateTime objects).  Enable this property if you desire getting back
        the unmodified version of the object from the API.

    .PARAMETER DisableTelemetry
        Specify this switch to stop the module from reporting any of its usage (which would be used
        for diagnostics purposes).

    .PARAMETER DisableUpdateCheck
        Specify this switch to stop the daily update check with PowerShellGallery which can
        inform you when there is a newer version of this module available.

    .PARAMETER LogPath
        The location of the log file that all activity will be written to if DisableLogging remains
        $false.

    .PARAMETER LogProcessId
        If specified, the Process ID of the current PowerShell session will be included in each
        log entry.  This can be useful if you have concurrent PowerShell sessions all logging
        to the same file, as it would then be possible to filter results based on ProcessId.

    .PARAMETER LogRequestBody
        If specified, the JSON body of the REST request will be logged to verbose output.
        This can be helpful for debugging purposes.

    .PARAMETER LogTimeAsUtc
        If specified, all times logged will be logged as UTC instead of the local timezone.

    .PARAMETER MaximumRetriesWhenResultNotReady
        Some API requests may take time for GitHub to gather the results, and in the interim,
        a 202 response is returned.  This value indicates the maximum number of times that the
        query will be retried before giving up and failing.  The amount of time between each of
        these requests is controlled by the RetryDelaySeconds configuration value.

    .PARAMETER MultiRequestProgressThreshold
        Some commands may require sending multiple requests to GitHub.  In some situations,
        getting the entirety of the request might take 70+ requests occurring over 20+ seconds.
        A progress bar will be shown (displaying which sub-request is being executed) if the number
        of requests required to complete this command is greater than or equal to this configuration
        value.
        Set to 0 to disable this feature.

    .PARAMETER RetryDelaySeconds
        The number of seconds to wait before retrying a command again after receiving a 202 response.
        The number of times that a retry will occur is controlled by the
        MaximumRetriesWhenResultNotReady configuration value.

    .PARAMETER StateChangeDelaySeconds
        The number of seconds to wait before returning the result after executing a command that
        may result in a state change on the server.  This is intended to only be used during test
        execution in order to increase reliability.

    .PARAMETER SuppressNoTokenWarning
        If an Access Token has not been configured, this module will provide a warning to the user
        informing them of this, once per session.  If it is expected that this module will regularly
        be used without configuring an Access Token, specify this switch to always suppress that
        warning message.

    .PARAMETER SuppressTelemetryReminder
        When telemetry is enabled, a warning will be printed to the console once per session
        informing users that telemetry is occurring.  Setting this value will suppress that
        message from showing up ever again.

    .PARAMETER WebRequestTimeoutSec
        The number of seconds that should be allowed before an API request times out.  A value of
        0 indicates an infinite timeout, however experience has shown that PowerShell doesn't seem
        to always honor inifinite timeouts.  Hence, this value can be configured if need be.

    .PARAMETER SessionOnly
        By default, this method will store the configuration values in a local file so that changes
        persist across PowerShell sessions.  If this switch is provided, the file will not be
        created/updated and the specified configuration changes will only remain in memory/effect
        for the duration of this PowerShell session.

    .EXAMPLE
        Set-GitHubConfiguration -WebRequestTimeoutSec 120 -SuppressNoTokenWarning

        Changes the timeout permitted for a web request to two minutes, and additionally tells
        the module to never warn about no Access Token being configured.  These settings will be
        persisted across future PowerShell sessions.

    .EXAMPLE
        Set-GitHubConfiguration -DisableLogging -SessionOnly

        Disables the logging of any activity to the logfile specified in LogPath, but for this
        session only.

    .EXAMPLE
        Set-GitHubConfiguration -ApiHostName "github.contoso.com"

        Sets all requests to connect to a GitHub Enterprise server running at
        github.contoso.com.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess)]
    param(
        [ValidatePattern('^(?!https?:)(?!api\.)(?!www\.).*')]
        [string] $ApiHostName,

        [string] $ApplicationInsightsKey,

        [string] $DefaultOwnerName,

        [string] $DefaultPassThru,

        [string] $DefaultRepositoryName,

        [switch] $DisableLogging,

        [switch] $DisablePiiProtection,

        [switch] $DisablePipelineSupport,

        [switch] $DisableSmarterObjects,

        [switch] $DisableTelemetry,

        [switch] $DisableUpdateCheck,

        [string] $LogPath,

        [switch] $LogProcessId,

        [switch] $LogRequestBody,

        [switch] $LogTimeAsUtc,

        [int] $MaximumRetriesWhenResultNotReady,

        [int] $MultiRequestProgressThreshold,

        [int] $RetryDelaySeconds,

        [int] $StateChangeDelaySeconds,

        [switch] $SuppressNoTokenWarning,

        [switch] $SuppressTelemetryReminder,

        [ValidateRange(0, 3600)]
        [int] $WebRequestTimeoutSec,

        [switch] $SessionOnly
    )

    $persistedConfig = $null
    if (-not $SessionOnly)
    {
        $persistedConfig = Read-GitHubConfiguration -Path $script:configurationFilePath
    }

    if (-not $PSCmdlet.ShouldProcess('GitHubConfiguration', 'Set'))
    {
        return
    }

    $properties = Get-Member -InputObject $script:configuration -MemberType NoteProperty | Select-Object -ExpandProperty Name
    foreach ($name in $properties)
    {
        if ($PSBoundParameters.ContainsKey($name))
        {
            $value = $PSBoundParameters.$name
            if ($value -is [switch]) { $value = $value.ToBool() }
            $script:configuration.$name = $value

            if (-not $SessionOnly)
            {
                Add-Member -InputObject $persistedConfig -Name $name -Value $value -MemberType NoteProperty -Force
            }
        }
    }

    if (-not $SessionOnly)
    {
        Save-GitHubConfiguration -Configuration $persistedConfig -Path $script:configurationFilePath
    }
}

function Get-GitHubConfiguration
{
<#
    .SYNOPSIS
        Gets the currently configured value for the requested configuration setting.

    .DESCRIPTION
        Gets the currently configured value for the requested configuration setting.

        Always returns the value for this session, which may or may not be the persisted
        setting (that all depends on whether or not the setting was previously modified
        during this session using Set-GitHubConfiguration -SessionOnly).

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Name
        The name of the configuration whose value is desired.

    .EXAMPLE
        Get-GitHubConfiguration -Name WebRequestTimeoutSec

        Gets the currently configured value for WebRequestTimeoutSec for this PowerShell session
        (which may or may not be the same as the persisted configuration value, depending on
        whether this value was modified during this session with Set-GitHubConfiguration -SessionOnly).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ApiHostName',
            'ApplicationInsightsKey',
            'DefaultOwnerName',
            'DefaultPassThru',
            'DefaultRepositoryName',
            'DisableLogging',
            'DisablePiiProtection',
            'DisablePipelineSupport',
            'DisableSmarterObjects',
            'DisableTelemetry',
            'DisableUpdateCheck',
            'LogPath',
            'LogProcessId',
            'LogRequestBody',
            'LogTimeAsUtc',
            'MaximumRetriesWhenResultNotReady',
            'MultiRequestProgressThreshold',
            'RetryDelaySeconds',
            'StateChangeDelaySeconds',
            'SuppressNoTokenWarning',
            'SuppressTelemetryReminder',
            'TestConfigSettingsHash',
            'WebRequestTimeoutSec')]
        [string] $Name
    )

    return $script:configuration.$Name
}

function Save-GitHubConfiguration
{
<#
    .SYNOPSIS
        Serializes the provided settings object to disk as a JSON file.

    .DESCRIPTION
        Serializes the provided settings object to disk as a JSON file.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Configuration
        The configuration object to persist to disk.

    .PARAMETER Path
        The path to the file on disk that Configuration should be persisted to.

    .NOTES
        Internal helper method.

    .EXAMPLE
        Save-GitHubConfiguration -Configuration $config -Path 'c:\foo\config.json'

        Serializes $config as a JSON object to 'c:\foo\config.json'
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Configuration,

        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not $PSCmdlet.ShouldProcess('GitHub Configuration', 'Save'))
    {
        return
    }

    $null = New-Item -Path $Path -Force
    ConvertTo-Json -InputObject $Configuration |
        Set-Content -Path $Path -Force -ErrorAction SilentlyContinue -ErrorVariable ev

    if (($null -ne $ev) -and ($ev.Count -gt 0))
    {
        $message = "Failed to persist these updated settings to disk.  They will remain for this PowerShell session only."
        Write-Log -Message $message -Level Warning -Exception $ev[0]
    }
}

function Test-PropertyExists
{
<#
    .SYNOPSIS
        Determines if an object contains a property with a specified name.

    .DESCRIPTION
        Determines if an object contains a property with a specified name.

        This is essentially using Get-Member to verify that a property exists,
        but additionally adds a check to ensure that InputObject isn't null.

    .PARAMETER InputObject
        The object to check to see if it has a property named Name.

    .PARAMETER Name
        The name of the property on InputObject that is being tested for.

    .EXAMPLE
        Test-PropertyExists -InputObject $listing -Name 'title'

        Returns $true if $listing is non-null and has a property named 'title'.
        Returns $false otherwise.

    .NOTES
        Internal-only helper method.
#>
    [CmdletBinding()]
    [OutputType([bool])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Exists isn't a noun and isn't violating the intention of this rule.")]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [String] $Name
    )

    return (($null -ne $InputObject) -and
            ($null -ne (Get-Member -InputObject $InputObject -Name $Name -MemberType Properties)))
}

function Resolve-PropertyValue
{
<#
    .SYNOPSIS
        Returns the requested property from the provided object, if it exists and is a valid
        value.  Otherwise, returns the default value.

    .DESCRIPTION
        Returns the requested property from the provided object, if it exists and is a valid
        value.  Otherwise, returns the default value.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER InputObject
        The object to check the value of the requested property.

    .PARAMETER Name
        The name of the property on InputObject whose value is desired.

    .PARAMETER Type
        The type of the value stored in the Name property on InputObject.  Used to validate
        that the property has a valid value.

    .PARAMETER DefaultValue
        The value to return if Name doesn't exist on InputObject or is of an invalid type.

    .EXAMPLE
        Resolve-PropertyValue -InputObject $config -Name defaultOwnerName -Type String -DefaultValue $null

        Checks $config to see if it has a property named "defaultOwnerName".  If it does, and it's a
        string, returns that value, otherwise, returns $null (the DefaultValue).
#>
    [CmdletBinding()]
    param(
        [PSCustomObject] $InputObject,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('String', 'Boolean', 'Int32', 'Int64')]
        [String] $Type,

        $DefaultValue
    )

    if ($null -eq $InputObject)
    {
        return $DefaultValue
    }

    $typeType = [String]
    if ($Type -eq 'Boolean') { $typeType = [Boolean] }
    if ($Type -eq 'Int32') { $typeType = [Int32] }
    if ($Type -eq 'Int64') { $typeType = [Int64] }
    $numberEquivalents = @('Int32', 'Int64', 'long', 'int')

    if (Test-PropertyExists -InputObject $InputObject -Name $Name)
    {
        if (($InputObject.$Name -is $typeType) -or
            (($Type -in $numberEquivalents) -and ($InputObject.$Name.GetType().Name -in $numberEquivalents)))
        {
            return $InputObject.$Name
        }
        else
        {
            $message = "The locally cached $Name configuration was not of type $Type (it was $($InputObject.$Name.GetType())).  Reverting to default value."
            Write-Log -Message $message -Level Warning
            return $DefaultValue
        }
    }
    else
    {
        return $DefaultValue
    }
}

function Reset-GitHubConfiguration
{
<#
    .SYNOPSIS
        Clears out the user's configuration file and configures this session with all default
        configuration values.

    .DESCRIPTION
        Clears out the user's configuration file and configures this session with all default
        configuration values.

        This would be the functional equivalent of using this on a completely different computer.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER SessionOnly
        By default, this will delete the location configuration file so that all defaults are used
        again.  If this is specified, then only the configuration values that were made during
        this session will be discarded.

    .EXAMPLE
        Reset-GitHubConfiguration

        Deletes the local configuration file and loads in all default configuration values.

    .NOTES
        This command will not clear your authentication token.
        Please use Clear-GitHubAuthentication to accomplish that.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch] $SessionOnly
    )

    if (-not $PSCmdlet.ShouldProcess('GitHub Configuration', 'Reset'))
    {
        return
    }

    Set-TelemetryEvent -EventName Reset-GitHubConfiguration

    if (-not $SessionOnly)
    {
        $null = Remove-Item -Path $script:configurationFilePath -Force -ErrorAction SilentlyContinue -ErrorVariable ev

        if (($null -ne $ev) -and ($ev.Count -gt 0) -and ($ev[0].FullyQualifiedErrorId -notlike 'PathNotFound*'))
        {
            $message = "Reset was unsuccessful.  Experienced a problem trying to remove the file [$script:configurationFilePath]."
            Write-Log -Message $message -Level Warning -Exception $ev[0]
        }
    }

    Initialize-GitHubConfiguration

    $message = "This has not cleared your authentication token.  Call Clear-GitHubAuthentication to accomplish that."
    Write-Log -Message $message -Level Verbose
}

function Read-GitHubConfiguration
{
<#
    .SYNOPSIS
        Loads in the default configuration values and returns the deserialized object.

    .DESCRIPTION
        Loads in the default configuration values and returns the deserialized object.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Path
        The file that may or may not exist with a serialized version of the configuration
        values for this module.

    .OUTPUTS
        PSCustomObject

    .NOTES
        Internal helper method.
        No side-effects.

    .EXAMPLE
        Read-GitHubConfiguration -Path 'c:\foo\config.json'

        Returns back an object with the deserialized object contained in the specified file,
        if it exists and is valid.
#>
    [CmdletBinding()]
    param(
        [string] $Path
    )

    $content = Get-Content -Path $Path -Encoding UTF8 -ErrorAction Ignore
    if (-not [String]::IsNullOrEmpty($content))
    {
        try
        {
            return ($content | ConvertFrom-Json)
        }
        catch
        {
            $message = 'The configuration file for this module is in an invalid state.  Use Reset-GitHubConfiguration to recover.'
            Write-Log -Message $message -Level Warning
        }
    }

    return [PSCustomObject]@{}
}

function Import-GitHubConfiguration
{
<#
    .SYNOPSIS
        Loads in the default configuration values, and then updates the individual properties
        with values that may exist in a file.

    .DESCRIPTION
        Loads in the default configuration values, and then updates the individual properties
        with values that may exist in a file.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Path
        The file that may or may not exist with a serialized version of the configuration
        values for this module.

    .OUTPUTS
        PSCustomObject

    .NOTES
        Internal helper method.
        No side-effects.

    .EXAMPLE
        Import-GitHubConfiguration -Path 'c:\foo\config.json'

        Creates a new default config object and updates its values with any that are found
        within a deserialized object from the content in $Path.  The configuration object
        is then returned.
#>
    [CmdletBinding()]
    param(
        [string] $Path
    )

    # Create a configuration object with all the default values.  We can then update the values
    # with any that we find on disk.
    $logPath = [String]::Empty
    $logName = 'PowerShellForGitHub.log'
    $documentsFolder = [System.Environment]::GetFolderPath('MyDocuments')
    $logToLocalAppDataFolder = [System.String]::IsNullOrEmpty($documentsFolder)
    if ($logToLocalAppDataFolder)
    {
        $logPath = Join-Path -Path ([System.Environment]::GetFolderPath('LocalApplicationData')) -ChildPath $logName
    }
    else
    {
        $logPath = Join-Path -Path $documentsFolder -ChildPath $logName
    }

    $config = [PSCustomObject]@{
        'apiHostName' = 'github.com'
        'applicationInsightsKey' = '66d83c52-3070-489b-886b-09860e05e78a'
        'disableLogging' = ([String]::IsNullOrEmpty($logPath))
        'disablePiiProtection' = $false
        'disablePipelineSupport' = $false
        'disableSmarterObjects' = $false
        'disableTelemetry' = $false
        'disableUpdateCheck' = $false
        'defaultOwnerName' = [String]::Empty
        'defaultPassThru' = $false
        'defaultRepositoryName' = [String]::Empty
        'logPath' = $logPath
        'logProcessId' = $false
        'logRequestBody' = $false
        'logTimeAsUtc' = $false
        'maximumRetriesWhenResultNotReady' = 30
        'multiRequestProgressThreshold' = 10
        'retryDelaySeconds' = 30
        'stateChangeDelaySeconds' = 0
        'suppressNoTokenWarning' = $false
        'suppressTelemetryReminder' = $false
        'webRequestTimeoutSec' = 0

        # This hash is generated by using Helper.ps1's Get-Sha512Hash in Tests/Config/Settings.ps1
        # like so:
        #    . ./Helpers.ps1; Get-Sha512Hash -PlainText (Get-Content -Path ./Tests/Config/Settings.ps1 -Raw -Encoding Utf8)
        # The hash is used to identify if the user has made changes to the config file prior to
        # running the UT's locally.  It intentionally cannot be modified via Set-GitHubConfiguration
        # and must be updated directly in the source code here should the default Settings.ps1 file
        # ever be changed.
        'testConfigSettingsHash' = '272EE14CED396100A7AFD23EA21CA262470B7F4D80E47B7ABD90508B86210775F020EEF79D322F4C22A53835F700E1DFD13D0509C1D08DD6F9771B3F0133EDAB'
    }

    $jsonObject = Read-GitHubConfiguration -Path $Path
    Get-Member -InputObject $config -MemberType NoteProperty |
        ForEach-Object {
            $name = $_.Name
            $type = $config.$name.GetType().Name
            $config.$name = Resolve-PropertyValue -InputObject $jsonObject -Name $name -Type $type -DefaultValue $config.$name
        }

    # Let the user know when we had to revert to using the LocalApplicationData folder for the
    # log location (if they haven't already changed its path in their local config).
    $configuredLogPath = $config.logPath
    if ($logToLocalAppDataFolder -and ($logPath -eq $configuredLogPath))
    {
        # Limited instance where we write the warning directly instead of using Write-Log, since
        # Write-Log won't yet be configured.
        $message = "Storing log at non-default location: [$logPath] (no user profile path was found).  You can change this location by calling Set-GitHubConfiguration -LogPath <desiredPathToLogFile>"
        Write-Verbose -Message $message
    }

    return $config
}

function Backup-GitHubConfiguration
{
<#
    .SYNOPSIS
        Exports the user's current configuration file.

    .DESCRIPTION
        Exports the user's current configuration file.

        This is primarily used for unit testing scenarios.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Path
        The path to store the user's current configuration file.

    .PARAMETER Force
        If specified, will overwrite the contents of any file with the same name at the
        location specified by Path.

    .EXAMPLE
        Backup-GitHubConfiguration -Path 'c:\foo\config.json'

        Writes the user's current configuration file to c:\foo\config.json.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string] $Path,

        [switch] $Force
    )

    if (-not $PSCmdlet.ShouldProcess('GitHub Configuration', 'Backup'))
    {
        return
    }

    # Make sure that the path that we're going to be storing the file exists.
    $null = New-Item -Path (Split-Path -Path $Path -Parent) -ItemType Directory -Force

    if (Test-Path -Path $script:configurationFilePath -PathType Leaf)
    {
        $null = Copy-Item -Path $script:configurationFilePath -Destination $Path -Force:$Force
    }
    else
    {
        ConvertTo-Json -InputObject @{} | Set-Content -Path $Path -Force:$Force
    }
}

function Restore-GitHubConfiguration
{
<#
    .SYNOPSIS
        Sets the specified file to be the user's configuration file.

    .DESCRIPTION
        Sets the specified file to be the user's configuration file.

        This is primarily used for unit testing scenarios.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Path
        The path to store the user's current configuration file.

    .EXAMPLE
        Restore-GitHubConfiguration -Path 'c:\foo\config.json'

        Makes the contents of c:\foo\config.json be the user's configuration for the module.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) { $true }
            else { throw "$_ does not exist." }})]
        [string] $Path
    )

    if (-not $PSCmdlet.ShouldProcess('GitHub Configuration', 'Restore'))
    {
        return
    }

    # Make sure that the path that we're going to be storing the file exists.
    $null = New-Item -Path (Split-Path -Path $script:configurationFilePath -Parent) -ItemType Directory -Force

    $null = Copy-Item -Path $Path -Destination $script:configurationFilePath -Force

    Initialize-GitHubConfiguration
}

function Resolve-ParameterWithDefaultConfigurationValue
{
<#
    .SYNOPSIS
        Some of the configuration properties act as default values to be used for some functions.
        This will determine what the correct final value should be by inspecting the calling
        functions inbound parameters, along with the corresponding configuration value.

    .DESCRIPTION
        Some of the configuration properties act as default values to be used for some functions.
        This will determine what the correct final value should be by inspecting the calling
        functions inbound parameters, along with the corresponding configuration value.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER BoundParameters
        The inbound parameters from the calling method.
        No need to explicitly provide this if you're using the PSBoundParameters from the
        function that is calling this directly.

    .PARAMETER Name
        The name of the parameter in BoundParameters.

    .PARAMETER ConfigValueName
        The name of the configuration property that should be used as default if Name doesn't exist
        in BoundParameters.

    .PARAMETER NonEmptyStringRequired
        If specified, will throw an exception if the resolved value to be returned would end up
        being null or an empty string.

    .EXAMPLE
        Resolve-ParameterWithDefaultConfigurationValue -BoundParameters $PSBoundParameters -Name OwnerName -ConfigValueName DefaultOwnerName

        Checks to see if the OwnerName was provided by the user from the calling method.  If
        so, uses that value. otherwise uses the DefaultOwnerName value currently configured.
#>
    [CmdletBinding()]
    param(
        $BoundParameters = (Get-Variable -Name PSBoundParameters -Scope 1 -ValueOnly),

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [String] $ConfigValueName,

        [switch] $NonEmptyStringRequired
    )

    $value = $null
    if ($BoundParameters.ContainsKey($Name))
    {
        $value = $BoundParameters[$Name]
        if ($value -is [switch])
        {
            $value = $value.IsPresent
        }
    }
    else
    {
        $value = (Get-GitHubConfiguration -Name $ConfigValueName)
    }

    if ($NonEmptyStringRequired -and [String]::IsNullOrEmpty($value))
    {
        $message = "A value must be provided for $Name either as a parameter, or as a default configuration value ($ConfigValueName) via Set-GitHubConfiguration."
        Write-Log -Message $message -Level Error
        throw $message
    }
    else
    {
        return $value
    }
}

function Set-GitHubAuthentication
{
<#
    .SYNOPSIS
        Allows the user to configure the API token that should be used for authentication
        with the GitHub API.

    .DESCRIPTION
        Allows the user to configure the API token that should be used for authentication
        with the GitHub API.

        The token will be stored on the machine as a SecureString and will automatically
        be read on future PowerShell sessions with this module.  If the user ever wishes
        to remove their authentication from the system, they simply need to call
        Clear-GitHubAuthentication.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Credential
        If provided, instead of prompting the user for their API Token, it will be extracted
        from the password field of this credential object.

    .PARAMETER SessionOnly
        By default, this method will store the provided API Token as a SecureString in a local
        file so that it can be restored automatically in future PowerShell sessions.  If this
        switch is provided, the file will not be created/updated and the authentication information
        will only remain in memory for the duration of this PowerShell session.

    .EXAMPLE
        Set-GitHubAuthentication

        Prompts the user for their GitHub API Token and stores it in a file on the machine as a
        SecureString for use in future PowerShell sessions.

    .EXAMPLE
        $secureString = ("<Your Access Token>" | ConvertTo-SecureString -AsPlainText -Force)
        $cred = New-Object System.Management.Automation.PSCredential "username is ignored", $secureString
        Set-GitHubAuthentication -Credential $cred
        $secureString = $null # clear this out now that it's no longer needed
        $cred = $null # clear this out now that it's no longer needed

        Allows you to specify your access token as a plain-text string ("<Your Access Token>")
        which will be securely stored on the machine for use in all future PowerShell sessions.

    .EXAMPLE
        Set-GitHubAuthentication -SessionOnly

        Prompts the user for their GitHub API Token, but keeps it in memory only for the duration
        of this PowerShell session.

    .EXAMPLE
        Set-GitHubAuthentication -Credential $cred -SessionOnly

        Uses the API token stored in the password field of the provided credential object for
        authentication, but keeps it in memory only for the duration of this PowerShell session..
#>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUsePSCredentialType", "", Justification="The System.Management.Automation.Credential() attribute does not appear to work in PowerShell v4 which we need to support.")]
    param(
        [PSCredential] $Credential,

        [switch] $SessionOnly
    )

    Write-InvocationLog

    if (-not $PSCmdlet.ShouldProcess('GitHub Authentication', 'Set'))
    {
        return
    }

    if (-not $PSBoundParameters.ContainsKey('Credential'))
    {
        $message = 'Please provide your GitHub API Token in the Password field.  You can enter anything in the username field (it will be ignored).'
        if (-not $SessionOnly)
        {
            $message = $message + '  ***The token is being cached across PowerShell sessions.  To clear caching, call Clear-GitHubAuthentication.***'
        }

        Write-Log -Message $message
        $Credential = Get-Credential -Message $message
    }

    if ([String]::IsNullOrWhiteSpace($Credential.GetNetworkCredential().Password))
    {
        $message = "The API Token was not provided in the password field.  Nothing to do."
        Write-Log -Message $message -Level Error
        throw $message
    }

    $script:accessTokenCredential = $Credential

    if (-not $SessionOnly)
    {
        $null = New-Item -Path $script:accessTokenFilePath -Force
        $script:accessTokenCredential.Password |
            ConvertFrom-SecureString |
            Set-Content -Path $script:accessTokenFilePath -Force
    }
}

function Clear-GitHubAuthentication
{
<#
    .SYNOPSIS
        Clears out any GitHub API token from memory, as well as from local file storage.

    .DESCRIPTION
        Clears out any GitHub API token from memory, as well as from local file storage.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER SessionOnly
        By default, this will clear out the cache in memory, as well as in the local
        configuration file.  If this switch is specified, authentication will be cleared out
        in this session only -- the local configuration file cache will remain
        (and thus still be available in a new PowerShell session).

    .EXAMPLE
        Clear-GitHubAuthentication

        Clears out any GitHub API token from memory, as well as from local file storage.

    .NOTES
        This command will not clear your configuration settings.
        Please use Reset-GitHubConfiguration to accomplish that.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch] $SessionOnly
    )

    Write-InvocationLog

    Set-TelemetryEvent -EventName Clear-GitHubAuthentication

    if (-not $PSCmdlet.ShouldProcess('GitHub Authentication', 'Clear'))
    {
        return
    }

    $script:accessTokenCredential = $null

    if (-not $SessionOnly)
    {
        Remove-Item -Path $script:accessTokenFilePath -Force -ErrorAction SilentlyContinue -ErrorVariable ev

        if (($null -ne $ev) -and
            ($ev.Count -gt 0) -and
            ($ev[0].FullyQualifiedErrorId -notlike 'PathNotFound*'))
        {
            $message = "Experienced a problem trying to remove the file that persists the Access Token [$script:accessTokenFilePath]."
            Write-Log -Message $message -Level Warning -Exception $ev[0]
        }
    }

    $message = "This has not cleared your configuration settings.  Call Reset-GitHubConfiguration to accomplish that."
    Write-Log -Message $message -Level Verbose
}

function Get-AccessToken
{
<#
    .SYNOPSIS
        Retrieves the API token for use in the rest of the module.

    .DESCRIPTION
        Retrieves the API token for use in the rest of the module.

        First will try to use the one that may have been provided as a parameter.
        If not provided, then will try to use the one already cached in memory.
        If still not found, will look to see if there is a file with the API token stored
        as a SecureString.
        Finally, if there is still no available token, none will be used.  The user will then be
        subjected to tighter hourly query restrictions.

        The Git repo for this module can be found here: http://aka.ms/PowershellForGitHub

    .PARAMETER AccessToken
        If provided, this will be returned instead of using the cached/configured value

    .OUTPUTS
        System.String
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "", Justification="For back-compat with v0.1.0, this still supports the deprecated method of using a global variable for storing the Access Token.")]
    [OutputType([String])]
    param(
        [string] $AccessToken
    )

    if (-not [String]::IsNullOrEmpty($AccessToken))
    {
        return $AccessToken
    }

    if ($null -ne $script:accessTokenCredential)
    {
        $token = $script:accessTokenCredential.GetNetworkCredential().Password

        if (-not [String]::IsNullOrEmpty($token))
        {
            return $token
        }
    }

    $content = Get-Content -Path $script:accessTokenFilePath -ErrorAction Ignore
    if (-not [String]::IsNullOrEmpty($content))
    {
        try
        {
            $secureString = $content | ConvertTo-SecureString

            $message = "Restoring Access Token from file.  This value can be cleared in the future by calling Clear-GitHubAuthentication."
            Write-Log -Message $messsage -Level Verbose
            $script:accessTokenCredential = New-Object System.Management.Automation.PSCredential "<username is ignored>", $secureString
            return $script:accessTokenCredential.GetNetworkCredential().Password
        }
        catch
        {
           $message = 'The Access Token file for this module contains an invalid SecureString (files can''t be shared by users or computers).  Use Set-GitHubAuthentication to update it.'
           Write-Log -Message $message -Level Warning
        }
    }

    if (-not [String]::IsNullOrEmpty($global:gitHubApiToken))
    {
        $message = 'Storing the Access Token in `$global:gitHubApiToken` is insecure and is no longer recommended.  To cache your Access Token for use across future PowerShell sessions, please use Set-GitHubAuthentication instead.'
        Write-Log -Message $message -Level Warning
        return $global:gitHubApiToken
    }

    if ((-not (Get-GitHubConfiguration -Name SuppressNoTokenWarning)) -and
        (-not $script:seenTokenWarningThisSession))
    {
        $script:seenTokenWarningThisSession = $true
        $message = 'This module has not yet been configured with a personal GitHub Access token.  The module can still be used, but GitHub will limit your usage to 60 queries per hour.  You can get a GitHub API token from https://github.com/settings/tokens/new (provide a description and check any appropriate scopes).'
        Write-Log -Message $message -Level Warning
    }

    return $null
}

function Test-GitHubAuthenticationConfigured
{
<#
    .SYNOPSIS
        Indicates if a GitHub API Token has been configured for this module via Set-GitHubAuthentication.

    .DESCRIPTION
        Indicates if a GitHub API Token has been configured for this module via Set-GitHubAuthentication.

        The Git repo for this module can be found here: http://aka.ms/PowershellForGitHub

    .OUTPUTS
        Boolean

    .EXAMPLE
        Test-GitHubAuthenticationConfigured

        Returns $true if the session is authenticated; $false otherwise
#>
    [CmdletBinding()]
    [OutputType([Boolean])]
    param()

    return (-not [String]::IsNullOrWhiteSpace((Get-AccessToken)))
}

Initialize-GitHubConfiguration

# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDzNbGEJl5E2AcJ
# fnxu79btus3HVOn82HCTZxLri2c3fqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII2xpHBA1SfDADupvzKtH4t6
# kU25KW7gOb46/0e5jHjFMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAzSCzKP0CF49qkcUi24P9jR0iZKyG2WNI5FcnSMppzzSCTXnyq6Tza
# D6kvrFepVR7QQPDWB4EEsdZIIRQ2rZh3e6Hqp85rPPUBs2d2UzsWppcJ0xexGG5N
# EbU0MMYoK+m9bDaCMNh2xRwI5IuTcYhzBRipbiRH3NaynyKQ6c6d1Mraxe2VkWqk
# Xp1+bwVzILNkTHoQllYzJsTQC4j7K4r6B9Wh7UI4zwOw1oQ+TQaHjg5JNIBzAeg1
# yHigDwzBps/C2qdBrzJZJekdz9hWhzBYDU9ouBiNrOXXFWQFICbmDNkyeXuPBWJd
# M/GQfndHUGq2uQsshG1gvYz02hc3N17soYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJP4HIgYgzO8VPQQPvP+EDUkJ93Jgfb3JCThdC3jTWCKAgZlVuAH
# xmUYEzIwMjMxMTIxMTczNTE3LjUxMVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MkFENC00QjkyLUZBMDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAd6eSJ6WnyhEPQABAAAB3jAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA3MTJaFw0yNTAxMTAxOTA3MTJaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjJBRDQt
# NEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtIH0HIX1QgOEDrEWs6eL
# D/GwOXyxKL2s4I5dJI7hUxCOc0YCjlUfHSKKMwQwf0tjZJQgGRVBLQyXqRH5NqCR
# Q9toSnCOFDWamuFGAlP+OVKeJzjZUMCjR6fgkjrGdegChagrJJjz9E4gp2mmGAjs
# 4lvhceTU/exfak1nfYsNjWS1yErX+FbI+VuVpcAdG7QTfKe/CtLz9tyisA07oOO7
# KzJL3NSav7DcfcAS9KCzZF64uPamQFx9bVQ8IW50t3sg9nZELih1BwQ+djXaPKlg
# +dLrJkCzSkumrQpEVTIHXHrHo5Tvey52Ic43XqYTSXostP06YajRL3gHGDc3/doT
# p9RudWh6ZVzsWQUu6bwqRlxtDtw4dIBYYnF0K+jk61S1F1Kp/zkWSUJcgiSDiybu
# cz1OS1RV87SSnqTHubKyAPRCvHHr/mhqqfA5NYs3Mr4EKLUbudQPWm165e9Cnx8T
# UqlOOcb/U4l56HAo00+Ma33xXQGaiBlN7dLEGQ545DIsD77kfKD8vryl74Otmhk9
# cloZT+IGIWYv66X86Ld3zfMsAeUdCYf9UY0F9HA/6LG+qHKT8R5vC5dUlj6tPJ9t
# F+6H2fQBoyGE3HGDq0YrJlLgQASIPGsX2YBkTLx7yt/p2Uohfl3dpAuj18N1rVlM
# 7D5cBwC+Pb83cMtUZmUeceUCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBRrMCZvGx5p
# qmB3HMrw6z6do9ASyDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA4pTAexcNpwY6
# 9QiCzkcOA+zQtnWrIdLoLrB8qUtoPfq1l9ta3XH4YyJrNK7L4azGJUfOSExb4Wor
# yCu4tBY3+w4Jf58ZSBP0tPbVxEilxmPj9kUi/C2QFywLPVcRSxdg5IlQ+K1jsTxt
# uV2aaFhnb2n5dCkhywb+r5iOSoFb2bDSu7Ux/ExNCz0xMOIPbyABUas8Dc3KSJIK
# G92pLtVf78twTP1RvO2j/DbxYDwc4IeoFNsNEeaI/swiP5JCYj1UhrJiwgZGO96W
# Y1rQ69tT0IlLP818wSB/Y0cxlRhbwqpYSMiM98cgrFaU0xiG5Z9ZFIdkIrIgA0DR
# okviygdC3PNnYyc1+NhjznXAdiMaDBSP+GUtGBA7lLfRnHvwaoEp/KWnblo5Yn+o
# +EL4NczaBdqMhduX6OkZxUA3C0UW6MIlF1lt4fVH5DjUWOAGDibc5MUMai3kNK5W
# RCCOS7uk5U+2V0TjpCUOD/ZaE+lNDFcfriw/UZ+QDBS23qutkz88LBEbqCKtiadN
# EsuyJwGGhguH4QQWNW+JcAZOTqme7yPH/hY9a7SOzPvIXODzb8UyoKT3Arcu/IsD
# IMc34XFscDG2DBp3ugtA8zRYYRF0HW6Y8IiJixJ/+Pv0Sod2g3BBhE5Wb5lfXRFf
# efptGYCeyR42GLTCdVp5WiAsx0YP6eowggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBooFKKzLjLzqmXxfLbYIlkTETa86CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6QdM+zAiGA8yMDIzMTEyMTIzMzYyN1oYDzIwMjMxMTIyMjMzNjI3WjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDpB0z7AgEAMAcCAQACAhpDMAcCAQACAhF5MAoC
# BQDpCJ57AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAdoaO31frTgOAnX+8
# wHG2jdHzSheaFRpUbU46HyqGh06xOmvc5vHHvij9MJm+ILpP/BFvdj4dKS+acDmP
# K5WeFl5uwjWoTgzDpygEY+PhfdibSpskFX38sxxTMGwVC31FEE0fT1yZcaa4HO9I
# RIIhJaekghJ+ozeMhUhQ1oiXfPoxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAd6eSJ6WnyhEPQABAAAB3jANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCBr2r2jlW0EOwi+W8kXFMU/J26rHUBfZwJh2VNDDvH9cTCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EII4+I58NwV4QEEkCf+YLcyCtPnD9TbPzUtgPjgdz
# fh17MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHe
# nkielp8oRD0AAQAAAd4wIgQgkIwwIgxYiJ2BygJ3dMh4is+eUPqOHKxVsfKqMPwi
# ULgwDQYJKoZIhvcNAQELBQAEggIANU8jHpbA0tajWYS8igce3Nq4waHGrcZOpJbt
# fffFG1FslOd/0cX9rXTKaekkxACu5yj9Em0YdP2U4vUjbB8uDfqpPH7LIdIkTpAx
# EdSktX4W8EJnEq7qIEJVToL9/vKNB94xpIMC6WVMGkUPy7nn/SsHE2sk7q6myIXs
# nNzWTkPlyCc665cnaDA2xBLNvlcRjnrBHP/dLU6L7CvsJUbxWOxT3T8ppxNCUF9u
# 2u6CidGYY52jFKBw1QxnoHLjGkUWB3zYTKeRIj4IaW2jdYqLds9/kIgt9IFrrkYr
# 0EbddIaG87ybbv6Hjp6C6qrA6krAi+WQ6Dh3ZGtKocAbanw056eDQp2D3xtmS813
# /3Tdu4rCT324x9lkdmhms/mhAZnJe5r2X/fL/VkBQtR4z1lry66w3Ef3c3syDjC6
# QzQz050N5UFdlQRa7Q8RlZf/eQxX6cubg5UDkYTuYnbYUof6MG8eY54EDVU5RRhO
# l3S6XNNS4GGde3zyj1rkWG5AtGgsFXle9V4N4Gvytl1eQARUECJH3vjadSJ+5plp
# ZtXFwJfeHzJNzl0dCXeItU7uY7DvZIZervVYlV9X0KIRzhxDMTJGpx+WYOecxuYm
# AI/P3asnAbX5sSHvMGaA9CHO3MqRnFe5VGo05CutnkNMiVALXvs9LV1oLHTjMZ8Y
# AfRdcW0=
# SIG # End signature block
