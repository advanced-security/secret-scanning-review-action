# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubGistTypeName = 'GitHub.Gist'
    GitHubGistCommitTypeName = 'GitHub.GistCommit'
    GitHubGistForkTypeName = 'GitHub.GistFork'
    GitHubGistSummaryTypeName = 'GitHub.GistSummary'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubGist
{
<#
    .SYNOPSIS
        Retrieves gist information from GitHub.

    .DESCRIPTION
        Retrieves gist information from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to retrieve.

    .PARAMETER Sha
        The specific revision of the gist that you wish to retrieve.

    .PARAMETER Forks
        Gets the forks of the specified gist.

    .PARAMETER Commits
        Gets the commits of the specified gist.

    .PARAMETER UserName
        Gets public gists for the specified user.

    .PARAMETER Path
        Download the files that are part of the specified gist to this path.

    .PARAMETER Force
        If downloading files, this will overwrite any files with the same name in the provided path.

    .PARAMETER Current
        Gets the authenticated user's gists.

    .PARAMETER Starred
        Gets the authenticated user's starred gists.

    .PARAMETER Public
        Gets public gists sorted by most recently updated to least recently updated.
        The results will be limited to the first 3000.

    .PARAMETER Since
        Only gists updated at or after this time are returned.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.Gist
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .EXAMPLE
        Get-GitHubGist -Starred

        Gets all starred gists for the current authenticated user.

    .EXAMPLE
        Get-GitHubGist -Public -Since ((Get-Date).AddDays(-2))

        Gets all public gists that have been updated within the past two days.

    .EXAMPLE
        Get-GitHubGist -Gist 6cad326836d38bd3a7ae

        Gets octocat's "hello_world.rb" gist.
#>
    [CmdletBinding(
        DefaultParameterSetName='Current',
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistTypeName})]
    [OutputType({$script:GitHubGistCommitTypeName})]
    [OutputType({$script:GitHubGistForkTypeName})]
    [OutputType({$script:GitHubGistSummaryTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Id',
            Position = 1)]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Download',
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(ParameterSetName='Id')]
        [Parameter(ParameterSetName='Download')]
        [ValidateNotNullOrEmpty()]
        [string] $Sha,

        [Parameter(ParameterSetName='Id')]
        [switch] $Forks,

        [Parameter(ParameterSetName='Id')]
        [switch] $Commits,

        [Parameter(
            Mandatory,
            ParameterSetName='User')]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(
            Mandatory,
            ParameterSetName='Download',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(ParameterSetName='Download')]
        [switch] $Force,

        [Parameter(ParameterSetName='Current')]
        [switch] $Current,

        [Parameter(ParameterSetName='Current')]
        [switch] $Starred,

        [Parameter(ParameterSetName='Public')]
        [switch] $Public,

        [Parameter(ParameterSetName='User')]
        [Parameter(ParameterSetName='Current')]
        [Parameter(ParameterSetName='Public')]
        [DateTime] $Since,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = [String]::Empty
    $description = [String]::Empty
    $outputType = $script:GitHubGistSummaryTypeName

    if ($PSCmdlet.ParameterSetName -in ('Id', 'Download'))
    {
        $telemetryProperties['ById'] = $true

        if ($PSBoundParameters.ContainsKey('Sha'))
        {
            if ($Forks -or $Commits)
            {
                $message = 'Cannot check for forks or commits of a specific SHA.  Do not specify SHA if you want to list out forks or commits.'
                Write-Log -Message $message -Level Error
                throw $message
            }

            $telemetryProperties['SpecifiedSha'] = $true

            $uriFragment = "gists/$Gist/$Sha"
            $description = "Getting gist $Gist with specified Sha"
            $outputType = $script:GitHubGistTypeName
        }
        elseif ($Forks)
        {
            $uriFragment = "gists/$Gist/forks"
            $description = "Getting forks of gist $Gist"
            $outputType = $script:GitHubGistForkTypeName
        }
        elseif ($Commits)
        {
            $uriFragment = "gists/$Gist/commits"
            $description = "Getting commits of gist $Gist"
            $outputType = $script:GitHubGistCommitTypeName
        }
        else
        {
            $uriFragment = "gists/$Gist"
            $description = "Getting gist $Gist"
            $outputType = $script:GitHubGistTypeName
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'User')
    {
        $telemetryProperties['ByUserName'] = $true

        $uriFragment = "users/$UserName/gists"
        $description = "Getting public gists for $UserName"
        $outputType = $script:GitHubGistSummaryTypeName
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Current')
    {
        $telemetryProperties['CurrentUser'] = $true
        $outputType = $script:GitHubGistSummaryTypeName

        if ((Test-GitHubAuthenticationConfigured) -or (-not [String]::IsNullOrEmpty($AccessToken)))
        {
            if ($Starred)
            {
                $uriFragment = 'gists/starred'
                $description = 'Getting starred gists for current authenticated user'
            }
            else
            {
                $uriFragment = 'gists'
                $description = 'Getting gists for current authenticated user'
            }
        }
        else
        {
            if ($Starred)
            {
                $message = 'Starred can only be specified for authenticated users.  Either call Set-GitHubAuthentication first, or provide a value for the AccessToken parameter.'
                Write-Log -Message $message -Level Error
                throw $message
            }

            $message = 'Specified -Current, but not currently authenticated.  Either call Set-GitHubAuthentication first, or provide a value for the AccessToken parameter.'
            Write-Log -Message $message -Level Error
            throw $message
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Public')
    {
        $telemetryProperties['Public'] = $true
        $outputType = $script:GitHubGistSummaryTypeName

        $uriFragment = "gists/public"
        $description = 'Getting public gists'
    }

    $getParams = @()
    $sinceFormattedTime = [String]::Empty
    if ($null -ne $Since)
    {
        $sinceFormattedTime = $Since.ToUniversalTime().ToString('o')
        $getParams += "since=$sinceFormattedTime"
    }

    $params = @{
        'UriFragment' = $uriFragment + '?' +  ($getParams -join '&')
        'Description' =  $description
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = (Invoke-GHRestMethodMultipleResult @params |
        Add-GitHubGistAdditionalProperties -TypeName $outputType)

    if ($PSCmdlet.ParameterSetName -eq 'Download')
    {
        Save-GitHubGist -GistObject $result -Path $Path -Force:$Force
    }
    else
    {
        if ($result.truncated -eq $true)
        {
            $message = @(
                'Response has been truncated.  The API will only return the first 3000 gist results',
                'the first 300 files within the gist, and the first 1 Mb of an individual',
                'file.  If the file has been truncated, you can call',
                '(Invoke-WebRequest -UseBasicParsing -Method Get -Uri <raw_url>).Content)',
                'where <raw_url> is the value of raw_url for the file in question.  Be aware that',
                'for files larger than 10 Mb, you''ll need to clone the gist via the URL provided',
                'by git_pull_url.')

            Write-Log -Message ($message -join ' ') -Level Warning
        }

        return $result
    }
}

function Save-GitHubGist
{
<#
    .SYNOPSIS
        Downloads the contents of a gist to the specified file path.

    .DESCRIPTION
        Downloads the contents of a gist to the specified file path.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER GistObject
        The Gist PSCustomObject

    .PARAMETER Path
        Download the files that are part of the specified gist to this path.

    .PARAMETER Force
        If downloading files, this will overwrite any files with the same name in the provided path.

    .NOTES
        Internal-only helper
#>
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $GistObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [switch] $Force
    )

    # First, check to see if the response is missing files.
    if ($GistObject.truncated)
    {
        $message = @(
            'Gist response has been truncated.  The API will only return information on',
            'the first 300 files within a gist. To download this entire gist,',
            'you''ll need to clone it via the URL provided by git_pull_url',
            "[$($GistObject.git_pull_url)].")

        Write-Log -Message ($message -join ' ') -Level Error
        throw $message
    }

    # Then check to see if there are files we won't be able to download
    $files = $GistObject.files | Get-Member -Type NoteProperty | Select-Object -ExpandProperty Name
    foreach ($fileName in $files)
    {
        if ($GistObject.files.$fileName.truncated -and
            ($GistObject.files.$fileName.size -gt 10mb))
        {
            $message = @(
                "At least one file ($fileName) in this gist is larger than 10mb.",
                'In order to download this gist, you''ll need to clone it via the URL',
                "provided by git_pull_url [$($GistObject.git_pull_url)].")

            Write-Log -Message ($message -join ' ') -Level Error
            throw $message
        }
    }

    # Finally, we're ready to directly save the non-truncated files,
    # and download the ones that are between 1 - 10mb.
    $originalSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    try
    {
        $headers = @{}
        $AccessToken = Get-AccessToken -AccessToken $AccessToken
        if (-not [String]::IsNullOrEmpty($AccessToken))
        {
            $headers['Authorization'] = "token $AccessToken"
        }

        $Path = Resolve-UnverifiedPath -Path $Path
        $null = New-Item -Path $Path -ItemType Directory -Force
        foreach ($fileName in $files)
        {
            $filePath = Join-Path -Path $Path -ChildPath $fileName
            if ((Test-Path -Path $filePath -PathType Leaf) -and (-not $Force))
            {
                $message = "File already exists at path [$filePath].  Choose a different path or specify -Force"
                Write-Log -Message $message -Level Error
                throw $message
            }

            if ($GistObject.files.$fileName.truncated)
            {
                # Disable Progress Bar in function scope during Invoke-WebRequest
                $ProgressPreference = 'SilentlyContinue'

                $webRequestParams = @{
                    UseBasicParsing = $true
                    Method = 'Get'
                    Headers = $headers
                    Uri = $GistObject.files.$fileName.raw_url
                    OutFile = $filePath
                }

                Invoke-WebRequest @webRequestParams
            }
            else
            {
                $stream = New-Object -TypeName System.IO.StreamWriter -ArgumentList ($filePath)
                try
                {
                    $stream.Write($GistObject.files.$fileName.content)
                }
                finally
                {
                    $stream.Close()
                }
            }
        }
    }
    finally
    {
        [Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
    }
}

filter Remove-GitHubGist
{
<#
    .SYNOPSIS
        Removes/deletes a gist from GitHub.

    .DESCRIPTION
        Removes/deletes a gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to retrieve.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .EXAMPLE
        Remove-GitHubGist -Gist 6cad326836d38bd3a7ae

        Removes octocat's "hello_world.rb" gist (assuming you have permission).

    .EXAMPLE
        Remove-GitHubGist -Gist 6cad326836d38bd3a7ae -Confirm:$false

        Removes octocat's "hello_world.rb" gist (assuming you have permission).
        Will not prompt for confirmation, as -Confirm:$false was specified.

    .EXAMPLE
        Remove-GitHubGist -Gist 6cad326836d38bd3a7ae -Force

        Removes octocat's "hello_world.rb" gist (assuming you have permission).
        Will not prompt for confirmation, as -Force was specified.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    [Alias('Delete-GitHubGist')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Gist, "Delete gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist"
        'Method' = 'Delete'
        'Description' =  "Removing gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Copy-GitHubGist
{
<#
    .SYNOPSIS
        Forks a gist from GitHub.

    .DESCRIPTION
        Forks a gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to fork.

    .PARAMETER PassThru
        Returns the newly created gist fork.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.GistSummary

    .EXAMPLE
        Copy-GitHubGist -Gist 6cad326836d38bd3a7ae

        Forks octocat's "hello_world.rb" gist.

    .EXAMPLE
        $result = Fork-GitHubGist -Gist 6cad326836d38bd3a7ae -PassThru

        Forks octocat's "hello_world.rb" gist.  This is using the alias for the command.
        The result is the same whether you use Copy-GitHubGist or Fork-GitHubGist.
        Specifying the -PassThru switch enables you to get a reference to the newly created fork.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistSummaryTypeName})]
    [Alias('Fork-GitHubGist')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    if (-not $PSCmdlet.ShouldProcess($Gist, "Forking gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/forks"
        'Method' = 'Post'
        'Description' =  "Forking gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = (Invoke-GHRestMethod @params |
        Add-GitHubGistAdditionalProperties -TypeName $script:GitHubGistSummaryTypeName)

    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Set-GitHubGistStar
{
<#
    .SYNOPSIS
        Changes the starred state of a gist on GitHub for the current authenticated user.

    .DESCRIPTION
        Changes the starred state of a gist on GitHub for the current authenticated user.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific Gist that you wish to change the starred state for.

    .PARAMETER Star
        Include this switch to star the gist.  Exclude the switch (or use -Star:$false) to
        remove the star.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .EXAMPLE
        Set-GitHubGistStar -Gist 6cad326836d38bd3a7ae -Star

        Stars octocat's "hello_world.rb" gist.

    .EXAMPLE
        Set-GitHubGistStar -Gist 6cad326836d38bd3a7ae

        Unstars octocat's "hello_world.rb" gist.

    .EXAMPLE
        Get-GitHubGist -Gist 6cad326836d38bd3a7ae | Set-GitHubGistStar -Star:$false

        Unstars octocat's "hello_world.rb" gist.

#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [switch] $Star,

        [string] $AccessToken
    )

    Write-InvocationLog
    Set-TelemetryEvent -EventName $MyInvocation.MyCommand.Name

    $PSBoundParameters.Remove('Star')
    if ($Star)
    {
        return Add-GitHubGistStar @PSBoundParameters
    }
    else
    {
        return Remove-GitHubGistStar @PSBoundParameters
    }
}

filter Add-GitHubGistStar
{
<#
    .SYNOPSIS
        Star a gist from GitHub.

    .DESCRIPTION
        Star a gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific Gist that you wish to star.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .EXAMPLE
        Add-GitHubGistStar -Gist 6cad326836d38bd3a7ae

        Stars octocat's "hello_world.rb" gist.

    .EXAMPLE
        Star-GitHubGist -Gist 6cad326836d38bd3a7ae

        Stars octocat's "hello_world.rb" gist.  This is using the alias for the command.
        The result is the same whether you use Add-GitHubGistStar or Star-GitHubGist.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [Alias('Star-GitHubGist')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [string] $AccessToken
    )

    Write-InvocationLog

    if (-not $PSCmdlet.ShouldProcess($Gist, "Starring gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/star"
        'Method' = 'Put'
        'Description' =  "Starring gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Remove-GitHubGistStar
{
<#
    .SYNOPSIS
        Unstar a gist from GitHub.

    .DESCRIPTION
        Unstar a gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to unstar.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .EXAMPLE
        Remove-GitHubGistStar -Gist 6cad326836d38bd3a7ae

        Unstars octocat's "hello_world.rb" gist.

    .EXAMPLE
        Unstar-GitHubGist -Gist 6cad326836d38bd3a7ae

        Unstars octocat's "hello_world.rb" gist.  This is using the alias for the command.
        The result is the same whether you use Remove-GitHubGistStar or Unstar-GitHubGist.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [Alias('Unstar-GitHubGist')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [string] $AccessToken
    )

    Write-InvocationLog

    if (-not $PSCmdlet.ShouldProcess($Gist, "Unstarring gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/star"
        'Method' = 'Delete'
        'Description' =  "Unstarring gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Test-GitHubGistStar
{
<#
    .SYNOPSIS
        Checks if a gist from GitHub is starred.

    .DESCRIPTION
        Checks if a gist from GitHub is starred.
        Will return $false if it isn't starred, as well as if it couldn't be checked
        (due to permissions or non-existence).

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to check.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        Boolean indicating if the gist was both found and determined to be starred.

    .EXAMPLE
        Test-GitHubGistStar -Gist 6cad326836d38bd3a7ae

        Returns $true if the gist is starred, or $false if isn't starred or couldn't be checked
        (due to permissions or non-existence).
#>
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([bool])]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/star"
        'Method' = 'Get'
        'Description' =  "Checking if gist $Gist is starred"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'ExtendedResult' = $true
    }

    try
    {
        $response = Invoke-GHRestMethod @params
        return $response.StatusCode -eq 204
    }
    catch
    {
        return $false
    }
}

filter New-GitHubGist
{
<#
    .SYNOPSIS
        Creates a new gist on GitHub.

    .DESCRIPTION
        Creates a new gist on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER File
        An array of filepaths that should be part of this gist.
        Use this when you have multiple files that should be part of a gist, or when you simply
        want to reference an existing file on disk.

    .PARAMETER FileName
        The name of the file that Content should be stored in within the newly created gist.

    .PARAMETER Content
        The content of a single file that should be part of the gist.

    .PARAMETER Description
        A descriptive name for this gist.

    .PARAMETER Public
        When specified, the gist will be public and available for anyone to see.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        String - Filename(s) of file(s) that should be the content of the gist.

    .OUTPUTS
        GitHub.GitDetail

    .EXAMPLE
        New-GitHubGist -FileName 'sample.txt' -Content 'Body of my file.' -Description 'This is my gist!' -Public

        Creates a new public gist with a single file named 'sample.txt' that has the body of "Body of my file."

    .EXAMPLE
        New-GitHubGist -File 'c:\files\foo.txt' -Description 'This is my gist!'

        Creates a new private gist with a single file named 'foo.txt'.  Will populate it with the
        content of the file at c:\files\foo.txt.

    .EXAMPLE
        New-GitHubGist -File ('c:\files\foo.txt', 'c:\other\bar.txt', 'c:\octocat.ps1') -Description 'This is my gist!'

        Creates a new private gist with a three files named 'foo.txt', 'bar.txt' and 'octocat.ps1'.
        Each will be populated with the content from the file on disk at the specified location.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='FileRef',
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ParameterSetName='FileRef',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]] $File,

        [Parameter(
            Mandatory,
            ParameterSetName='Content',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $FileName,

        [Parameter(
            Mandatory,
            ParameterSetName='Content',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Content,

        [string] $Description,

        [switch] $Public,

        [string] $AccessToken
    )

    begin
    {
        $files = @{}
    }

    process
    {
        foreach ($path in $File)
        {
            $path = Resolve-UnverifiedPath -Path $path
            if (-not (Test-Path -Path $path -PathType Leaf))
            {
                $message = "Specified file [$path] could not be found or was inaccessible."
                Write-Log -Message $message -Level Error
                throw $message
            }

            $content = [System.IO.File]::ReadAllText($path)
            $fileName = (Get-Item -Path $path).Name

            if ($files.ContainsKey($fileName))
            {
                $message = "You have specified more than one file with the same name [$fileName].  gists don't have a concept of directory structures, so please ensure each file has a unique name."
                Write-Log -Message $message -Level Error
                throw $message
            }

            $files[$fileName] = @{ 'content' = $Content }
        }
    }

    end
    {
        Write-InvocationLog

        $telemetryProperties = @{}

        if ($PSCmdlet.ParameterSetName -eq 'Content')
        {
            $files[$FileName] = @{ 'content' = $Content }
        }

        if (($files.Keys.StartsWith('gistfile') | Where-Object { $_ -eq $true }).Count -gt 0)
        {
            $message = "Don't name your files starting with 'gistfile'. This is the format of the automatic naming scheme that Gist uses internally."
            Write-Log -Message $message -Level Error
            throw $message
        }

        $hashBody = @{
            'description' = $Description
            'public' = $Public.ToBool()
            'files' = $files
        }

        if (-not $PSCmdlet.ShouldProcess('Create new gist'))
        {
            return
        }

        $params = @{
            'UriFragment' = "gists"
            'Body' = (ConvertTo-Json -InputObject $hashBody)
            'Method' = 'Post'
            'Description' =  "Creating a new gist"
            'AccessToken' = $AccessToken
            'TelemetryEventName' = $MyInvocation.MyCommand.Name
            'TelemetryProperties' = $telemetryProperties
        }

        return (Invoke-GHRestMethod @params |
            Add-GitHubGistAdditionalProperties -TypeName $script:GitHubGistTypeName)
    }
}

filter Set-GitHubGist
{
<#
    .SYNOPSIS
        Updates a gist on GitHub.

    .DESCRIPTION
        Updates a gist on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID for the gist to update.

    .PARAMETER Update
        A hashtable of files to update in the gist.
        The key should be the name of the file in the gist as it exists right now.
        The value should be another hashtable with the following optional key/value pairs:
            fileName - Specify a new name here if you want to rename the file.
            filePath - Specify a path to a file on disk if you wish to update the contents of the
                       file in the gist with the contents of the specified file.
                       Should not be specified if you use 'content' (below)
            content  - Directly specify the raw content that the file in the gist should be updated with.
                       Should not be used if you use 'filePath' (above).

    .PARAMETER Delete
        A list of filenames that should be removed from this gist.

    .PARAMETER Description
        New description for this gist.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER PassThru
        Returns the updated gist.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.GistDetail

    .EXAMPLE
        Set-GitHubGist -Gist 6cad326836d38bd3a7ae -Description 'This is my newer description'

        Updates the description for the specified gist.

    .EXAMPLE
        Set-GitHubGist -Gist 6cad326836d38bd3a7ae -Delete 'hello_world.rb' -Force

        Deletes the 'hello_world.rb' file from the specified gist without prompting for confirmation.

    .EXAMPLE
        Set-GitHubGist -Gist 6cad326836d38bd3a7ae -Delete 'hello_world.rb' -Description 'This is my newer description'

        Deletes the 'hello_world.rb' file from the specified gist and updates the description.

    .EXAMPLE
        Set-GitHubGist -Gist 6cad326836d38bd3a7ae -Update @{'hello_world.rb' = @{ 'fileName' = 'hello_universe.rb' }}

        Renames the 'hello_world.rb' file in the specified gist to be 'hello_universe.rb'.

    .EXAMPLE
        Set-GitHubGist -Gist 6cad326836d38bd3a7ae -Update @{'hello_world.rb' = @{ 'fileName' = 'hello_universe.rb' }}

        Renames the 'hello_world.rb' file in the specified gist to be 'hello_universe.rb'.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Content',
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [hashtable] $Update,

        [string[]] $Delete,

        [string] $Description,

        [switch] $Force,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $files = @{}

    $shouldProcessMessage = 'Update gist'

    # Mark the files that should be deleted.
    if ($Delete.Count -gt 0)
    {
        $ConfirmPreference = 'Low'
        $shouldProcessMessage = 'Update gist (and remove files)'

        foreach ($toDelete in $Delete)
        {
            $files[$toDelete] = $null
        }
    }

    # Then figure out which ones need content updates and/or file renames
    if ($null -ne $Update)
    {
        foreach ($toUpdate in $Update.GetEnumerator())
        {
            $currentFileName = $toUpdate.Key

            $providedContent = $toUpdate.Value.Content
            $providedFileName = $toUpdate.Value.FileName
            $providedFilePath = $toUpdate.Value.FilePath

            if (-not [String]::IsNullOrWhiteSpace($providedContent))
            {
                $files[$currentFileName] = @{ 'content' = $providedContent }
            }

            if (-not [String]::IsNullOrWhiteSpace($providedFilePath))
            {
                if (-not [String]::IsNullOrWhiteSpace($providedContent))
                {
                    $message = "When updating a file [$currentFileName], you cannot provide both a path to a file [$providedFilePath] and the raw content."
                    Write-Log -Message $message -Level Error
                    throw $message
                }

                $providedFilePath = Resolve-Path -Path $providedFilePath
                if (-not (Test-Path -Path $providedFilePath -PathType Leaf))
                {
                    $message = "Specified file [$providedFilePath] could not be found or was inaccessible."
                    Write-Log -Message $message -Level Error
                    throw $message
                }

                $newContent = [System.IO.File]::ReadAllText($providedFilePath)
                $files[$currentFileName] = @{ 'content' = $newContent }
            }

            # The user has chosen to rename the file.
            if (-not [String]::IsNullOrWhiteSpace($providedFileName))
            {
                $files[$currentFileName] = @{ 'filename' = $providedFileName }
            }
        }
    }

    $hashBody = @{}
    if (-not [String]::IsNullOrWhiteSpace($Description)) { $hashBody['description'] = $Description }
    if ($files.Keys.count -gt 0) { $hashBody['files'] = $files }

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Gist, $shouldProcessMessage))
    {
        return
    }

    $ConfirmPreference = 'None'
    $params = @{
        'UriFragment' = "gists/$Gist"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Patch'
        'Description' =  "Updating gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    try
    {
        $result = (Invoke-GHRestMethod @params |
            Add-GitHubGistAdditionalProperties -TypeName $script:GitHubGistTypeName)

        if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
        {
            return $result
        }
    }
    catch
    {
        if ($_.Exception.Message -like '*(422)*')
        {
            $message = 'This error can happen if you try to delete a file that doesn''t exist.  Be aware that casing matters.  ''A.txt'' is not the same as ''a.txt''.'
            Write-Log -Message $message -Level Warning
        }

        throw
    }
}

function Set-GitHubGistFile
{
<#
    .SYNOPSIS
        Updates content of file(s) in an existing gist on GitHub,
        or adds them if they aren't already part of the gist.

    .DESCRIPTION
        Updates content of file(s) in an existing gist on GitHub,
        or adds them if they aren't already part of the gist.

        This is a helper function built on top of Set-GitHubGist.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID for the gist to update.

    .PARAMETER File
        An array of filepaths that should be part of this gist.
        Use this when you have multiple files that should be part of a gist, or when you simply
        want to reference an existing file on disk.

    .PARAMETER FileName
        The name of the file that Content should be stored in within the newly created gist.

    .PARAMETER Content
        The content of a single file that should be part of the gist.

    .PARAMETER PassThru
        Returns the updated gist.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.Gist

    .EXAMPLE
        Set-GitHubGistFile -Gist 1234567 -Content 'Body of my file.' -FileName 'sample.txt'

        Adds a file named 'sample.txt' that has the body of "Body of my file." to the existing
        specified gist, or updates the contents of 'sample.txt' in the gist if is already there.

    .EXAMPLE
        Set-GitHubGistFile -Gist 1234567 -File 'c:\files\foo.txt'

        Adds the file 'foo.txt' to the existing specified gist, or updates its content if it
        is already there.

    .EXAMPLE
        Set-GitHubGistFile -Gist 1234567 -File ('c:\files\foo.txt', 'c:\other\bar.txt', 'c:\octocat.ps1')

        Adds all three files to the existing specified gist, or updates the contents of the files
        in the gist if they are already there.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Content',
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistTypeName})]
    [Alias('Add-GitHubGistFile')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "", Justification="This is a helper method for Set-GitHubGist which will handle ShouldProcess.")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ParameterSetName='FileRef',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string[]] $File,

        [Parameter(
            Mandatory,
            ParameterSetName='Content',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $FileName,

        [Parameter(
            Mandatory,
            ParameterSetName='Content',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $Content,

        [switch] $PassThru,

        [string] $AccessToken
    )

    begin
    {
        $files = @{}
    }

    process
    {
        foreach ($path in $File)
        {
            $path = Resolve-UnverifiedPath -Path $path
            if (-not (Test-Path -Path $path -PathType Leaf))
            {
                $message = "Specified file [$path] could not be found or was inaccessible."
                Write-Log -Message $message -Level Error
                throw $message
            }

            $fileName = (Get-Item -Path $path).Name
            $files[$fileName] = @{ 'filePath' = $path }
        }
    }

    end
    {
        Write-InvocationLog
        Set-TelemetryEvent -EventName $MyInvocation.MyCommand.Name

        if ($PSCmdlet.ParameterSetName -eq 'Content')
        {
            $files[$FileName] = @{ 'content' = $Content }
        }

        $params = @{
            'Gist' = $Gist
            'Update' = $files
            'PassThru' = (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
            'AccessToken' = $AccessToken
        }

        return (Set-GitHubGist @params)
    }
}

function Remove-GitHubGistFile
{
<#
    .SYNOPSIS
        Removes one or more files from an existing gist on GitHub.

    .DESCRIPTION
        Removes one or more files from an existing gist on GitHub.

        This is a helper function built on top of Set-GitHubGist.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID for the gist to update.

    .PARAMETER FileName
        An array of filenames (no paths, just names) to remove from the gist.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER PassThru
        Returns the updated gist.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.Gist

    .EXAMPLE
        Remove-GitHubGistFile -Gist 1234567 -FileName ('foo.txt')

        Removes the file 'foo.txt' from the specified gist.

    .EXAMPLE
        Remove-GitHubGistFile -Gist 1234567 -FileName ('foo.txt') -Force

        Removes the file 'foo.txt' from the specified gist without prompting for confirmation.

    .EXAMPLE
        @('foo.txt', 'bar.txt') | Remove-GitHubGistFile -Gist 1234567

        Removes the files 'foo.txt' and 'bar.txt' from the specified gist.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistTypeName})]
    [Alias('Delete-GitHubGistFile')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "", Justification="This is a helper method for Set-GitHubGist which will handle ShouldProcess.")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string[]] $FileName,

        [switch] $Force,

        [switch] $PassThru,

        [string] $AccessToken
    )

    begin
    {
        $files = @()
    }

    process
    {
        foreach ($name in $FileName)
        {
            $files += $name
        }
    }

    end
    {
        Write-InvocationLog
        Set-TelemetryEvent -EventName $MyInvocation.MyCommand.Name

        $params = @{
            'Gist' = $Gist
            'Delete' = $files
            'Force' = $Force
            'Confirm' = ($Confirm -eq $true)
            'PassThru' = (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
            'AccessToken' = $AccessToken
        }

        return (Set-GitHubGist @params)
    }
}

filter Rename-GitHubGistFile
{
<#
    .SYNOPSIS
        Renames a file in a gist on GitHub.

    .DESCRIPTION
        Renames a file in a gist on GitHub.

        This is a helper function built on top of Set-GitHubGist.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID for the gist to update.

    .PARAMETER FileName
        The current file in the gist to be renamed.

    .PARAMETER NewName
        The new name of the file for the gist.

    .PARAMETER PassThru
        Returns the updated gist.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.Gist

    .EXAMPLE
        Rename-GitHubGistFile -Gist 1234567 -FileName 'foo.txt' -NewName 'bar.txt'

        Renames the file 'foo.txt' to 'bar.txt' in the specified gist.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "", Justification="This is a helper method for Set-GitHubGist which will handle ShouldProcess.")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(
            Mandatory,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $FileName,

        [Parameter(
            Mandatory,
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $NewName,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog
    Set-TelemetryEvent -EventName $MyInvocation.MyCommand.Name

    $params = @{
        'Gist' = $Gist
        'Update' = @{$FileName = @{ 'fileName' = $NewName }}
        'PassThru' = (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
        'AccessToken' = $AccessToken
    }

    return (Set-GitHubGist @params)
}

filter Add-GitHubGistAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Gist objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Gist
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary
#>
    [CmdletBinding()]
    [OutputType({$script:GitHubGistTypeName})]
    [OutputType({$script:GitHubGistFormTypeName})]
    [OutputType({$script:GitHubGistSummaryTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubGistSummaryTypeName
    )

    if ($TypeName -eq $script:GitHubGistCommitTypeName)
    {
        return Add-GitHubGistCommitAdditionalProperties -InputObject $InputObject
    }
    elseif ($TypeName -eq $script:GitHubGistForkTypeName)
    {
        return Add-GitHubGistForkAdditionalProperties -InputObject $InputObject
    }

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            Add-Member -InputObject $item -Name 'GistId' -Value $item.id -MemberType NoteProperty -Force

            @('user', 'owner') |
                ForEach-Object {
                    if ($null -ne $item.$_)
                    {
                        $null = Add-GitHubUserAdditionalProperties -InputObject $item.$_
                    }
                }

            if ($null -ne $item.forks)
            {
                $item.forks = Add-GitHubGistForkAdditionalProperties -InputObject $item.forks
            }

            if ($null -ne $item.history)
            {
                $item.history = Add-GitHubGistCommitAdditionalProperties -InputObject $item.history
            }
        }

        Write-Output $item
    }
}

filter Add-GitHubGistCommitAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub GistCommit objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.GistCommit
#>
    [CmdletBinding()]
    [OutputType({$script:GitHubGistCommitTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubGistCommitTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $hostName = $(Get-GitHubConfiguration -Name 'ApiHostName')
            if ($item.url -match "^https?://(?:www\.|api\.|)$hostName/gists/([^/]+)/(.+)$")
            {
                $id = $Matches[1]
                $sha = $Matches[2]

                if ($sha -ne $item.version)
                {
                    $message = "The gist commit url no longer follows the expected pattern.  Please contact the PowerShellForGitHubTeam: $item.uri"
                    Write-Log -Message $message -Level Warning
                }
            }

            Add-Member -InputObject $item -Name 'GistId' -Value $id -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'Sha' -Value $item.version -MemberType NoteProperty -Force

            $null = Add-GitHubUserAdditionalProperties -InputObject $item.user
        }

        Write-Output $item
    }
}

filter Add-GitHubGistForkAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Gist Fork objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.GistFork
#>
    [CmdletBinding()]
    [OutputType({$script:GitHubGistForkTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubGistForkTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            Add-Member -InputObject $item -Name 'GistId' -Value $item.id -MemberType NoteProperty -Force

            # See here for why we need to work with both 'user' _and_ 'owner':
            # https://github.community/t/gist-api-v3-documentation-incorrect-for-forks/122545
            @('user', 'owner') |
            ForEach-Object {
                if ($null -ne $item.$_)
                {
                    $null = Add-GitHubUserAdditionalProperties -InputObject $item.$_
                }
            }
        }

        Write-Output $item
    }
}
# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAh4sA9mSDSlaxQ
# 2s4kYld7oPdDLqa5eOOehJlvmRGoE6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIO51O/HGZbWRPIYFteMmYcOB
# CzJy2QTbnhY7TchlUOckMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBqcvqP16jNI62pbmBNMFdZfGgUe25xpOeNPkHut0o762kxn5wrntsK
# t1wvxrEJv9qtVpaw4p6YXoKsy70fqV8RgqcfAuQxSd76kaT35tmfXk8n/d+LXCWk
# 06aH+ihmEfJ9iyvbO07hRjIuNC28yThFh+BnNEsNW6kSDLGy6HPG0rWgob82BVsK
# PezxepkOSnisn/hJzLzXC7B0Z1S2Wlyytu1xFFVv6AGRNPMFf+W4YNOHzEIQpPb5
# Xo5ywHGA1EiKBGvNLLA509Sx4GB5k+RsRg6H7nY7uTBTKExJv9mO/jx4hAsZijqT
# TnFR2/EOrETlE9GNmWO1N4dwEC2eo+fuoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFDGFk81jOeelhlymrFFXdOXGM8nnpx9PAYMvjS5wrtiAgZlVtVS
# yhUYEzIwMjMxMTIxMTczNTI3LjE4MlowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjozMzAz
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAABzIal3Dfr2WEtAAEAAAHMMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIwMVoXDTI0MDIwMTE5MTIwMVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjozMzAzLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAMyxIgXx702YRz7zc1VkaBZZmL/AFi3zOHEB9IYz
# vHDsrsJsD/UDgaGi8++Qhjzve2fLN3Jl77pgdfH5F3rXyVAOaablfh66Jgbnct3t
# Ygr4N36HKLQf3sPoczhnMaqi+bAHR9neWH6mEkug9P73KtMsXOSQrDZVxvvBcwHO
# IPQxVVhubBGVFrKlOe2Xf0gQ0ISKNb2PowSVPJc/bOtzQ62FA3lGsxNjmJmNrczI
# cIWZgwaKeYd+2xobdh2LwZrwFCN22hObl1WGeqzaoo0Q6plKifbxHhd9/S2UkvlQ
# fIjdvLAf/7NB4m7yqexIKLxUU86xkRvpxnOFcdoCJIa10oBtBFoAiETFshSl4nKk
# LuX7CooLcE70AMa6kH1mBQVtK/kQIWMwPNt+bwznPPYDjFg09Bepm/TAZYv6NO9v
# uQViIM8977NHIFvOatKk5sHteqOrNQU0qXCn4zHXmTUXsUyzkQza4brwhCx0AYGR
# ltIOa4aaM9tnt22Kb5ce6Hc1LomZdg9LuuKSkJtSwxkyfl5bGJYUiTp/TSyRHhEt
# aaHQ3o6r4pgjV8Dn0vMaIBs6tzGC9CRGjc4PijUlb3PVM0zARuTM+tcyjyusay4a
# jJhZyyb3GF3QZchEccLrifNsjd7QbmOoSxZBzi5pB5JHKvvQpGKPNXJaONh+wS29
# UyUnAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUgqYcZF08h0tFe2xHldFLIzf7aQww
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAHkZQyj1e+JSXeDva7yhBOisgoOgB2BZ
# ngtD350ARAKZp62xOGTFs2bXmx67sabCll2ExA3xM110aSLmzkh75oDZUSj29nPf
# WWW6wcFcBWtC2m59Cq0gD7aee6x9pi+KK2vqnmRVPrT0shM5iB0pFYSl/H/jJPlH
# 3Ix4rGjGSTy3IaIY9krjRJPlnXg490l9VuRh4K+UtByWxfX5YFk3H9dm9rMmZeO9
# iNO4bRBtmnHDhk7dmh99BjFlhHOfTPjVTswMWVejaKF9qx1se65rqSkfEn0AihR6
# +HebO9TFinS7TPfBgM+ku6j4zZViHxc4JQHS7vnEbdLn73xMqYVupliCmCvo/5gp
# 5qjZikHWLOzznRhLO7BpfuRHEBRGWY3+Pke/jBpuc59lvfqYOomngh4abA+3Ajy0
# Q+y5ECbKt56PKGRlXt1+Ang3zdAGGkdVmUHgWaUlHzIXdoHXlBbq3DgJof48wgO5
# 3oZ44k7hxAT6VNzqsgmY3hx+LZNMbt7j1O+EJd8FLanM7Jv1h6ZKbSSuTyMmHrOB
# 4arO2TvN7B8T7eyFBFzvixctjnym9WjOd+B8a/LWWVurg57L3oqi7CK6EO3G4qVO
# dbunDvFo0+Egyw7Fbx2lKn3XkW0p86opH918k6xscNIlj+KInPiZYoAajJ14szrM
# uaiFEI9aT9DmMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AE5O5ne5h+KKFLjNFOjGKwO32YmkoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpB0J8MCIYDzIwMjMxMTIxMTQ1
# MTQwWhgPMjAyMzExMjIxNDUxNDBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# QnwCAQAwCgIBAAICE9kCAf8wBwIBAAICEtwwCgIFAOkIk/wCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAgVrVapv+BZfWUgGuap8gDW2qRIMzUlkZ2zmFGPgK
# kKC0DlKP06awnSeFydihWHYBVe2oPlH1OQ1uMVTNVSIoqPjkB92CsU2wjMjPJIhq
# EB2b4r/WQ04PRzfACgtT4vcndyzXHJogPbC9NTrSIBRGYjvrZJBaPUzKMvR5ENmX
# gSX2yeZ8hjZC81xYScmBnxYfm6c1a8CjBPycVU17UKPbtwRJKR+s0Tbqhz54+pjq
# 0ygOxfMDaCgaefKBsQysQWIr6zExnDS2nhIyyyPvom4t8ANx23NMGLdDkWbIa0oc
# 9at3Y0xQdSpDzsczP4AoxFxSxlLXSsbY3Dba3L1MMAn4ZDGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABzIal3Dfr2WEtAAEA
# AAHMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIKD7bqWh7bvYvGNMM5f32OBuCzswjEFBqR/darA4
# OwAeMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1u5lAcL+wwIT5yApVKTA
# qkMgJ+d58VliANsXgetwWOYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAcyGpdw369lhLQABAAABzDAiBCD6EBxxQ5xKVakysJwYEcZO
# 6oRFEUCYp7BqLkC37iLtwTANBgkqhkiG9w0BAQsFAASCAgBUPfHFGgKVp/ZK61hx
# voBaG1utmykfPvNtCPxuONFk0ulKMIm864Bxka5LzObcTh8sMhm6t6d4WikNRXpe
# 5nNtq0Ae0J6tGLMCepR0AUvoOWMlTAiH+GcwZiZHKOYj9efolNVZgb1bXeJ+o/4B
# tNeJKAedgTKzFMz+MV+dmrzWd9CL13KZmLv+6Go6tJENfvu/l+r8S7CjP9bCKIGC
# HAhGptnhQDQMzsiiN92NqzBUpDkMDRdQWwPvHHAyvlKZf3w5fv8EDThA7uPJL8eb
# sDR+30RVaOgJwqk/lBygIjX3+Mp5Y1NPxSD9Hd7RQLVKsgF6GhitzlrnUSyQUb1g
# 1P1qiuYqD5JTV+jsHKVCeMfrkM08DUm4/ZO4gB0Lm9eeKO8F3/gP3yuXV8y4OLNd
# egtGm6/5j7kq1AFkuzAH9HCKf/V/LDxy8PqVxMYunHietEcKkEXQXgTbpjGZ1hIS
# hJtceD46Re8tBdfo46+VVv693TJQ3Xr6AVsWxFZx/L8vknWP0WfoJGW511KncHcs
# 5S2V+U3NlgHv8ydXhJEYK8v5YZiTczEEt9p/r/PxW4CJDpqPAHWxDoYd12xYmcyo
# zoNl0MBZvf1Dbw1tYv63pEOK8GYeWrric5rICpP4F/8wWSxFo1bRcT4teq2qXiNC
# nHwbZyqn21eNRFt+mAtdPw5NWg==
# SIG # End signature block
