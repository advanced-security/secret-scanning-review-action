@{
    GitHubContentTypeName = 'GitHub.Content'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubContent
{
    <#
    .SYNOPSIS
        Retrieve the contents of a file or directory in a repository on GitHub.

    .DESCRIPTION
        Retrieve content from files on GitHub.
        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OwnerName
        Owner of the repository.
        If not supplied here, the DefaultOwnerName configuration property value will be used.

    .PARAMETER RepositoryName
        Name of the repository.
        If not supplied here, the DefaultRepositoryName configuration property value will be used.

    .PARAMETER Uri
        Uri for the repository.
        The OwnerName and RepositoryName will be extracted from here instead of needing to provide
        them individually.

    .PARAMETER Path
        The file path for which to retrieve contents

    .PARAMETER BranchName
        The branch, or defaults to the default branch of not specified.

    .PARAMETER MediaType
        The format in which the API will return the body of the issue.

        Object - Return a json object representation a file or folder.
                 This is the default if you do not pass any specific media type.
        Raw    - Return the raw contents of a file.
        Html   - For markup files such as Markdown or AsciiDoc,
                 you can retrieve the rendered HTML using the Html media type.

    .PARAMETER ResultAsString
        If this switch is specified and the MediaType is either Raw or Html then the
        resulting bytes will be decoded the result will be  returned as a string instead of bytes.
        If the MediaType is Object, then an additional property on the object named
        'contentAsString' will be included and its value will be the decoded base64 result
        as a string.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Branch
        GitHub.Content
        GitHub.Event
        GitHub.Issue
        GitHub.IssueComment
        GitHub.Label
        GitHub.Milestone
        GitHub.PullRequest
        GitHub.Project
        GitHub.ProjectCard
        GitHub.ProjectColumn
        GitHub.Reaction
        GitHub.Release
        GitHub.ReleaseAsset
        GitHub.Repository

    .OUTPUTS
        [String]
        GitHub.Content

    .EXAMPLE
        Get-GitHubContent -OwnerName microsoft -RepositoryName PowerShellForGitHub -Path README.md -MediaType Html

        Get the Html output for the README.md file

    .EXAMPLE
        Get-GitHubContent -OwnerName microsoft -RepositoryName PowerShellForGitHub -Path LICENSE

        Get the Binary file output for the LICENSE file

    .EXAMPLE
        Get-GitHubContent -OwnerName microsoft -RepositoryName PowerShellForGitHub -Path Tests

        List the files within the "Tests" path of the repository

    .EXAMPLE
        $repo = Get-GitHubRepository -OwnerName microsoft -RepositoryName PowerShellForGitHub
        $repo | Get-GitHubContent -Path Tests

        List the files within the "Tests" path of the repository

    .NOTES
        Unable to specify Path as ValueFromPipeline because a Repository object may be incorrectly
        coerced into a string used for Path, thus confusing things.
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    [OutputType([String])]
    [OutputType({$script:GitHubContentTypeName})]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [string] $Path,

        [ValidateNotNullOrEmpty()]
        [string] $BranchName,

        [ValidateSet('Raw', 'Html', 'Object')]
        [string] $MediaType = 'Object',

        [switch] $ResultAsString,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    $description = [String]::Empty

    $uriFragment = "/repos/$OwnerName/$RepositoryName/contents"

    if ($PSBoundParameters.ContainsKey('Path'))
    {
        $Path = $Path.TrimStart("\", "/")
        $uriFragment += "/$Path"
        $description = "Getting content for $Path in $RepositoryName"
    }
    else
    {
        $description = "Getting all content for in $RepositoryName"
    }

    if ($PSBoundParameters.ContainsKey('BranchName'))
    {
        $uriFragment += "?ref=$BranchName"
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AcceptHeader' = (Get-MediaAcceptHeader -MediaType $MediaType)
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = Invoke-GHRestMethodMultipleResult @params

    if ($ResultAsString)
    {
        if ($MediaType -eq 'Raw' -or $MediaType -eq 'Html')
        {
            # Decode bytes to string
            $result = [System.Text.Encoding]::UTF8.GetString($result)
        }
        elseif ($MediaType -eq 'Object')
        {
            # Convert from base64
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($result.content))
            Add-Member -InputObject $result -NotePropertyName "contentAsString" -NotePropertyValue $decoded
        }
    }

    if ($MediaType -eq 'Object')
    {
        $null = $result | Add-GitHubContentAdditionalProperties
    }

    return $result
}

filter Set-GitHubContent
{
    <#
    .SYNOPSIS
        Sets the contents of a file or directory in a repository on GitHub.

    .DESCRIPTION
        Sets the contents of a file or directory in a repository on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OwnerName
        Owner of the repository.
        If not supplied here, the DefaultOwnerName configuration property value will be used.

    .PARAMETER RepositoryName
        Name of the repository.
        If not supplied here, the DefaultRepositoryName configuration property value will be used.

    .PARAMETER Uri
        Uri for the repository.
        The OwnerName and RepositoryName will be extracted from here instead of needing to provide
        them individually.

    .PARAMETER Path
        The file path for which to set contents.

    .PARAMETER CommitMessage
        The Git commit message.

    .PARAMETER Content
        The new file content.

    .PARAMETER Sha
        The SHA value of the current file if present. If this parameter is not provided, and the
        file currently exists in the specified branch of the repo, it will be read to obtain this
        value.

    .PARAMETER BranchName
        The branch, or defaults to the default branch if not specified.

    .PARAMETER CommitterName
        The name of the committer of the commit. Defaults to the name of the authenticated user if
        not specified. If specified, CommiterEmail must also be specified.

    .PARAMETER CommitterEmail
        The email of the committer of the commit. Defaults to the email of the authenticated user
        if not specified. If specified, CommitterName must also be specified.

    .PARAMETER AuthorName
        The name of the author of the commit. Defaults to the name of the authenticated user if
        not specified. If specified, AuthorEmail must also be specified.

    .PARAMETER AuthorEmail
        The email of the author of the commit. Defaults to the email of the authenticated user if
        not specified. If specified, AuthorName must also be specified.

    .PARAMETER PassThru
        Returns the updated GitHub Content.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

     .INPUTS
        GitHub.Branch
        GitHub.Content
        GitHub.Event
        GitHub.Issue
        GitHub.IssueComment
        GitHub.Label
        GitHub.Milestone
        GitHub.PullRequest
        GitHub.Project
        GitHub.ProjectCard
        GitHub.ProjectColumn
        GitHub.Release
        GitHub.Repository

    .OUTPUTS
        GitHub.Content

    .EXAMPLE
        Set-GitHubContent -OwnerName microsoft -RepositoryName PowerShellForGitHub -Path README.md -CommitMessage 'Adding README.md' -Content '# README' -BranchName master

        Sets the contents of the README.md file on the master branch of the PowerShellForGithub repository.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [OutputType({$script:GitHubContentTypeName})]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1,
            ParameterSetName='Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [string] $Path,

        [Parameter(
            Mandatory,
            Position = 3)]
        [string] $CommitMessage,

        [Parameter(
            Mandatory,
            Position = 4)]
        [string] $Content,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Sha,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $BranchName,

        [string] $CommitterName,

        [string] $CommitterEmail,

        [string] $AuthorName,

        [string] $AuthorEmail,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements -DisableValidation
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    $uriFragment = "/repos/$OwnerName/$RepositoryName/contents/$Path"

    $encodedContent = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Content))

    $hashBody = @{
        message = $CommitMessage
        content = $encodedContent
    }

    if ($PSBoundParameters.ContainsKey('BranchName'))
    {
        $hashBody['branch'] = $BranchName
    }

    if ($PSBoundParameters.ContainsKey('CommitterName') -or
        $PSBoundParameters.ContainsKey('CommitterEmail'))
    {
        if (![System.String]::IsNullOrEmpty($CommitterName) -and
            ![System.String]::IsNullOrEmpty($CommitterEmail))
        {
            $hashBody['committer'] = @{
                name = $CommitterName
                email = $CommitterEmail
            }
        }
        else
        {
            $message = 'Both CommiterName and CommitterEmail need to be specified.'
            Write-Log -Message $message -Level Error
            throw $message
        }
    }

    if ($PSBoundParameters.ContainsKey('AuthorName') -or
        $PSBoundParameters.ContainsKey('AuthorEmail'))
    {
        if (![System.String]::IsNullOrEmpty($AuthorName) -and
            ![System.String]::IsNullOrEmpty($AuthorEmail))
        {
            $hashBody['author'] = @{
                name = $AuthorName
                email = $AuthorEmail
            }
        }
        else
        {
            $message = 'Both AuthorName and AuthorEmail need to be specified.'
            Write-Log -Message $message -Level Error
            throw $message
        }
    }

    if ($PSBoundParameters.ContainsKey('Sha'))
    {
        $hashBody['sha'] = $Sha
    }

    if (-not $PSCmdlet.ShouldProcess(
        "$BranchName branch of $RepositoryName",
        "Set GitHub Contents on $Path"))
    {
        return
    }

    $params = @{
        UriFragment = $uriFragment
        Description = "Writing content for $Path in the $BranchName branch of $RepositoryName"
        Body = (ConvertTo-Json -InputObject $hashBody)
        Method = 'Put'
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    try
    {
        $result = (Invoke-GHRestMethod @params | Add-GitHubContentAdditionalProperties)
        if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
        {
            return $result
        }
    }
    catch
    {
        $overwriteShaRequired = $false

        # Temporary code to handle current differences in exception object between PS5 and PS7
        if ($PSVersionTable.PSedition -eq 'Core')
        {
            $errorMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).message -replace '\n',' ' -replace '\"','"'
            if (($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException]) -and
                ($errorMessage -eq 'Invalid request.  "sha" wasn''t supplied.'))
            {
                $overwriteShaRequired = $true
            }
            else
            {
                throw $_
            }
        }
        else
        {
            $errorMessage = $_.Exception.Message  -replace '\n',' ' -replace '\"','"'
            if ($errorMessage -like '*Invalid request.  "sha" wasn''t supplied.*')
            {
                $overwriteShaRequired = $true
            }
            else
            {
                throw $_
            }
        }

        if ($overwriteShaRequired)
        {
            # Get SHA from current file
            $getGitHubContentParms = @{
                Path = $Path
                OwnerName = $OwnerName
                RepositoryName = $RepositoryName
            }

            if ($PSBoundParameters.ContainsKey('BranchName'))
            {
                $getGitHubContentParms['BranchName'] = $BranchName
            }

            if ($PSBoundParameters.ContainsKey('AccessToken'))
            {
                $getGitHubContentParms['AccessToken'] = $AccessToken
            }

            $object = Get-GitHubContent @getGitHubContentParms

            $hashBody['sha'] = $object.sha
            $params['body'] = ConvertTo-Json -InputObject $hashBody

            $message = 'Replacing the content of an existing file requires the current SHA ' +
                'of that file.  Retrieving the SHA now.'
            Write-Log -Level Verbose -Message $message

            $result = (Invoke-GHRestMethod @params | Add-GitHubContentAdditionalProperties)
            if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
            {
                return $result
            }
        }
    }
}

filter Add-GitHubContentAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Content objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Content
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubContentTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            if ($item.html_url)
            {
                $uri = $item.html_url
            }
            else
            {
                $uri = $item.content.html_url
            }

            $elements = Split-GitHubUri -Uri $uri
            $repositoryUrl = Join-GitHubUri @elements

            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force

            $hostName = $(Get-GitHubConfiguration -Name 'ApiHostName')

            if ($uri -match "^https?://(?:www\.|api\.|)$hostName/(?:[^/]+)/(?:[^/]+)/(?:blob|tree)/([^/]+)/([^#]*)?$")
            {
                $branchName = $Matches[1]
                $path = $Matches[2]
            }
            else
            {
                $branchName = [String]::Empty
                $path = [String]::Empty
            }

            Add-Member -InputObject $item -Name 'BranchName' -Value $branchName -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'Path' -Value $path -MemberType NoteProperty -Force
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIInxAYJKoZIhvcNAQcCoIIntTCCJ7ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBcLsEBWajZE4it
# PIXGx3wrvx1e6LQmV64GHeTFlix7yaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaQwghmgAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFDyxDUhlk1jwdvSYXZJeuPa
# 83TVXtvG3KryoVNADmHbMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCd6Melm7SyyJca18sh3tAetEXTYV4W7dZp6Ex27VIOkLMN7eAgPZ3E
# iCmKbJiy1/VzNKsqB/fXF4sxMSIUD6RnWmUfb7IqUp8Mm6s1Jsv9s/3ucU1yyf2v
# bAPvrs5rVkHsKTN88toONW/N1my8NqQ1T4m9WBKuPYyVZXtYGHN9TFUXaMEhIOL2
# b28eWkqTUovB6gGQficVrJe6SqPjkbaL2MzOhsEfy++ToD+GenuydDw4b9Vb3Fg8
# QeV7olIjgmeUEB23FotvYthVemPNBNq/icUUzupthNgVkpg+LX5iIkyxVafwxIQ5
# NFejZAC9HvqiZJ0JAo6qKAqCFPtqY9YeoYIXLDCCFygGCisGAQQBgjcDAwExghcY
# MIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIKK4jZPeF8V2y03tDfpwAybUPBHj2H7GQ5/aBynMoPjjAgZlVuY6
# XjAYEzIwMjMxMTIxMTczNTM3LjA3M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAeKZmZXx3OMg6wABAAAB4jAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA3MjVaFw0yNTAxMTAxOTA3MjVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEt
# NEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtWO1mFX6QWZvxwpCmDab
# OKwOVEj3vwZvZqYa9sCYJ3TglUZ5N79AbMzwptCswOiXsMLuNLTcmRys+xaL1alX
# CwhyRFDwCRfWJ0Eb0eHIKykBq9+6/PnmSGXtus9DHsf31QluwTfAyamYlqw9amAX
# TnNmW+lZANQsNwhjKXmVcjgdVnk3oxLFY7zPBaviv3GQyZRezsgLEMmvlrf1JJ48
# AlEjLOdohzRbNnowVxNHMss3I8ETgqtW/UsV33oU3EDPCd61J4+DzwSZF7OvZPcd
# MUSWd4lfJBh3phDt4IhzvKWVahjTcISD2CGiun2pQpwFR8VxLhcSV/cZIRGeXMmw
# ruz9kY9Th1odPaNYahiFrZAI6aSCM6YEUKpAUXAWaw+tmPh5CzNjGrhzgeo+dS7i
# FPhqqm9Rneog5dt3JTjak0v3dyfSs9NOV45Sw5BuC+VF22EUIF6nF9vqduynd9xl
# o8F9Nu1dVryctC4wIGrJ+x5u6qdvCP6UdB+oqmK+nJ3soJYAKiPvxdTBirLUfJid
# K1OZ7hP28rq7Y78pOF9E54keJKDjjKYWP7fghwUSE+iBoq802xNWbhBuqmELKSev
# AHKqisEIsfpuWVG0kwnCa7sZF1NCwjHYcwqqmES2lKbXPe58BJ0+uA+GxAhEWQdk
# a6KEvUmOPgu7cJsCaFrSU6sCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBREhA4R2r7t
# B2yWm0mIJE2leAnaBTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA5FREMatVFNue
# 6V+yDZxOzLKHthe+FVTs1kyQhMBBiwUQ9WC9K+ILKWvlqneRrvpjPS3/qXG5zMjr
# Du1eryfhbFRSByPnACGc2iuGcPyWNiptyTft+CBgrf7ATAuE/U8YLm29crTFiiZT
# WdT6Vc7L1lGdKEj8dl0WvDayuC2xtajD04y4ANLmWDuiStdrZ1oI4afG5oPUg77r
# kTuq/Y7RbSwaPsBZ06M12l7E+uykvYoRw4x4lWaST87SBqeEXPMcCdaO01ad5TXV
# ZDoHG/w6k3V9j3DNCiLJyC844kz3eh3nkQZ5fF8Xxuh8tWVQTfMiKShJ537yzrU0
# M/7H1EzJrabAr9izXF28OVlMed0gqyx+a7e+79r4EV/a4ijJxVO8FCm/92tEkPrx
# 6jjTWaQJEWSbL/4GZCVGvHatqmoC7mTQ16/6JR0FQqZf+I5opnvm+5CDuEKIEDnE
# iblkhcNKVfjvDAVqvf8GBPCe0yr2trpBEB5L+j+5haSa+q8TwCrfxCYqBOIGdZJL
# +5U9xocTICufIWHkb6p4IaYvjgx8ScUSHFzexo+ZeF7oyFKAIgYlRkMDvffqdAPx
# +fjLrnfgt6X4u5PkXlsW3SYvB34fkbEbM5tmab9zekRa0e/W6Dt1L8N+tx3WyfYT
# iCThbUvWN1EFsr3HCQybBj4Idl4xK8EwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# ahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAWm5lp+nRuekl0iF+IHV3ylOiGb6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6QdTFzAiGA8yMDIzMTEyMjAwMDIzMVoYDzIwMjMxMTIzMDAwMjMxWjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDpB1MXAgEAMAoCAQACAiGvAgH/MAcCAQACAhGB
# MAoCBQDpCKSXAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAGLDDSs7ArTd0
# olj8BJvSyJmIjNOyanyVf1C6gfXu/hMi9XcprQDUPpjDaSRCI+owo4eXqxSzddy9
# RmEcR2lk1EvxRYxhW8eKIOly1N3OjnOTm29ohjUt3s7OI4dfp9/g7NsemHCMxpT6
# cGAppGUCwcOEk4IEsxQZlgV7MzE9Mm0xggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAeKZmZXx3OMg6wABAAAB4jANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCB1lCEEiaK7Uge3saT0gy2i4uQ8jXt+3GEyVY0daz//RDCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EICuJKkoQ/Sa4xsFQRM4Ogvh3ktToj9uO5whm
# Q4kIj3//MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHimZmV8dzjIOsAAQAAAeIwIgQgqvzaLYxDTBsl41dBF0nCwsGccg85uorAv7zS
# P5sykSEwDQYJKoZIhvcNAQELBQAEggIAN/1kG1cHMa70RwmT7morbhFpcJ83gvIH
# I/V0eD3gPWrPJb8Oj3II2T+MkdiCdG0AXzcrJrxWP5wnAQ4ZOjuvjLcWPGc9YAny
# Te2wkIA1W/KtR/upUcEhiAViA4ihaYDpRUv0cG8PkowxN19aWKJ6DHLoK8oGM30s
# EnCvFsrs20AY/44kp6ClDNTifuIk2e0I3zBscg9yPxqp2Ffz8y/0xH37kitUInDf
# 9AXWSN1OpxBrRURSsb8Mb28zxfyBr2zEwc4VBDNUxCaxP9ZAxk17b4JDDgNY0EMT
# FksncyIYVBypE3KyO3yS5nZRVK8l3Rczrf9Dhh+bHDqx14Vw1eZ4lr20Trfg+2zn
# iUx03j888iqlMc2BBEg61I83urG1n3eGGlCAYV83VIjsTpAXtuCKoznrdFMWTZWE
# 4o7c3pMTyAJqFOuBuImVntoq6RtIb2myR69VRhpPTEC+k+U8IG1y+QpFxlWqGx5U
# 8TkptSuBqqqJ8VAnbtGc5bcpiw1uGJklfbqaXMnRB/UVmSXLtDSTzqAnh6FLq7tZ
# klg4bjJevwPOd+moaQqsBOEPPc905IT4/CLriGI42vimjn8M1xR1S0czmFfoVxMw
# Z55qijFC4VcCcdHfedbjUo+ClW+yv/BaIfgQHBguviAj0NK80B2HAnsSC2TJnp6J
# rGt9X6IJXNA=
# SIG # End signature block
