# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubProjectTypeName = 'GitHub.Project'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubProject
{
<#
    .SYNOPSIS
        Get the projects for a given GitHub user, repository or organization.

    .DESCRIPTION
        Get the projects for a given GitHub user, repository or organization.

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

    .PARAMETER OrganizationName
        The name of the organization to get projects for.

    .PARAMETER UserName
        The name of the user to get projects for.

    .PARAMETER Project
        ID of the project to retrieve.

    .PARAMETER State
        Only projects with this state are returned.

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
        GitHub.Project

    .EXAMPLE
        Get-GitHubProject -OwnerName microsoft -RepositoryName PowerShellForGitHub

        Get the projects for the microsoft\PowerShellForGitHub repository.

    .EXAMPLE
        Get-GitHubProject -OrganizationName Microsoft

        Get the projects for the Microsoft organization.

    .EXAMPLE
        Get-GitHubProject -Uri https://github.com/Microsoft/PowerShellForGitHub

        Get the projects for the microsoft\PowerShellForGitHub repository using the Uri.

    .EXAMPLE
        Get-GitHubProject -UserName GitHubUser

        Get the projects for the user GitHubUser.

    .EXAMPLE
        Get-GitHubProject -OwnerName microsoft -RepositoryName PowerShellForGitHub -State Closed

        Get closed projects from the microsoft\PowerShellForGitHub repo.

    .EXAMPLE
        Get-GitHubProject -Project 4378613

        Get a project by id, with this parameter you don't need any other information.
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubPullRequestTypeName})]
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
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='ProjectObject')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Organization')]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ParameterSetName = 'User')]
        [string] $UserName,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Project')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='ProjectObject')]
        [Alias('ProjectId')]
        [int64] $Project,

        [ValidateSet('Open', 'Closed', 'All')]
        [string] $State,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = [String]::Empty
    $description = [String]::Empty
    if ($PSCmdlet.ParameterSetName -in @('Project', 'ProjectObject'))
    {
        $telemetryProperties['Project'] = Get-PiiSafeString -PlainText $Project

        $uriFragment = "/projects/$Project"
        $description = "Getting project $project"
    }
    elseif ($PSCmdlet.ParameterSetName -in ('Elements', 'Uri'))
    {
        $elements = Resolve-RepositoryElements
        $OwnerName = $elements.ownerName
        $RepositoryName = $elements.repositoryName

        $telemetryProperties['OwnerName'] = Get-PiiSafeString -PlainText $OwnerName
        $telemetryProperties['RepositoryName'] = Get-PiiSafeString -PlainText $RepositoryName

        $uriFragment = "/repos/$OwnerName/$RepositoryName/projects"
        $description = "Getting projects for $RepositoryName"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Organization')
    {
        $telemetryProperties['OrganizationName'] = Get-PiiSafeString -PlainText $OrganizationName

        $uriFragment = "/orgs/$OrganizationName/projects"
        $description = "Getting projects for $OrganizationName"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'User')
    {
        $telemetryProperties['UserName'] = Get-PiiSafeString -PlainText $UserName

        $uriFragment = "/users/$UserName/projects"
        $description = "Getting projects for $UserName"
    }

    if ($PSBoundParameters.ContainsKey('State'))
    {
        $getParams = @()
        $State = $State.ToLower()
        $getParams += "state=$State"

        $uriFragment = "$uriFragment`?" + ($getParams -join '&')
        $description += " with state '$state'"
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubProjectAdditionalProperties)

}

filter New-GitHubProject
{
<#
    .SYNOPSIS
        Creates a new GitHub project for the given repository.

    .DESCRIPTION
        Creates a new GitHub project for the given repository.

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

    .PARAMETER OrganizationName
        The name of the organization to create the project under.

    .PARAMETER UserProject
        If this switch is specified creates a project for your user.

    .PARAMETER Name
        The name of the project to create.

    .PARAMETER Description
        Short description for the new project.

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
        GitHub.Project

    .EXAMPLE
        New-GitHubProject -OwnerName microsoft -RepositoryName PowerShellForGitHub -ProjectName TestProject

        Creates a project called 'TestProject' for the microsoft\PowerShellForGitHub repository.

    .EXAMPLE
        New-GitHubProject -OrganizationName Microsoft -ProjectName TestProject -Description 'This is just a test project'

        Create a project for the Microsoft organization called 'TestProject' with a description.

    .EXAMPLE
        New-GitHubProject -Uri https://github.com/Microsoft/PowerShellForGitHub -ProjectName TestProject

        Create a project for the microsoft\PowerShellForGitHub repository
        using the Uri called 'TestProject'.

    .EXAMPLE
        New-GitHubProject -UserProject -ProjectName 'TestProject'

        Creates a project for the signed in user called 'TestProject'.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubPullRequestTypeName})]
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

        [Parameter(
            Mandatory,
            ParameterSetName = 'Organization')]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ParameterSetName = 'User')]
        [switch] $UserProject,

        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [Alias('Name')]
        [string] $ProjectName,

        [string] $Description,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}
    $telemetryProperties['ProjectName'] = Get-PiiSafeString -PlainText $ProjectName

    $uriFragment = [String]::Empty
    $apiDescription = [String]::Empty
    if ($PSCmdlet.ParameterSetName -in ('Elements', 'Uri'))
    {
        $elements = Resolve-RepositoryElements
        $OwnerName = $elements.ownerName
        $RepositoryName = $elements.repositoryName

        $telemetryProperties['OwnerName'] = Get-PiiSafeString -PlainText $OwnerName
        $telemetryProperties['RepositoryName'] = Get-PiiSafeString -PlainText $RepositoryName

        $uriFragment = "/repos/$OwnerName/$RepositoryName/projects"
        $apiDescription = "Creating project for $RepositoryName"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Organization')
    {
        $telemetryProperties['OrganizationName'] = Get-PiiSafeString -PlainText $OrganizationName

        $uriFragment = "/orgs/$OrganizationName/projects"
        $apiDescription = "Creating project for $OrganizationName"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'User')
    {
        $telemetryProperties['User'] = $true

        $uriFragment = "/user/projects"
        $apiDescription = "Creating project for user"
    }

    $hashBody = @{
        'name' = $ProjectName
    }

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        $hashBody.add('body', $Description)
    }

    if (-not $PSCmdlet.ShouldProcess($ProjectName, 'Create GitHub Project'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' = $apiDescription
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return (Invoke-GHRestMethod @params | Add-GitHubProjectAdditionalProperties)
}

filter Set-GitHubProject
{
<#
    .SYNOPSIS
        Modify a GitHub Project.

    .DESCRIPTION
        Modify a GitHub Project.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Project
        ID of the project to modify.

    .PARAMETER Description
        Short description for the project.

    .PARAMETER State
        Set the state of the project.

    .PARAMETER OrganizationPermission
        Set the permission level that determines whether all members of the project's
        organization can see and/or make changes to the project.
        Only available for organization projects.

    .PARAMETER Private
        Sets the visibility of a project board.
        Only available for organization and user projects.
        Note: Updating a project's visibility requires admin access to the project.

    .PARAMETER PassThru
        Returns the updated Project.  By default, this cmdlet does not generate any output.
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
        GitHub.ReleaseAsset
        GitHub.Repository

    .OUTPUTS
        GitHub.Project

    .EXAMPLE
        Set-GitHubProject -Project 999999 -State Closed

        Set the project with ID '999999' to closed.

    .EXAMPLE
        $project = Get-GitHubProject -OwnerName microsoft -RepositoryName PowerShellForGitHub | Where-Object Name -eq 'TestProject'
        Set-GitHubProject -Project $project.id -State Closed

        Get the ID for the 'TestProject' project for the microsoft\PowerShellForGitHub
        repository and set state to closed.
#>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType({$script:GitHubPullRequestTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('ProjectId')]
        [int64] $Project,

        [string] $Description,

        [ValidateSet('Open', 'Closed')]
        [string] $State,

        [ValidateSet('Read', 'Write', 'Admin', 'None')]
        [string] $OrganizationPermission,

        [switch] $Private,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = "projects/$Project"
    $apiDescription = "Updating project $Project"

    $hashBody = @{}

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        $hashBody.add('body', $Description)
        $apiDescription += " description"
    }

    if ($PSBoundParameters.ContainsKey('State'))
    {
        $hashBody.add('state', $State)
        $apiDescription += ", state to '$State'"
    }

    if ($PSBoundParameters.ContainsKey('Private'))
    {
       $hashBody.add('private', $Private.ToBool())
       $apiDescription += ", private to '$Private'"
    }

    if ($PSBoundParameters.ContainsKey('OrganizationPermission'))
    {
        $hashBody.add('organization_permission', $OrganizationPermission.ToLower())
        $apiDescription += ", organization_permission to '$OrganizationPermission'"
    }

    if (-not $PSCmdlet.ShouldProcess($Project, 'Set GitHub Project'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $apiDescription
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'AccessToken' = $AccessToken
        'Method' = 'Patch'
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubProjectAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Remove-GitHubProject
{
<#
    .SYNOPSIS
        Removes the projects for a given GitHub repository.

    .DESCRIPTION
        Removes the projects for a given GitHub repository.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Project
        ID of the project to remove.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

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
        GitHub.ReleaseAsset
        GitHub.Repository

    .EXAMPLE
        Remove-GitHubProject -Project 4387531

        Remove project with ID '4387531'.

    .EXAMPLE
        Remove-GitHubProject -Project 4387531 -Confirm:$false

        Remove project with ID '4387531' without prompting for confirmation.

    .EXAMPLE
        Remove-GitHubProject -Project 4387531 -Force

        Remove project with ID '4387531' without prompting for confirmation.

    .EXAMPLE
        $project = Get-GitHubProject -OwnerName microsoft -RepositoryName PowerShellForGitHub | Where-Object Name -eq 'TestProject'
        Remove-GitHubProject -Project $project.id

        Get the ID for the 'TestProject' project for the microsoft\PowerShellForGitHub
        repository and then remove the project.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High')]
    [Alias('Delete-GitHubProject')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('ProjectId')]
        [int64] $Project,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = "projects/$Project"
    $description = "Deleting project $Project"

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Project, 'Remove GitHub Project'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AccessToken' = $AccessToken
        'Method' = 'Delete'
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return Invoke-GHRestMethod @params
}

filter Add-GitHubProjectAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Project objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Project
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
        [string] $TypeName = $script:GitHubProjectTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $elements = Split-GitHubUri -Uri $item.html_url
            $repositoryUrl = Join-GitHubUri @elements

            # A "user" project has no associated repository, and adding this in that scenario
            # would cause API-level errors with piping further on,
            if ($elements.OwnerName -ne 'users')
            {
                Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force
            }

            Add-Member -InputObject $item -Name 'ProjectId' -Value $item.id -MemberType NoteProperty -Force

            if ($null -ne $item.creator)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.creator
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQ3d5+qgotrcB5
# I6J9ONTJE0UpjTnDxJSzoVM78HpOu6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIH9z9pQfWZvT8b70E5Rocwyi
# RtQzQbNC85inZm6PH8OKMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA4ynXTWbEDTqzv3ig8YaKH6piXm03Uuj1iNmg8/9epXnOtDkQw9Yzy
# apubSZpSB66ORGMwm41sgV3nDiUy/csGDidC/SfsT6RaRyEPzoINe+7r6xxEnT1E
# teK30KFOX/h+7a3cQ+vakUVQoCi2vmC382BoLg95x5yzFycnPeCF95q3gc0hYQoX
# xqVlRFMOwEg4Y3EgSIU7CEq7eX9J0QlQKTkH2Mw0NTIfTx3hNZKSj8ELZBAdrg+s
# qP9hBJChWlADzWAgMDAGW3ssvdj4zOSVtOpIJqRFFfXTH00GcET066hQ6oPrmNak
# UZ7yp+FI7JmJt98uRH00XtidjFny7L9zoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIB22Anl0qhy4tDbb5rg7QahmNak8moc978J/wAdh2VgwAgZlVsEy
# hBYYEzIwMjMxMTIxMTczNTQ5LjI4NFowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
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
# AQQwLwYJKoZIhvcNAQkEMSIEIOjsg8UUdnAc7t2CTjtU5vqs8yoKgRawLz3QhPZ1
# 4mgSMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1stNDVd40z4QGKc4QkyN
# l3SMw0O6v4Ar47w/XaPlJPwwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAdYnaf9yLVbIrgABAAAB1jAiBCA31rAZghduxT8BdG6P7Rl6
# biGg0w08eWGJDY7WRis5CjANBgkqhkiG9w0BAQsFAASCAgBgKfcVDbeFOUef7Hk2
# VbipY9NqLRAif+ekzBkEjlESULJX0FG2o6pGN/eNbJNqxk/ojPJHG/nH9sUvUzyx
# 5MLycicnT1ZzzAon1sw+9aBMOi2Qorr5eGFN3Eyxs5EizZYkDW/AW0jM5CA1qEl3
# nmcR/uPTk8CyP8YHf40EHzmXxb64D+yOyorloQklMAhNzUILLPnzCLH+YNbJ4U63
# I0mc4Um/PTxbJUhpZii0sX2VVIYMQI9YL028zrKvCKL6GPcyW8BPqQJlrDyC5bwQ
# DIrmsCt86iAPEkkv5MA8k/F+NHp82QhTAaCY4QNoq6KnlJEVmD5tzNoLxgTA3ZNX
# XxiPVJ6sQ9UCnjrYEUIxBpPuErvXgC99CeoCWO3osKNAccQdVMvIYKcE5DTzNpRY
# /BCGjJLM7U6ztNPHCCBuxwhvpXudz4Ti8o2JzSlVAjHMP7CEqU6N4Emmn0viZOG+
# SQ24GAIor2zbALdDghw7hFa4w63jDfpmBs9XdM7SS4qvBKmU1kMqe/7P7tk6AUFh
# RA64d+U1sOeA80/AbfQjcLfkGr/T9kB8VQphUbWI2qMkocafawdmt2fXU87yr15+
# boqZGwMjsvBRhjD2w5uYA6F6BffzwKrdBQaWmWx1PHjIi6wyXiQpliU6VAWwE5lm
# z3AYe5fZNZYNf6FT1rvPxyX8mQ==
# SIG # End signature block
