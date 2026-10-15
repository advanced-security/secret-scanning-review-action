# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Group-GitHubIssue
{
<#
    .SYNOPSIS
        Groups the provided issues based on the specified grouping criteria.

    .DESCRIPTION
        Groups the provided issues based on the specified grouping criteria.

        Currently able to group Issues by week.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Issue
        The Issue(s) to be grouped.

    .PARAMETER Weeks
        The number of weeks to group the Issues by.

    .PARAMETER DateType
        The date property that should be inspected when determining which week grouping the issue
        if part of.

    .INPUTS
        GitHub.Issue

    .OUTPUTS
        [PSCustomObject[]]
        Collection of issues and counts, by week, along with the total count of issues.

    .EXAMPLE
        $issues = @()
        $issues += Get-GitHubIssue -Uri 'https://github.com/powershell/xpsdesiredstateconfiguration'
        $issues += Get-GitHubIssue -Uri 'https://github.com/powershell/xactivedirectory'
        $issues | Group-GitHubIssue -Weeks 12 -DateType Closed
#>
    [CmdletBinding(DefaultParameterSetName = 'Weekly')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="DateType due to PowerShell/PSScriptAnalyzer#1472")]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [PSCustomObject[]] $Issue,

        [Parameter(
            Mandatory,
            ParameterSetName='Weekly')]
        [ValidateRange(0, 10000)]
        [int] $Weeks,

        [Parameter(ParameterSetName='Weekly')]
        [ValidateSet('Created', 'Closed')]
        [string] $DateType = 'Created'
    )

    begin
    {
        Write-InvocationLog

        if ($PSCmdlet.ParameterSetName -eq 'Weekly')
        {
            $weekDates = Get-WeekDate -Weeks $Weeks

            $result = [ordered]@{}
            foreach ($week in $weekDates)
            {
                $result[$week] = ([PSCustomObject]([ordered]@{
                    'WeekStart' = $week
                    'Count' = 0
                    'Issues' = @()
                }))
            }

            $result['total'] = ([PSCustomObject]([ordered]@{
                'WeekStart' = 'total'
                'Count' = 0
                'Issues' = @()
            }))
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Weekly')
        {
            $endOfWeek = Get-Date
            foreach ($week in $weekDates)
            {
                $filteredIssues = @($Issue | Where-Object {
                    (($DateType -eq 'Created') -and
                     ($_.created_at -ge $week) -and
                     ($_.created_at -le $endOfWeek)) -or
                    (($DateType -eq 'Closed') -and
                     ($_.closed_at -ge $week) -and
                     ($_.closed_at -le $endOfWeek))
                })

                $endOfWeek = $week

                $result[$week].Issues += $filteredIssues
                $result[$week].Count += ($filteredIssues.Count)

                $result['total'].Issues += $filteredIssues
                $result['total'].Count += ($filteredIssues.Count)
            }
        }
        else
        {
            Write-Output -InputObject $Issue
        }
    }

    end
    {
        if ($PSCmdlet.ParameterSetName -eq 'Weekly')
        {
            foreach ($entry in $result.Values.GetEnumerator())
            {
                Write-Output -InputObject $entry
            }
        }
    }
}

function Group-GitHubPullRequest
{
<#
    .SYNOPSIS
        Groups the provided pull requests based on the specified grouping criteria.

    .DESCRIPTION
        Groups the provided pull requests based on the specified grouping criteria.

        Currently able to group Pull Requests by week.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER PullRequest
        The Pull Requests(s) to be grouped.

    .PARAMETER Weeks
        The number of weeks to group the Pull Requests by.

    .PARAMETER DateType
        The date property that should be inspected when determining which week grouping the
        pull request if part of.

    .INPUTS
        GitHub.PullRequest

    .OUTPUTS
        [PSCustomObject[]] Collection of pull requests and counts, by week, along with the
        total count of pull requests.

    .EXAMPLE
        $pullRequests = @()
        $pullRequests += Get-GitHubPullRequest -Uri 'https://github.com/powershell/xpsdesiredstateconfiguration'
        $pullRequests += Get-GitHubPullRequest -Uri 'https://github.com/powershell/xactivedirectory'
        $pullRequests | Group-GitHubPullRequest -Weeks 12 -DateType Closed
#>
    [CmdletBinding(DefaultParameterSetName='Weekly')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="DateType due to PowerShell/PSScriptAnalyzer#1472")]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [PSCustomObject[]] $PullRequest,

        [Parameter(
            Mandatory,
            ParameterSetName='Weekly')]
        [ValidateRange(0, 10000)]
        [int] $Weeks,

        [Parameter(ParameterSetName='Weekly')]
        [ValidateSet('Created', 'Merged')]
        [string] $DateType = 'Created'
    )

    begin
    {
        Write-InvocationLog

        if ($PSCmdlet.ParameterSetName -eq 'Weekly')
        {
            $weekDates = Get-WeekDate -Weeks $Weeks

            $result = [ordered]@{}
            foreach ($week in $weekDates)
            {
                $result[$week] = ([PSCustomObject]([ordered]@{
                    'WeekStart' = $week
                    'Count' = 0
                    'PullRequests' = @()
                }))
            }

            $result['total'] = ([PSCustomObject]([ordered]@{
                'WeekStart' = 'total'
                'Count' = 0
                'PullRequests' = @()
            }))
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Weekly')
        {
            $endOfWeek = Get-Date
            foreach ($week in $weekDates)
            {
                $filteredPullRequests = @($PullRequest | Where-Object {
                    (($DateType -eq 'Created') -and
                     ($_.created_at -ge $week) -and
                     ($_.created_at -le $endOfWeek)) -or
                    (($DateType -eq 'Merged') -and
                     ($_.merged_at -ge $week) -and
                     ($_.merged_at -le $endOfWeek))
                })

                $endOfWeek = $week

                $result[$week].PullRequests += $filteredPullRequests
                $result[$week].Count += ($filteredPullRequests.Count)

                $result['total'].PullRequests += $filteredPullRequests
                $result['total'].Count += ($filteredPullRequests.Count)
            }
        }
        else
        {
            Write-Output -InputObject $PullRequest
        }
    }

    end
    {
        if ($PSCmdlet.ParameterSetName -eq 'Weekly')
        {
            foreach ($entry in $result.Values.GetEnumerator())
            {
                Write-Output -InputObject $entry
            }
        }
    }
}

function Get-WeekDate
{
<#
    .SYNOPSIS
        Retrieves an array of dates with starts of $Weeks previous weeks.
        Dates are sorted in reverse chronological order

    .DESCRIPTION
        Retrieves an array of dates with starts of $Weeks previous weeks.
        Dates are sorted in reverse chronological order

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Weeks
        The number of weeks prior to today that should be included in the final result.

    .OUTPUTS
        [DateTime[]] List of DateTimes representing the first day of each requested week.

    .EXAMPLE
        Get-WeekDate -Weeks 10
#>
    [CmdletBinding()]
    [OutputType([DateTime[]])]
    param(
        [ValidateRange(0, 10000)]
        [int] $Weeks = 12
    )

    $dates = @()

    $midnightToday = Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0
    $startOfWeek = $midnightToday.AddDays(- ($midnightToday.DayOfWeek.value__ - 1))

    $i = 0
    while ($i -lt $Weeks)
    {
        $dates += $startOfWeek
        $startOfWeek = $startOfWeek.AddDays(-7)
        $i++
    }

    return $dates
}

# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBsqaUSZNZy0oqs
# YxQV8iSxHQ0y4VdmtTXJd2iUnpj+kKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINJ9HBG/HCDBxpcBI+QjcDCd
# poLMdRZd29wkbxca0n27MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA7ah0n5kkXB6dm+sQyfNQ1dIJmE8vc1Xw4wdQBZmC2fDpukZQkOxM3
# wfZ0TwGc2G4VsUuUEbGJEfMqrRg0Wr1q3QMuNWUt7M+HLrqnLBAEtCgJhZJ8k9tv
# ZqwlBP3xBttszKI2FVFn7KIoGXqsZuZd/c742BFotsuxRGuYX8XubtepCcAhBifh
# JgnnKZKC2UNh6op0RkwPW3RFx5jT98EWucz26CyfizaSVOKs2dba6BUcgqtj8dcx
# x1hOiJyTaKNyoful73fnkge3h2IgQVOMSwgFhLFEC5elPspEEMvi8hf5c+MbDBYb
# tR4MmfS1JsKAMS0YpuBOCWyheaUlRVT5oYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFUi+dGyEE4Q2WkFMWZU7L7h5gO2jocAmUdAiT5dulrqAgZlVuEV
# l7IYEzIwMjMxMTIxMTczNTExLjQwNFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAdqO1claANERsQABAAAB2jAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA2NTlaFw0yNTAxMTAxOTA2NTlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDIt
# NEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk5AGCHa1UVHWPyNADg0N
# /xtxWtdI3TzQI0o9JCjtLnuwKc9TQUoXjvDYvqoe3CbgScKUXZyu5cWn+Xs+kxCD
# bkTtfzEOa/GvwEETqIBIA8J+tN5u68CxlZwliHLumuAK4F/s6J1emCxbXLynpWzu
# wPZq6n/S695jF5eUq2w+MwKmUeSTRtr4eAuGjQnrwp2OLcMzYrn3AfL3Gu2xgr5f
# 16tsMZnaaZffvrlpLlDv+6APExWDPKPzTImfpQueScP2LiRRDFWGpXV1z8MXpQF6
# 7N+6SQx53u2vNQRkxHKVruqG/BR5CWDMJCGlmPP7OxCCleU9zO8Z3SKqvuUALB9U
# aiDmmUjN0TG+3VMDwmZ5/zX1pMrAfUhUQjBgsDq69LyRF0DpHG8xxv/+6U2Mi4Zx
# 7LKQwBcTKdWssb1W8rit+sKwYvePfQuaJ26D6jCtwKNBqBiasaTWEHKReKWj1gHx
# DLLlDUqEa4frlXfMXLxrSTBsoFGzxVHge2g9jD3PUN1wl9kE7Z2HNffIAyKkIabp
# Ka+a9q9GxeHLzTmOICkPI36zT9vuizbPyJFYYmToz265Pbj3eAVX/0ksaDlgkkIl
# cj7LGQ785edkmy4a3T7NYt0dLhchcEbXug+7kqwV9FMdESWhHZ0jobBprEjIPJId
# g628jJ2Vru7iV+d8KNj+opMCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBShfI3JUT1m
# E5WLMRRXCE2Avw9fRTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAuYNV1O24jSMA
# S3jU7Y4zwJTbftMYzKGsavsXMoIQVpfG2iqT8g5tCuKrVxodWHa/K5DbifPdN04G
# /utyz+qc+M7GdcUvJk95pYuw24BFWZRWLJVheNdgHkPDNpZmBJxjwYovvIaPJauH
# vxYlSCHusTX7lUPmHT/quz10FGoDMj1+FnPuymyO3y+fHnRYTFsFJIfut9psd6d2
# l6ptOZb9F9xpP4YUixP6DZ6PvBEoir9CGeygXyakU08dXWr9Yr+sX8KGi+SEkwO+
# Wq0RNaL3saiU5IpqZkL1tiBw8p/Pbx53blYnLXRW1D0/n4L/Z058NrPVGZ45vbsp
# t6CFrRJ89yuJN85FW+o8NJref03t2FNjv7j0jx6+hp32F1nwJ8g49+3C3fFNfZGE
# xkkJWgWVpsdy99vzitoUzpzPkRiT7HVpUSJe2ArpHTGfXCMxcd/QBaVKOpGTO9Kd
# ErMWxnASXvhVqGUpWEj4KL1FP37oZzTFbMnvNAhQUTcmKLHn7sovwCsd8Fj1QUvP
# iydugntCKncgANuRThkvSJDyPwjGtrtpJh9OhR5+Zy3d0zr19/gR6HYqH02wqKKm
# Hnz0Cn/FLWMRKWt+Mv+D9luhpLl31rZ8Dn3ya5sO8sPnHk8/fvvTS+b9j48iGanZ
# 9O+5Layd15kGbJOpxQ0dE2YKT6eNXecwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# OjA4NDItNEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBCoh8hiWMdRs2hjT/COFdGf+xIDaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6QdN7DAiGA8yMDIzMTEyMTIzNDAyOFoYDzIwMjMxMTIyMjM0MDI4WjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDpB03sAgEAMAcCAQACAga0MAcCAQACAhJEMAoC
# BQDpCJ9sAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEApjXJbgfeMj3NDy80
# NhYFfENfZV5twZuJ+TnnlXs8jQufwPjV9uoitIi63t2I+kNkqvy8nuRCbPksqjTs
# wCb1n+fmNCls2tzlJbO7t5xWcOARsfU+IJCbMHGpggsgEzlA6Bzadv6GMCLl8Std
# 8jsYrYLVAiyAGvy7i9TVC3gKl54xggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAdqO1claANERsQABAAAB2jANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCCUQAhgYjsG60bL4v8N2sE85rt0fwh/uj5nJc6FjZWp8TCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EICKlo2liwO+epN73kOPULT3TbQjmWOJutb+d0gI7
# GD3GMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHa
# jtXJWgDREbEAAQAAAdowIgQg7rJMq3SEpSxIoccy6bwt05nwpLZYSkjQ9MUBBot6
# 7mAwDQYJKoZIhvcNAQELBQAEggIAHAfLgQ94H8VbxXzMjJKOEstKPy/uOtCSJ72u
# I/cQYopLF0L97t44S90+LtQV+TtlH1N5soMoZPt6wVS4+ITwFd0jqRtxyo1rY3vX
# tJD0yfZROaFNbaLXzXAlsTPiQL+CmOyZTIr0gKJbFTIJNvcGTqskJo5vWfQ51Yfs
# UU0CMksl6t2dt1J3aUZkTLVmmLBSKwCqyXD8idC0CZqGP9di+1gT5GJpCf1f4VKL
# l9pdAH5szHRUso3LUplT37svhYBDoeUiYZsIxa+vhvkP0MYxFFjnsauJowADG38v
# PO0l7fSiV4eyYtznAxFeQB5LvX55osJTs30n5qNce1wlIwiE8SjEzuyRtys4D/L5
# 4i/0EjSsVBF5XvJU2x3LOi3KwzXd7r8MYxuesR5bfi3d1gAW2XtSwyWJZe2yV4Uq
# ugR2p6tjlf/3DS0rx0nMDudiyim8WKEfTwJ60Ji9aU/HflAdstoFY7fGkDH8IgQ4
# 7s18yh/RWMKTL3vEmi2bXVlk98k70Zsi18+AVGwGoOOcwCnoT1/RyjUCAYoBmDhb
# um2/98XOb5VK4HLB0gzrri0lOSjLwgQR+4Nyju1XUbqG1+uNebBW58OIgC+xs2F+
# h2Yd7QncU7I4Wb5XGPWAaJwYDj+pPdZJqZCcPflUNKVmj4nExvvDzRN4cc1jJfld
# 3jjBX+Q=
# SIG # End signature block
