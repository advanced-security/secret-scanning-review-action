# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# We'll cache our job name and result so that we don't check more than once per day.
$script:UpdateCheckJobName = $null
$script:HasLatestVersion = $null

function Invoke-UpdateCheck
{
<#
    .SYNOPSIS
        Checks PowerShellGallery to see if a newer version of this module has been published.

    .DESCRIPTION
        Checks PowerShellGallery to see if a newer version of this module has been published.

        The check will only run once per day.

        Runs asynchronously, so the user won't see any message until after they run their first
        API request after the module has been imported.

        Will always assume true in the event of an incomplete or failed check.

        Reports the result to the user via a Warning message (if a newer version is available)
        or a Verbose message (if they're running the latest version or the version check failed).

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Force
        For debugging purposes, using this switch will allow the check to occur more than the limit
        of once per day.  This _will not_ bypass the DisableUpdateCheck configuration value however.

    .EXAMPLE
        Invoke-UpdateCheck

    .NOTES
        Internal-only helper method.
#>
    [cmdletbinding()]
    param([switch] $Force)

    if (Get-GitHubConfiguration -Name DisableUpdateCheck)
    {
        return
    }

    $moduleName = $MyInvocation.MyCommand.Module.Name
    $moduleVersion = $MyInvocation.MyCommand.Module.Version

    $jobNameToday = "Invoke-UpdateCheck-" + (Get-Date -format 'yyyyMMdd')

    if ($Force)
    {
        if ($null -ne $script:UpdateCheckJobName)
        {
            # We're going to clear out the existing job and try running it again.
            $null = Receive-Job -Name $script:UpdateCheckJobName -AutoRemoveJob -Wait -ErrorAction SilentlyContinue -ErrorVariable errorInfo
        }

        $script:UpdateCheckJobName = $null
        $script:HasLatestVersion = $null
    }

    # We only check once per day
    if ($jobNameToday -eq $script:UpdateCheckJobName)
    {
        # Have we retrieved the status yet?  $null means we haven't.
        if ($null -ne $script:HasLatestVersion)
        {
            # We've already completed the check for today.  No further action required.
            return
        }

        $state = (Get-Job -Name $script:UpdateCheckJobName).state
        if ($state -eq 'Failed')
        {
            # We'll just assume we're up-to-date if we failed to check today.
            $message = '[$moduleName] update check failed for today (web request failed).  Assuming up-to-date.'
            Write-Log -Message $message -Level Verbose
            $script:HasLatestVersion = $true

            # Clear out the job info (even though we don't need the result)
            $null = Receive-Job -Name $script:UpdateCheckJobName -AutoRemoveJob -Wait -ErrorAction SilentlyContinue -ErrorVariable errorInfo
            return
        }
        elseif ($state -eq 'Completed')
        {
            $result = Receive-Job -Name $script:UpdateCheckJobName -AutoRemoveJob -Wait
            try
            {
                # Occasionally the API puts two nearly identical XML responses in the body (each on a separate line).
                # We'll try to avoid an unnecessary failure by always using the first line of the response.
                $xml = [xml]($result.Content.Split([Environment]::NewLine) | Select-Object -First 1)
                $latestVersion = $xml.feed.entry.properties.version |
                    ForEach-Object {[System.Version]$_} |
                    Sort-Object -Descending |
                    Select-Object -First 1

                $script:HasLatestVersion = $latestVersion -eq $moduleVersion
                if ($script:HasLatestVersion)
                {
                    $message = "[$moduleName] update check complete.  Running latest version: $latestVersion"
                    Write-Log -Message $message -Level Verbose
                }
                elseif ($moduleVersion -gt $latestVersion)
                {
                    $message = "[$moduleName] update check complete.  This version ($moduleVersion) is newer than the latest published version ($latestVersion)."
                    Write-Log -Message $message -Level Verbose
                }
                else
                {
                    $message = "A newer version of $moduleName is available ($latestVersion).  Your current version is $moduleVersion.  Run 'Update-Module $moduleName' to get up-to-date."
                    Write-Log -Message $message -Level Warning
                }
            }
            catch
            {
                # This could happen if the server returned back an invalid (non-XML) response for the request
                # for some reason.
                $message = "[$moduleName] update check failed for today (invalid XML response).  Assuming up-to-date."
                Write-Log -Message $message -Level Verbose
                $script:HasLatestVersion = $true
            }

            return
        }
        else
        {
            # It's still running.  Nothing further for us to do right now.  We'll check back
            # again next time.
            return
        }
    }
    else
    {
        # We either haven't checked yet, or it's a new day so we should check again.
        $script:UpdateCheckJobName = $jobNameToday
        $script:HasLatestVersion = $null
    }

    [scriptblock]$scriptBlock = {
        param($ModuleName)

        $params = @{}
        $params.Add('Uri', "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='$ModuleName'")
        $params.Add('Method', 'Get')
        $params.Add('UseDefaultCredentials', $true)
        $params.Add('UseBasicParsing', $true)

        try
        {
            # Disable Progress Bar in function scope during Invoke-WebRequest
            $ProgressPreference = 'SilentlyContinue'

            Invoke-WebRequest @params
        }
        catch
        {
            # We will silently ignore any errors that occurred, but we need to make sure that
            # we are explicitly catching and throwing them so that our reported state is Failed.
            throw
        }
    }

    $null = Start-Job -Name $script:UpdateCheckJobName -ScriptBlock $scriptBlock -Arg @($moduleName)

    # We're letting this run asynchronously so that users can immediately start using the module.
    # We'll check back in on the result of this the next time they run any command.
}

# We will explicitly run this as soon as the module has been loaded,
# and then it will be called again during every major function call in the module
# so that the result can be reported.
Invoke-UpdateCheck
# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCApxzenJfI8Smat
# QhOUUT0FpLksSu/LTlxnt4lWRI75fqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILF0hw+FylbDkPJxGAJyNKlk
# UVrE+Slzm/5GymbgG94BMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAL65123DK1/bfglBanStJqIu3TjGQwsLbvuSVMVX27IyEUZEHdHjQB
# 8btqoVq0wsTnZdQ/1aB5mR4wCukSJfLD0992C1KeJA22LTqVja4aucXy7JY2o6XP
# mj0cvzW28xOsILJeZiZaAOimhpRNki8KKUEjQbnEmHInTQjOQAUeDflDFTAWyy6K
# K/7B4WB0yz853EBEmE6McqpngsLwCsEDQsRMRAWTr25zBuQjFj7oNxnDmEggWgSh
# jCdwOApqSHtsYxfWB975GX9v2jeAqP0HgjRxfc9+6AhwDs3znPL/F/EVcit5a25/
# xbGz295gha9kis1/BHVDw7hJItxXtGk3oYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHgb1W8qQZqV5x0/UUVFXKlQkM42q4MranGHl+LMgu5WAgZlVuGY
# qrUYEzIwMjMxMTIxMTczNjI0LjA5NFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAePfvZuaHGiDIgABAAAB4zAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA3MjlaFw0yNTAxMTAxOTA3MjlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvqQNaB5Gn5/FIFQPo3/K
# 4QmleCDMF40bkoHwz0BshZ4SiQmA6CGUyDwmaqQ2wHhaXU0RdHtwvq+U8KxYYsyH
# KqaxxC7fr/yHZvHpNTgzx1VkR3pXhT6X2Cm175UX3WQ4jfl86onp5AMzBIFDlz0S
# U8VSKNMDvNXtjk9FitLgUv2nj3hOJ0KkEQfk3oA7m7zA0D+Mo73hmR+OC7uwsXxJ
# R2tzUZE0STYX3UvenFH7fYWy5BNmLyGq2sWkQ5HFvJKCJAE/dwft8+V43U3KeExF
# /pPtcLUvQ9HIrL0xnpMFau7Yd5aK+TEi57WctBv87+fSPZBV3jZl/QCtcH9WrniB
# Dwki9QfRxu/JYzw+iaEWLqrYXuF7jeOGvHK+fVeLWnAc5WxsfbpjEMpNbGXbSF9A
# t3PPhFVOjxwVEx1ALGUqRKehw9ap9X/gfkA9I9eTSvwJz9wya9reDgS+6kXgSttI
# 7RQ2cJG/tQPGVIaLCIaSafLneaq0Bns0t4+EW3B/GnoBMiiOXwleOvf5udBZQIMJ
# 3k5qnnh8Z4ZhTwrE6iGbPrTgGBPXh7exFYAGlb6hdhILIVDdJlDf8s1NVvL0Q2y4
# SHZQhApZTuW/tyGsGscIPDSMz5bA6NhRLtjEwCFpLI5qGlu50Au9FRelCEQsWg7q
# 07H/rqHOqCNJM4Rjem7joEUCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBSxrg1mvjUV
# t6Fnxj56nabZiJipAzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAt76bLqnU08wR
# bW3vRrxjaEbGPqyINK6UYCzhTGaR/PEwCJziPT4ZM9sfGTX3eZDQVE9r121tFtp7
# NXQYuQSxRZMYXa0/pawN2Xn+UPjBRDvoCsU56dwKkrmy8TSw7QXKGskdnEwsI5yW
# 93q8Ag86RkBiKEEf9FdzHNuKWI4Kv//fDtESewu46n/u+VckCwbOYl6wE//QRGrG
# Mq509a4EbP+p1GUm06Xme/01mTIuKDgPmHL2nYRzXNqi2IuIecn2aWwkRxQOFiPw
# +dicmOOwLG/7InNqjZpQeIhDMxsWr4zTxzy4ER/6zfthtlDtcAXHB7YRUkBTClaO
# a0ndvfNJZMyYVa6cWvZouTq9V5LS7UzIR8S/7RsOT43eOawLBsuQz0VoOLurYe1S
# ffPqTsCcRNzbx0C8t/+KipStVhPAGttEfhdUUS9ohD6Lt6wNCJxZbV0IMD8nfE6g
# IQJXrzrXWOuJqN91WDyjRan4UKDkIBS2yWA4W6JhQuBzGerOSY/aLnxkRrSubgtn
# KYcHOwgxTTIya5WYCRjFt0QOLleqVki6k+mqYPr98uMPi5vRIQS206mDSenStr8w
# 0J+/+1WEm3PnCCIQgpf6zhqRrAt9j7XrEMHrg2bQegaz8bLzbe6UibgbKtRyk1nG
# de8To5kyMj9XUCBICDxT+F4xa5lNZVQwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQA9iJe7w5FDiG8py4TsYrQI6DFaeqCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6QdOejAiGA8yMDIzMTEyMTIzNDI1MFoYDzIwMjMxMTIyMjM0MjUwWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDpB056AgEAMAcCAQACAgKbMAcCAQACAhF3MAoC
# BQDpCJ/6AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAJC9qXPsCCBBExJv/
# gtyPhVfiCE5pUMtZnoR7KTgS2Fox/zivi3FDcCLBTOHsSjSGmscKd+29H0MWoF0K
# LmFgDRxClZBRh102Sb9Hx3RyzeuQORkMQNdwbtrsgn5FjDAAgUKmeSUjX80ujseE
# ZFoNpfX3uek2MBlAbaT/UYkvHXYxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAePfvZuaHGiDIgABAAAB4zANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCDni6oiyga+6MjpK0u7PxDluIzApfxiUlqX23v94gC2LjCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIDPUI6vlsP5k90SBCNa9wha4MlxBt2Crw12PTHIy
# 5iYqMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHj
# 372bmhxogyIAAQAAAeMwIgQgAd26ZylHjs38VDlKqnZ0Wsgslt1EweWo5nkAkt3d
# 2V4wDQYJKoZIhvcNAQELBQAEggIAPqtkE9TnhClednm7yaeFCqmEwV9mES8Dc9ry
# uwyKirMBiAelEy3h4wwGSriK7I3T13v+cSt/vnNpiPTqSXPyh5hcuknRBkhA/gRH
# T0KQ5iX/eTGrNjOjvu8qDF2TMxYu4w3P4owyWikT3HCYBw7OC+8uwodT19TMSlzM
# SbiU+/9zIMM27P+fPFBoCaIMgE2QCW/kEWIzWJhc1B3FVdV42SX5QHYqBi/jm3Dj
# fH3nITDN46nB/EUZQZwSv8F9BRUOsdWsxdCCRIG6OnUdRRcDqqxTo9ZlhbcdZ35e
# fQacUAhb665ZzpxfGOrZFvNyaShaeWHyorbXMtBodEdQ/oLhdXOj34gNvp4FASfV
# gESuvSVF0KsCwZS8/bYL4/Bx8DyqFO0zStA16Cb96lFPTr0bmEzQ6YY+6Hc2BeHt
# Tk/h6jXLnSjunoji7DdXaAR/z4OWkPI7sntRmqrKQ/3FTUxDl45fbfeEtQHeFfth
# /Exb6remDg636JQsya+h72mcf61JMWCe8MF3Qiy1yjugwPDs4yb3IWp899s7PoFh
# h5zU29/hrDsgTjLusx98X23oz/mqHnsUzjxISYZoNKN6YIuhK67whzNUEDnJ0fkN
# ZFC08hTRM3cMmuG32Cut4v5OsqYWkG9/e5/K9MFK+Set2PATliQkfptqTlqcSc2w
# fR4lco4=
# SIG # End signature block
