
Import-Module Pester
Import-Module GitHubActions

Set-Variable -Scope Script -Option Constant -Name EOL -Value ([System.Environment]::NewLine) -ErrorAction Ignore

# Setup temp files for GitHub Actions environment variables
# These are required by the GitHubActions module to write environment variables, paths, and outputs
BeforeAll {
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "GitHubActionsTests_$([System.Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null

    $env:GITHUB_ENV = Join-Path $script:TempDir 'github_env'
    $env:GITHUB_PATH = Join-Path $script:TempDir 'github_path'
    $env:GITHUB_OUTPUT = Join-Path $script:TempDir 'github_output'

    # Create the files
    New-Item -ItemType File -Path $env:GITHUB_ENV -Force | Out-Null
    New-Item -ItemType File -Path $env:GITHUB_PATH -Force | Out-Null
    New-Item -ItemType File -Path $env:GITHUB_OUTPUT -Force | Out-Null
}

AfterAll {
    # Cleanup temp files
    if ($script:TempDir -and (Test-Path $script:TempDir)) {
        Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $env:GITHUB_ENV = $null
    $env:GITHUB_PATH = $null
    $env:GITHUB_OUTPUT = $null
}

Describe 'Set-ActionVariable' {
    $testCases = @(
        @{ Name = 'varName1'  ; Value = 'varValue1' }
        @{ Name = 'var name 2'; Value = 'var value 2' }
        @{ Name = 'var,name;3'; Value = 'var,value;3' }
    )

    BeforeEach {
        # Clear the GITHUB_ENV file and test environment variables before each test
        Set-Content -Path $env:GITHUB_ENV -Value '' -NoNewline
        [System.Environment]::SetEnvironmentVariable('varName1', $null)
        [System.Environment]::SetEnvironmentVariable('var name 2', $null)
        [System.Environment]::SetEnvironmentVariable('var,name;3', $null)
    }
    It 'Given valid -Name and -Value, and -SkipLocal' -TestCases $testCases {
        param($Name, $Value)

        Set-ActionVariable $Name $Value -SkipLocal
        $fileContent = Get-Content -Path $env:GITHUB_ENV -Raw
        $fileContent | Should -Match ([regex]::Escape("$Name=$Value"))
        [System.Environment]::GetEnvironmentVariable($Name) | Should -BeNullOrEmpty
    }
    It 'Given valid -Name and -Value, and NOT -SkipLocal' -TestCases $testCases {
        param($Name, $Value)

        Set-ActionVariable $Name $Value
        $fileContent = Get-Content -Path $env:GITHUB_ENV -Raw
        $fileContent | Should -Match ([regex]::Escape("$Name=$Value"))
        [System.Environment]::GetEnvironmentVariable($Name) | Should -Be $Value
    }
}

Describe 'Add-ActionSecretMask' {
    It 'Given a valid -Secret' {
        $secret = 'f00B@r!'
        Add-ActionSecretMask $secret | Should -Be "::add-mask::$($secret)$EOL"
    }
}

Describe 'Add-ActionPath' {
    BeforeEach {
        # Clear the GITHUB_PATH file before each test
        Set-Content -Path $env:GITHUB_PATH -Value '' -NoNewline
    }

    It 'Given a valid -Path and -SkipLocal' {
        $addPath = '/to/some/path'
        $oldPath = [System.Environment]::GetEnvironmentVariable('PATH')
        Add-ActionPath $addPath -SkipLocal
        $fileContent = Get-Content -Path $env:GITHUB_PATH -Raw
        $fileContent | Should -Match ([regex]::Escape($addPath))
        [System.Environment]::GetEnvironmentVariable('PATH') | Should -Be $oldPath
    }

    It 'Given a valid -Path and NOT -SkipLocal' {
        $addPath = '/to/some/path'
        $oldPath = [System.Environment]::GetEnvironmentVariable('PATH')
        $newPath = "$($addPath)$([System.IO.Path]::PathSeparator)$($oldPath)"
        Add-ActionPath $addPath
        $fileContent = Get-Content -Path $env:GITHUB_PATH -Raw
        $fileContent | Should -Match ([regex]::Escape($addPath))
        [System.Environment]::GetEnvironmentVariable('PATH') | Should -Be $newPath
    }
}

Describe 'Get-ActionInput' {
    [System.Environment]::SetEnvironmentVariable('INPUT_INPUT1', 'Value 1')
    [System.Environment]::SetEnvironmentVariable('INPUT_INPUT3', 'Value 3')

    $testCases = @(
        @{ Name = 'input1' ; Should = @{ Be = $true; ExpectedValue = 'Value 1' } }
        @{ Name = 'INPUT1' ; Should = @{ Be = $true; ExpectedValue = 'Value 1' } }
        @{ Name = 'Input1' ; Should = @{ Be = $true; ExpectedValue = 'Value 1' } }
        @{ Name = 'input2' ; Should = @{ BeNullOrEmpty = $true } }
        @{ Name = 'INPUT2' ; Should = @{ BeNullOrEmpty = $true } }
        @{ Name = 'Input2' ; Should = @{ BeNullOrEmpty = $true } }
    )

    It 'Given valid -Name' -TestCases $testCases {
        param($Name, $Should)

        Get-ActionInput $Name | Should @Should
        Get-ActionInput $Name | Should @Should
        Get-ActionInput $Name | Should @Should
        Get-ActionInput $Name | Should @Should
        Get-ActionInput $Name | Should @Should
        Get-ActionInput $Name | Should @Should
    }
}

Describe 'Get-ActionInputs' {
    [System.Environment]::SetEnvironmentVariable('INPUT_INPUT1', 'Value 1')
    [System.Environment]::SetEnvironmentVariable('INPUT_INPUT3', 'Value 3')

    $testCases = @(
        @{ Name = 'InPut1' ; Should = @{ Be = $true; ExpectedValue = "Value 1" } }
        @{ Name = 'InPut2' ; Should = @{ BeNullOrEmpty = $true } }
        @{ Name = 'InPut3' ; Should = @{ Be = $true; ExpectedValue = "Value 3" } }
    )

    ## We skip this test during CI build because we can't be sure of the actual
    ## number of INPUT_ environment variables in the real GH Workflow environment
    It 'Given 2 predefined inputs' -Tag 'SkipCI' {
        $inputs = Get-ActionInputs
        $inputs.Count | Should -Be 2
    }

    It 'Given 2 predefined inputs, and a -Name in any case' -TestCases $testCases {
        param($Name, $Should)

        $inputs = Get-ActionInputs

        $key = $Name
        $inputs[$key] | Should @Should
        $inputs.$key | Should @Should
        $key = $Name.ToUpper()
        $inputs[$key] | Should @Should
        $inputs.$key | Should @Should
        $key = $Name.ToLower()
        $inputs[$key] | Should @Should
        $inputs.$key | Should @Should
    }
}

Describe 'Set-ActionOuput' {
    BeforeEach {
        # Clear the GITHUB_OUTPUT file before each test
        Set-Content -Path $env:GITHUB_OUTPUT -Value '' -NoNewline
    }

    It 'Given a valid -Name and -Value' {
        Set-ActionOutput 'foo_bar' 'foo bar value'
        $fileContent = Get-Content -Path $env:GITHUB_OUTPUT -Raw
        $fileContent | Should -Match 'foo_bar=foo bar value'
    }
}

Describe 'Write-ActionDebug' {
    It 'Given a valid -Message' {
        $output = Write-ActionDebug 'This is a sample message'
        $output | Should -Be "::debug::This is a sample message$EOL"
    }
}

Describe 'Write-ActionError' {
    It 'Given a valid -Message' {
        $output = Write-ActionError 'This is a sample message'
        $output | Should -Be "::error::This is a sample message$EOL"
    }
}

Describe 'Write-ActionWarning' {
    It 'Given a valid -Message' {
        $output = Write-ActionWarning 'This is a sample message'
        $output | Should -Be "::warning::This is a sample message$EOL"
    }
}

Describe 'Write-ActionInfo' {
    It 'Given a valid -Message' {
        $output = Write-ActionInfo 'This is a sample message'
        $output | Should -Be "This is a sample message$EOL"
    }
}

Describe 'Enter-ActionOutputGroup' {
    It 'Given a valid -Name' {
        $output = Enter-ActionOutputGroup 'Sample Group'
        $output | Should -Be "::group::Sample Group$EOL"
    }
}

Describe 'Exit-ActionOutputGroup' {
    It 'Given everything is peachy' {
        $output = Exit-ActionOutputGroup
        $output | Should -Be "::endgroup::$EOL"
    }
}

Describe 'Invoke-ActionWithinOutputGroup' {
    It 'Given a valid -Name and -ScriptBlock' {
        $output = Invoke-ActionWithinOutputGroup 'Sample Group' {
            Write-ActionInfo "Message 1"
            Write-ActionInfo "Message 2"
        }

        $output | Should -Be @(
            "::group::Sample Group$EOL"
            "Message 1$EOL"
            "Message 2$EOL"
            "::endgroup::$EOL"
        )
    }
}
