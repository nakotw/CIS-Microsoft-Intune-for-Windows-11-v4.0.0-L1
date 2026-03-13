#Requires -RunAsAdministrator
<#!
.SYNOPSIS
  Full benchmark-style local machine auditor for CIS Microsoft Intune for Windows 11 v4.0.0 L1.

.DESCRIPTION
  Parses the supplied Tenable/Nessus .audit file and evaluates every supported custom_item
  locally on the endpoint. This version is designed for the uploaded CIS_Microsoft_Intune_for_Windows_11_v4.0.0_L1.audit.

  Supported item types in this benchmark:
    - REGISTRY_SETTING
    - GUID_REGISTRY_SETTING
    - REG_CHECK
    - AUDIT_POLICY_SUBCATEGORY
    - USER_RIGHTS_POLICY
    - CHECK_ACCOUNT
    - BANNER_CHECK
    - AUDIT_POWERSHELL

  Output files:
    - HTML dashboard
    - JSON results
    - CSV results

.NOTES
  - Use only with trusted .audit files.
  - Some controls are evaluated via PowerShell snippets embedded in the .audit file.
  - Default path targets the uploaded Tenable benchmark file.
#>

param(
    [string]$AuditFilePath = "/mnt/data/CIS_Microsoft_Intune_for_Windows_11_v4.0.0_L1.audit",
    [string]$OutputDirectory = "C:\Temp\CIS_Intune_W11_v4_Audit",
    [switch]$DoNotOpenReport
)

$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# ─────────────────────────────────────────────────────────────
#  Generic helpers
# ─────────────────────────────────────────────────────────────

function Write-Info  { param([string]$Text) Write-Host "[+] $Text" -ForegroundColor Cyan }
function Write-Good  { param([string]$Text) Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Warn  { param([string]$Text) Write-Host "[!] $Text" -ForegroundColor Yellow }
function Write-Bad   { param([string]$Text) Write-Host "[!] $Text" -ForegroundColor Red }

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Convert-ToPsRegistryPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim().Trim('"')
    if ($p -match '^(HKLM|HKEY_LOCAL_MACHINE)\\') {
        return ($p -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\' -replace '^HKLM\\', 'HKLM:\')
    }
    if ($p -match '^(HKCU|HKEY_CURRENT_USER)\\') {
        return ($p -replace '^HKEY_CURRENT_USER\\', 'HKCU:\' -replace '^HKCU\\', 'HKCU:\')
    }
    if ($p -match '^(HKCR|HKEY_CLASSES_ROOT)\\') {
        return ($p -replace '^HKEY_CLASSES_ROOT\\', 'HKCR:\' -replace '^HKCR\\', 'HKCR:\')
    }
    if ($p -match '^(HKU|HKEY_USERS)\\') {
        return ($p -replace '^HKEY_USERS\\', 'HKU:\' -replace '^HKU\\', 'HKU:\')
    }
    if ($p -match '^(HKCC|HKEY_CURRENT_CONFIG)\\') {
        return ($p -replace '^HKEY_CURRENT_CONFIG\\', 'HKCC:\' -replace '^HKCC\\', 'HKCC:\')
    }
    return $p
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $psPath = Convert-ToPsRegistryPath $Path
        if (-not $psPath) { return $null }
        if ($psPath -match '\\Interfaces$') {
            $items = Get-ChildItem -Path $psPath -ErrorAction Stop
            $vals = foreach ($item in $items) {
                try {
                    $p = Get-ItemProperty -Path $item.PSPath -Name $Name -ErrorAction Stop
                    $p.$Name
                } catch {}
            }
            if ($vals) { return $vals }
            return $null
        }
        $val = Get-ItemProperty -Path $psPath -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

function Test-RegExists {
    param([string]$Path, [string]$Name)
    try {
        $psPath = Convert-ToPsRegistryPath $Path
        if (-not $psPath) { return $false }
        $null = Get-ItemProperty -Path $psPath -Name $Name -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-AuditSetting {
    param([string]$Category)
    try {
        $result = auditpol /get /subcategory:"$Category" 2>$null
        if ($result) {
            $line = $result | Where-Object { $_ -match [regex]::Escape($Category) }
            if ($line -match 'Success and Failure') { return 'Success and Failure' }
            elseif ($line -match 'Success') { return 'Success' }
            elseif ($line -match 'Failure') { return 'Failure' }
            else { return 'No Auditing' }
        }
    } catch {}
    return 'Unknown'
}

function Export-SeceditContent {
    try {
        $tmpFile = Join-Path $env:TEMP ("secpol_{0}.inf" -f ([guid]::NewGuid().ToString()))
        secedit /export /cfg $tmpFile /quiet 2>$null | Out-Null
        $content = Get-Content -LiteralPath $tmpFile -Raw -ErrorAction Stop
        Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
        return $content
    } catch {
        return $null
    }
}

function Get-UserRightsMap {
    $content = Export-SeceditContent
    $map = @{}
    if (-not $content) { return $map }

    $inPrivilege = $false
    foreach ($line in ($content -split "`r?`n")) {
        if ($line -match '^\[Privilege Rights\]') { $inPrivilege = $true; continue }
        if ($inPrivilege -and $line -match '^\[') { break }
        if ($inPrivilege -and $line -match '^\s*([^=]+?)\s*=\s*(.*)$') {
            $right = $Matches[1].Trim()
            $raw   = $Matches[2].Trim()
            $vals  = if ([string]::IsNullOrWhiteSpace($raw)) { @() } else { $raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
            $map[$right] = $vals
        }
    }
    return $map
}

function Convert-SidOrNameToComparableLabel {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('*')
    try {
        if ($v -match '^S-1-') {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($v)
            $translated = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            return $translated
        }
    } catch {}
    return $v
}

function Expand-ComparablePrincipalNames {
    param([string[]]$Principals)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Principals) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $x = Convert-SidOrNameToComparableLabel $p
        if (-not $x) { continue }
        $list.Add($x)
        if ($x -match '^BUILTIN\\(.+)$') { $list.Add($Matches[1]) }
        if ($x -match '^[^\\]+\\(.+)$') { $list.Add($Matches[1]) }
        $list.Add($x.ToLowerInvariant())
        if ($x -match '^.+\\(.+)$') { $list.Add($Matches[1].ToLowerInvariant()) }
    }
    return ($list | Select-Object -Unique)
}

function Compare-UserRightsExpression {
    param(
        [string[]]$ActualPrincipals,
        [string]$ExpectedExpression,
        [string]$CheckType
    )

    $actualExpanded = Expand-ComparablePrincipalNames $ActualPrincipals
    $actualString = ($actualExpanded -join ' | ')

    if ($ExpectedExpression -eq '""' -or [string]::IsNullOrWhiteSpace($ExpectedExpression)) {
        $pass = -not $ActualPrincipals -or $ActualPrincipals.Count -eq 0
        return @{ Pass=$pass; Actual=$actualString; Expected='No One' }
    }

    $groups = @()
    foreach ($grp in ([regex]::Matches($ExpectedExpression, '\((.*?)\)') | ForEach-Object { $_.Groups[1].Value })) {
        if ($grp) { $groups += $grp }
    }
    if (-not $groups) { $groups = @($ExpectedExpression) }

    $groupResults = foreach ($grp in $groups) {
        $tokens = [regex]::Matches($grp, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
        if (-not $tokens) { continue }
        $allPresent = $true
        foreach ($token in $tokens) {
            $tokenLc = $token.ToLowerInvariant()
            $match = $actualExpanded | Where-Object {
                $_.ToString().ToLowerInvariant() -eq $tokenLc -or $_.ToString().ToLowerInvariant() -like "*\$tokenLc" -or $_.ToString().ToLowerInvariant() -like "*$tokenLc*"
            } | Select-Object -First 1
            if (-not $match) { $allPresent = $false; break }
        }
        $allPresent
    }

    if ($CheckType -eq 'CHECK_SUPERSET') {
        $tokens = [regex]::Matches($ExpectedExpression, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
        $pass = $true
        foreach ($token in $tokens) {
            $tokenLc = $token.ToLowerInvariant()
            $match = $actualExpanded | Where-Object { $_.ToString().ToLowerInvariant() -like "*$tokenLc*" } | Select-Object -First 1
            if (-not $match) { $pass = $false; break }
        }
    } else {
        $pass = $groupResults -contains $true
    }

    return @{ Pass=$pass; Actual=$actualString; Expected=$ExpectedExpression }
}

function Invoke-SafeAuditPowerShell {
    param([string]$Code)
    try {
        $output = Invoke-Expression $Code 2>$null | Out-String
        return $output.Trim()
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

function Get-LocalAccountNameSafe {
    param([ValidateSet('Administrator','Guest')] [string]$Account)
    try {
        $sid = if ($Account -eq 'Administrator') { 'S-1-5-21-*-500' } else { 'S-1-5-21-*-501' }
        $wmi = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like $sid } | Select-Object -First 1
        if ($wmi) { return $wmi.Name }
    } catch {}
    try {
        $user = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
        if ($user) { return $user.Name }
    } catch {}
    return $Account
}

# ─────────────────────────────────────────────────────────────
#  Audit parser
# ─────────────────────────────────────────────────────────────

function Get-AuditFieldValue {
    param(
        [string]$Block,
        [string]$FieldName
    )

    $pattern = '(?ms)^\s*{0}\s*:\s*(".*?"|''.*?''|[^\r\n]+)\s*(?=^\s*[A-Za-z0-9_]+\s*:|\z)' -f [regex]::Escape($FieldName)
    $m = [regex]::Match($Block, $pattern)
    if (-not $m.Success) { return $null }
    $value = $m.Groups[1].Value.Trim()
    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value.Trim()
}

function Get-AuditVariables {
    param([string]$AuditText)

    $vars = @{}
    $matches = [regex]::Matches($AuditText, '(?ims)^\s*#\s*<variable>\s*$.*?^\s*#\s*</variable>\s*$')

    foreach ($m in $matches) {
        $block = $m.Value -replace '(?m)^\s*#\s?', ''

        $nameMatch = [regex]::Match($block, '(?ims)<name>(.*?)</name>')
        $defaultMatch = [regex]::Match($block, '(?ims)<default>(.*?)</default>')

        $name = $nameMatch.Groups[1].Value.Trim()
        $default = $defaultMatch.Groups[1].Value.Trim()

        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $vars[$name] = $default
        }
    }

    return $vars
}

function Resolve-AuditVariables {
    param(
        [string]$Value,
        [hashtable]$Variables
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $resolved = $Value
    foreach ($key in $Variables.Keys) {
        $resolved = $resolved -replace [regex]::Escape("@$key@"), [regex]::Escape($Variables[$key]) -replace '\\\\', '\'
    }
    return $resolved
}

function Get-AuditItems {
    param([string]$AuditText)
    $thenIndex = $AuditText.IndexOf('<then>')
    if ($thenIndex -lt 0) { return @() }
    $content = $AuditText.Substring($thenIndex)
    $blocks = [regex]::Matches($content, '(?ms)<custom_item>(.*?)</custom_item>')
    $items = foreach ($m in $blocks) {
        $block = $m.Groups[1].Value
        $type = Get-AuditFieldValue $block 'type'
        if (-not $type) { continue }
        [PSCustomObject]@{
            Type           = $type
            Description    = Get-AuditFieldValue $block 'description'
            Info           = Get-AuditFieldValue $block 'info'
            Solution       = Get-AuditFieldValue $block 'solution'
            Reference      = Get-AuditFieldValue $block 'reference'
            SeeAlso        = Get-AuditFieldValue $block 'see_also'
            ValueType      = Get-AuditFieldValue $block 'value_type'
            ValueData      = Get-AuditFieldValue $block 'value_data'
            RegKey         = Get-AuditFieldValue $block 'reg_key'
            RegItem        = Get-AuditFieldValue $block 'reg_item'
            RegOption      = Get-AuditFieldValue $block 'reg_option'
            GuidRegKey     = Get-AuditFieldValue $block 'guid_reg_key'
            KeyItem        = Get-AuditFieldValue $block 'key_item'
            CheckType      = Get-AuditFieldValue $block 'check_type'
            PowerShellArgs = Get-AuditFieldValue $block 'powershell_args'
            RightType      = Get-AuditFieldValue $block 'right_type'
            AccountType    = Get-AuditFieldValue $block 'account_type'
        }
    }
    return $items
}

# ─────────────────────────────────────────────────────────────
#  Evaluation engine
# ─────────────────────────────────────────────────────────────

function Get-CheckIdFromDescription {
    param([string]$Description)
    if ($Description -match '^(\d+(?:\.\d+)*)') { return $Matches[1] }
    return 'PRECHECK'
}

function Get-SectionFromId {
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return 'OTHER' }

    $top = [int](($Id -split '\.')[0])

    $categoryMap = @{
        1  = 'CONFIGURATION MANAGEMENT'
        2  = 'ACCESS CONTROL'
        3  = 'ACCESS CONTROL'
        4  = 'ACCESS CONTROL'
        5  = 'CONFIGURATION MANAGEMENT'
        6  = 'CONFIGURATION MANAGEMENT'
        7  = 'SYSTEM AND INFORMATION INTEGRITY'
        8  = 'IDENTIFICATION AND AUTHENTICATION, SYSTEM AND COMMUNICATIONS PROTECTION'
        9  = 'IDENTIFICATION AND AUTHENTICATION, SYSTEM AND COMMUNICATIONS PROTECTION'
        10 = 'SYSTEM AND COMMUNICATIONS PROTECTION'
        11 = 'SYSTEM AND COMMUNICATIONS PROTECTION'
        12 = 'CONFIGURATION MANAGEMENT, SYSTEM AND SERVICES ACQUISITION'
        13 = 'ACCESS CONTROL, CONFIGURATION MANAGEMENT'
        14 = 'SYSTEM AND INFORMATION INTEGRITY'
        15 = 'ACCESS CONTROL'
        16 = 'AUDIT AND ACCOUNTABILITY'
        17 = 'CONFIGURATION MANAGEMENT'
        18 = 'ACCESS CONTROL, CONFIGURATION MANAGEMENT'
        19 = 'CONFIGURATION MANAGEMENT'
        20 = 'ACCESS CONTROL'
        21 = 'IDENTIFICATION AND AUTHENTICATION'
        22 = 'IDENTIFICATION AND AUTHENTICATION'
    }

    if ($categoryMap.ContainsKey($top)) { return $categoryMap[$top] }
    return 'OTHER'
}

function New-Result {
    param(
        [string]$Id,
        [string]$Section,
        [string]$Type,
        [string]$Title,
        [string]$Status,
        [string]$Actual,
        [string]$Expected,
        [string]$Remediation,
        [string]$Info,
        [string]$Reference,
        [string]$SeeAlso
    )
    [PSCustomObject]@{
        ID          = $Id
        Section     = $Section
        Type        = $Type
        Title       = $Title
        Status      = $Status
        Actual      = $Actual
        Expected    = $Expected
        Remediation = $Remediation
        Info        = $Info
        Reference   = $Reference
        SeeAlso     = $SeeAlso
    }
}

function Test-RegistryItem {
    param([pscustomobject]$Item, [hashtable]$Variables)

    $expected = Resolve-AuditVariables $Item.ValueData $Variables
    $regPath = if ($Item.Type -eq 'GUID_REGISTRY_SETTING' -and $Item.GuidRegKey) { $Item.GuidRegKey } else { $Item.RegKey }
    $actual = Get-RegValue -Path $regPath -Name $Item.RegItem
    if ($null -eq $actual -and $Item.Type -eq 'GUID_REGISTRY_SETTING' -and $Item.RegKey -and $Item.RegKey -notmatch '\{GUID\}') {
        $actual = Get-RegValue -Path $Item.RegKey -Name $Item.RegItem
    }

    if ($null -eq $actual) {
        return @{ Status='FAIL'; Actual='Not configured (null)'; Expected=$expected }
    }

    $actualText = if ($actual -is [array]) { $actual -join ', ' } else { [string]$actual }
    $status = 'FAIL'

    switch ($Item.CheckType) {
        'CHECK_REGEX' {
            $status = if ($actualText -match $expected) { 'PASS' } else { 'FAIL' }
        }
        'CHECK_NOT_REGEX' {
            $status = if ($actualText -notmatch $expected) { 'PASS' } else { 'FAIL' }
        }
        'CHECK_NOT_EQUAL' {
            $status = if ($actualText -ne $expected) { 'PASS' } else { 'FAIL' }
        }
        default {
            if ($Item.ValueType -eq 'POLICY_DWORD') {
                $status = if ([string]$actual -eq [string]$expected) { 'PASS' } else { 'FAIL' }
            } else {
                $status = if ($actualText -eq $expected) { 'PASS' } else { 'FAIL' }
            }
        }
    }

    return @{ Status=$status; Actual=$actualText; Expected=$expected }
}

function Test-RegCheckItem {
    param([pscustomobject]$Item, [hashtable]$Variables)
    $path = Resolve-AuditVariables $Item.ValueData $Variables
    $exists = Test-RegExists -Path $path -Name $Item.KeyItem
    $actual = if ($exists) { 'Exists' } else { 'Does not exist' }
    $expected = $Item.RegOption
    $status = 'FAIL'
    switch ($Item.RegOption) {
        'MUST_EXIST' { $status = if ($exists) { 'PASS' } else { 'FAIL' } }
        'MUST_NOT_EXIST' { $status = if (-not $exists) { 'PASS' } else { 'FAIL' } }
        default { $status = 'MANUAL' }
    }
    return @{ Status=$status; Actual=$actual; Expected=$expected }
}

function Test-AuditPolicyItem {
    param([pscustomobject]$Item, [hashtable]$Variables)
    $expected = Resolve-AuditVariables $Item.ValueData $Variables
    $name = $Item.Description -replace '^\d+(?:\.\d+)*\s*\(L\d\)\s*Ensure\s*''?', ''
    if ($Item.Description -match "Ensure '(.+?)' is set to '(.+?)'") {
        $subcategory = $Matches[1] -replace '^Account Logon ','Account Logon ' -replace '^Audit ','Audit '
        $actual = Get-AuditSetting -Category $subcategory
        $status = if ($actual -eq $Matches[2]) { 'PASS' } elseif ($Matches[2] -eq 'Success' -and $actual -eq 'Success and Failure') { 'PASS' } elseif ($Matches[2] -eq 'Failure' -and $actual -eq 'Success and Failure') { 'PASS' } else { 'FAIL' }
        return @{ Status=$status; Actual=$actual; Expected=$Matches[2] }
    }
    return @{ Status='MANUAL'; Actual='Unable to parse subcategory'; Expected=$expected }
}

function Test-AuditPowerShellItem {
    param([pscustomobject]$Item, [hashtable]$Variables)
    $expected = Resolve-AuditVariables $Item.ValueData $Variables
    $actual = Invoke-SafeAuditPowerShell $Item.PowerShellArgs
    $status = 'FAIL'
    switch ($Item.CheckType) {
        'CHECK_REGEX' { $status = if ($actual -match $expected) { 'PASS' } else { 'FAIL' } }
        'CHECK_NOT_REGEX' { $status = if ($actual -notmatch $expected) { 'PASS' } else { 'FAIL' } }
        'CHECK_NOT_EQUAL' { $status = if ($actual -ne $expected) { 'PASS' } else { 'FAIL' } }
        default { $status = if ($actual -eq $expected) { 'PASS' } else { 'FAIL' } }
    }
    return @{ Status=$status; Actual=$actual; Expected=$expected }
}

function Test-AccountItem {
    param([pscustomobject]$Item, [hashtable]$Variables)
    $expected = Resolve-AuditVariables $Item.ValueData $Variables
    $accountName = if ($Item.AccountType -eq 'ADMINISTRATOR_ACCOUNT') { Get-LocalAccountNameSafe -Account Administrator } else { Get-LocalAccountNameSafe -Account Guest }

    try {
        $user = Get-LocalUser -Name $accountName -ErrorAction Stop
    } catch {
        return @{ Status='FAIL'; Actual='Account not found'; Expected=$expected }
    }

    $actual = $accountName
    $status = 'FAIL'

    if ($Item.CheckType -eq 'CHECK_NOT_REGEX') {
        $status = if ($actual -notmatch $expected) { 'PASS' } else { 'FAIL' }
    } elseif ($Item.CheckType -eq 'CHECK_NOT_EQUAL') {
        $status = if ($actual -ne $expected) { 'PASS' } else { 'FAIL' }
    } else {
        if ($expected -eq 'Disabled') {
            $actual = if ($user.Enabled) { 'Enabled' } else { 'Disabled' }
            $status = if (-not $user.Enabled) { 'PASS' } else { 'FAIL' }
        } else {
            $status = if ($actual -eq $expected) { 'PASS' } else { 'FAIL' }
        }
    }

    return @{ Status=$status; Actual=$actual; Expected=$expected }
}

function Test-BannerItem {
    param([pscustomobject]$Item, [hashtable]$Variables)
    $expected = Resolve-AuditVariables $Item.ValueData $Variables
    $actual = Get-RegValue -Path $Item.RegKey -Name $Item.RegItem
    if ($null -eq $actual) { $actual = '' }
    $status = if ([string]$actual -eq [string]$expected) { 'PASS' } else { 'FAIL' }
    return @{ Status=$status; Actual=[string]$actual; Expected=$expected }
}

function Test-UserRightsItem {
    param([pscustomobject]$Item, [hashtable]$Variables, [hashtable]$UserRightsMap)
    $expected = Resolve-AuditVariables $Item.ValueData $Variables
    $actualList = @()
    if ($UserRightsMap.ContainsKey($Item.RightType)) { $actualList = $UserRightsMap[$Item.RightType] }
    $compare = Compare-UserRightsExpression -ActualPrincipals $actualList -ExpectedExpression $expected -CheckType $Item.CheckType
    return @{ Status = if ($compare.Pass) { 'PASS' } else { 'FAIL' }; Actual = $compare.Actual; Expected = $compare.Expected }
}

# ─────────────────────────────────────────────────────────────
#  HTML report helpers
# ─────────────────────────────────────────────────────────────

function New-HtmlEncoded { param([string]$Text) [System.Web.HttpUtility]::HtmlEncode([string]$Text) }

# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

if (-not (Test-Path -LiteralPath $AuditFilePath)) {
    throw "Audit file not found: $AuditFilePath"
}

Ensure-Directory -Path $OutputDirectory

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$htmlPath  = Join-Path $OutputDirectory "CIS_Intune_W11_v4_LocalAudit_$timestamp.html"
$jsonPath  = Join-Path $OutputDirectory "CIS_Intune_W11_v4_LocalAudit_$timestamp.json"
$csvPath   = Join-Path $OutputDirectory "CIS_Intune_W11_v4_LocalAudit_$timestamp.csv"

Write-Info "Loading audit file..."
$auditText  = Get-Content -LiteralPath $AuditFilePath -Raw -Encoding UTF8
$variables  = Get-AuditVariables -AuditText $auditText
$items      = Get-AuditItems -AuditText $auditText
$userRights = Get-UserRightsMap

Write-Info "Parsed $($items.Count) custom_item entries."

$results = New-Object System.Collections.Generic.List[object]

foreach ($item in $items) {
    $id = Get-CheckIdFromDescription $item.Description
    $section = Get-SectionFromId $id
    $test = switch ($item.Type) {
        'REGISTRY_SETTING'        { Test-RegistryItem -Item $item -Variables $variables }
        'GUID_REGISTRY_SETTING'   { Test-RegistryItem -Item $item -Variables $variables }
        'REG_CHECK'               { Test-RegCheckItem -Item $item -Variables $variables }
        'AUDIT_POLICY_SUBCATEGORY'{ Test-AuditPolicyItem -Item $item -Variables $variables }
        'AUDIT_POWERSHELL'        { Test-AuditPowerShellItem -Item $item -Variables $variables }
        'USER_RIGHTS_POLICY'      { Test-UserRightsItem -Item $item -Variables $variables -UserRightsMap $userRights }
        'CHECK_ACCOUNT'           { Test-AccountItem -Item $item -Variables $variables }
        'BANNER_CHECK'            { Test-BannerItem -Item $item -Variables $variables }
        default                   { @{ Status='MANUAL'; Actual='Unsupported item type'; Expected=$item.ValueData } }
    }

    $results.Add((New-Result -Id $id -Section $section -Type $item.Type -Title $item.Description -Status $test.Status -Actual $test.Actual -Expected $test.Expected -Remediation $item.Solution -Info $item.Info -Reference $item.Reference -SeeAlso $item.SeeAlso))
}

$totalChecks   = $results.Count
$passCount     = ($results | Where-Object Status -eq 'PASS').Count
$failCount     = ($results | Where-Object Status -eq 'FAIL').Count
$manualCount   = ($results | Where-Object Status -eq 'MANUAL').Count
$errorCount    = ($results | Where-Object Status -eq 'ERROR').Count
$scorePercent  = if ($totalChecks -gt 0) { [math]::Round((($passCount) / $totalChecks) * 100, 1) } else { 0 }

$computerName = $env:COMPUTERNAME
$osInfo       = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$osCaption    = if ($osInfo) { $osInfo.Caption } else { 'Unknown OS' }
$osBuild      = if ($osInfo) { $osInfo.BuildNumber } else { 'N/A' }
$reportDate   = Get-Date -Format "dddd, MMMM d, yyyy 'at' HH:mm:ss"
$runAsUser    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$benchName    = 'CIS Microsoft Intune for Windows 11 v4.0.0 L1'

Write-Good "Assessment complete: $passCount/$totalChecks passed ($scorePercent%)."

$results | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $jsonPath -Encoding UTF8 -Force
$results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -Force

$sectionOrder = $results.Section | Select-Object -Unique
$sectionSummary = @{}
foreach ($check in $results) {
    if (-not $sectionSummary.ContainsKey($check.Section)) {
        $sectionSummary[$check.Section] = @{ Pass=0; Fail=0; Manual=0; Total=0 }
    }
    $sectionSummary[$check.Section].Total++
    switch ($check.Status) {
        'PASS'   { $sectionSummary[$check.Section].Pass++ }
        'FAIL'   { $sectionSummary[$check.Section].Fail++ }
        default  { $sectionSummary[$check.Section].Manual++ }
    }
}

$summaryCards = ''
foreach ($sec in $sectionOrder) {
    $sd = $sectionSummary[$sec]
    $pct = if ($sd.Total -gt 0) { [math]::Round(($sd.Pass / $sd.Total) * 100) } else { 0 }
    $col = if ($pct -ge 80) { '#22c55e' } elseif ($pct -ge 50) { '#f59e0b' } else { '#ef4444' }
    $secId = ($sec -replace '[^a-zA-Z0-9]','-')
    $summaryCards += @"
    <a class="jump-link" href="#sec-$secId">
      <div class="left">
        <div class="name">$(New-HtmlEncoded $sec)</div>
        <div class="sub">$($sd.Pass)/$($sd.Total) pass · $($sd.Fail) fail · $($sd.Manual) other</div>
      </div>
      <div class="pct" style="color:$col">${pct}%</div>
    </a>
"@
}

$sectionHtml = ''
foreach ($sec in $sectionOrder) {
    $secChecks = $results | Where-Object Section -eq $sec
    $secPass   = ($secChecks | Where-Object Status -eq 'PASS').Count
    $secFail   = ($secChecks | Where-Object Status -eq 'FAIL').Count
    $secOther  = ($secChecks | Where-Object { $_.Status -notin @('PASS','FAIL') }).Count
    $secTotal  = $secChecks.Count
    $secPct    = if ($secTotal -gt 0) { [math]::Round(($secPass / $secTotal) * 100) } else { 0 }
    $barColor  = if ($secPct -ge 80) { '#22c55e' } elseif ($secPct -ge 50) { '#f59e0b' } else { '#ef4444' }
    $secId     = ($sec -replace '[^a-zA-Z0-9]','-')

    $rows = ''
    foreach ($c in $secChecks) {
        $statusClass = switch ($c.Status) { 'PASS' {'status-pass'} 'FAIL' {'status-fail'} default {'status-other'} }
        $statusDot   = switch ($c.Status) { 'PASS' {'dot-pass'} 'FAIL' {'dot-fail'} default {'dot-other'} }
        $rows += @"
        <tr class="check-row $(($c.Status).ToLower())-row" data-status="$($c.Status)" data-search="$(New-HtmlEncoded ($c.ID + ' ' + $c.Title + ' ' + $c.Actual + ' ' + $c.Expected + ' ' + $c.Remediation + ' ' + $c.Type))">
          <td><span class="check-id">$(New-HtmlEncoded $c.ID)</span></td>
          <td>
            <div class="control-title">$(New-HtmlEncoded $c.Title)</div>
            <div class="control-meta">$(New-HtmlEncoded $c.Type)</div>
          </td>
          <td>
            <span class="status-pill $statusClass"><span class="status-dot $statusDot"></span>$(New-HtmlEncoded $c.Status)</span>
          </td>
          <td class="mono-cell">$(New-HtmlEncoded $c.Actual)</td>
          <td class="mono-cell">$(New-HtmlEncoded $c.Expected)</td>
          <td class="remediation-cell">$(if($c.Remediation){ New-HtmlEncoded $c.Remediation } else { '<span class="muted">No remediation text</span>' })</td>
        </tr>
"@
    }

    $sectionHtml += @"
    <section class="section-card" id="sec-$secId">
      <div class="section-shell">
        <button class="section-header" onclick="toggleSection(this)" type="button">
          <div class="section-left">
            <div class="section-title-row">
              <span class="section-name">$(New-HtmlEncoded $sec)</span>
              <span class="section-chip neutral">$secTotal controls</span>
              <span class="section-chip pass">$secPass pass</span>
              <span class="section-chip fail">$secFail fail</span>
              <span class="section-chip other">$secOther other</span>
            </div>
            <div class="section-progress-line"><div class="section-progress-track"><div class="section-progress-fill" style="width:${secPct}%; background:${barColor};"></div></div></div>
          </div>
          <div class="section-right"><div class="section-pct" style="color:${barColor};">${secPct}%</div><div class="section-chevron">⌄</div></div>
        </button>
        <div class="section-body">
          <div class="section-toolbar">
            <div class="section-filter-group">
              <button class="filter-btn active" onclick="filterRows(this,'ALL')" type="button">All</button>
              <button class="filter-btn" onclick="filterRows(this,'PASS')" type="button">Pass</button>
              <button class="filter-btn" onclick="filterRows(this,'FAIL')" type="button">Fail</button>
              <button class="filter-btn" onclick="filterRows(this,'OTHER')" type="button">Other</button>
            </div>
            <div class="section-mini-stats"><span>Pass: <strong>$secPass</strong></span><span>Fail: <strong>$secFail</strong></span><span>Other: <strong>$secOther</strong></span></div>
          </div>
          <div class="table-wrap">
            <table class="checks-table">
              <thead>
                <tr><th>ID</th><th>Control</th><th>Status</th><th>Actual</th><th>Expected</th><th>Remediation</th></tr>
              </thead>
              <tbody>$rows</tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
"@
}

$healthClass = if($scorePercent -ge 80){'good'}elseif($scorePercent -ge 50){'mid'}else{'bad'}
$healthLabel = if($scorePercent -ge 80){'Healthy'}elseif($scorePercent -ge 50){'Attention'}else{'Critical'}
$gaugeColor  = if($scorePercent -ge 80){'#22c55e'}elseif($scorePercent -ge 50){'#f59e0b'}else{'#ef4444'}
$categoryCount = ($sectionOrder | Measure-Object).Count

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>$benchName - $computerName</title>
<style>
:root{--bg:#07111f;--surface:#0f1c31;--surface-2:#12233d;--surface-3:#162b49;--card:rgba(16,28,49,.92);--border:rgba(148,163,184,.14);--border-strong:rgba(148,163,184,.22);--text:#e6eefb;--muted:#94a3b8;--muted-2:#64748b;--accent:#66a8ff;--accent-2:#8b5cf6;--pass:#22c55e;--fail:#ef4444;--warn:#f59e0b;--other:#38bdf8;--shadow:0 18px 50px rgba(0,0,0,.32);--body-bg:#081425}
body.light{--surface:#ffffff;--surface-2:#f8fbff;--surface-3:#eef5ff;--card:rgba(255,255,255,.97);--border:rgba(15,23,42,.10);--border-strong:rgba(15,23,42,.16);--text:#0f172a;--muted:#475569;--muted-2:#64748b;--accent:#2563eb;--accent-2:#7c3aed;--pass:#16a34a;--fail:#dc2626;--warn:#d97706;--other:#0284c7;--shadow:0 10px 30px rgba(15,23,42,.08);--body-bg:#eef3f9}
*{box-sizing:border-box} html{scroll-behavior:smooth} body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--text);background:var(--body-bg)} a{color:inherit} .container{max-width:1600px;margin:0 auto;padding:0 24px}
.topbar{position:sticky;top:0;z-index:1000;background:var(--surface);border-bottom:1px solid var(--border)} .topbar-inner{min-height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:14px}.brand-mark{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg, rgba(102,168,255,.18), rgba(139,92,246,.18));border:1px solid rgba(102,168,255,.24)} .brand-text h1{margin:0;font-size:15px;font-weight:700}.brand-text p{margin:3px 0 0;font-size:12px;color:var(--muted)} .top-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.toolbar-pill,.theme-toggle{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:999px;border:1px solid var(--border);background:var(--surface-2);color:var(--muted);font-size:12px;font-weight:600}.theme-toggle{cursor:pointer;color:var(--text)} .toolbar-search{display:flex;align-items:center;gap:10px;min-width:320px;padding:11px 14px;border-radius:999px;border:1px solid var(--border);background:var(--surface-2);color:var(--muted)} .toolbar-search input{flex:1;background:transparent;border:none;outline:none;color:var(--text);font-size:13px}.toolbar-search input::placeholder{color:var(--muted-2)}.toolbar-filter{display:inline-flex;align-items:center;gap:8px;padding:6px;border-radius:999px;border:1px solid var(--border);background:var(--surface-2)}
.top-filter-btn{appearance:none;border:none;cursor:pointer;padding:10px 16px;border-radius:999px;background:transparent;color:var(--muted);font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;transition:.15s ease}
.top-filter-btn:hover{color:var(--text);background:rgba(255,255,255,.06)}
.top-filter-btn.active{color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 8px 20px rgba(59,130,246,.18)}
body.light .top-filter-btn.active{color:#fff}

.hero{padding:34px 0 18px}.hero-card{border:1px solid var(--border);background:var(--surface);border-radius:28px;box-shadow:var(--shadow);padding:32px}.hero-grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(320px,.8fr);gap:26px;align-items:start}.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;border-radius:999px;background:var(--surface-3);border:1px solid var(--border-strong);color:var(--accent);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.hero h2{margin:16px 0 10px;font-size:clamp(28px,5vw,44px);line-height:1.05;letter-spacing:-.03em}.hero p.lead{margin:0;color:var(--muted);max-width:760px;font-size:15px}
.meta-grid{margin-top:22px;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.meta-card{background:var(--surface-2);border:1px solid var(--border);border-radius:18px;padding:14px 16px;min-height:84px}.meta-label{font-size:11px;color:var(--muted-2);text-transform:uppercase;letter-spacing:.08em;font-family:Consolas, monospace}.meta-value{margin-top:8px;font-size:14px;font-weight:600;word-break:break-word}
.hero-side{display:grid;gap:14px}.score-card{background:var(--surface-2);border:1px solid var(--border);border-radius:24px;padding:22px}.score-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}.score-head .label{font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.06em;text-transform:uppercase}.score-state{padding:6px 10px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid transparent}.score-state.good{color:#86efac;background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.22)}.score-state.mid{color:#fcd34d;background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.22)}.score-state.bad{color:#fca5a5;background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.22)}
.score-main{display:grid;grid-template-columns:130px 1fr;gap:18px;align-items:center}.radial-wrap{position:relative;width:120px;height:120px;margin:auto}.radial-ring{width:120px;height:120px;border-radius:50%;background:conic-gradient($gaugeColor 0% ${scorePercent}%, rgba(128,128,128,.15) ${scorePercent}% 100%);display:grid;place-items:center}.radial-ring::before{content:'';width:88px;height:88px;border-radius:50%;background:var(--surface);border:1px solid var(--border);display:block}.radial-value{position:absolute;inset:0;display:grid;place-items:center;text-align:center}.radial-value .big{font-size:26px;font-weight:800}.radial-value .small{margin-top:2px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.score-copy h3{margin:0 0 8px;font-size:18px;font-weight:700}.score-copy p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}
.kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.kpi{background:var(--surface-2);border:1px solid var(--border);border-radius:18px;padding:16px}.kpi .kpi-label{font-size:11px;color:var(--muted-2);text-transform:uppercase;letter-spacing:.08em;font-family:Consolas, monospace}.kpi .kpi-value{margin-top:10px;font-size:30px;line-height:1;font-weight:800}.kpi.total .kpi-value{color:var(--accent)}.kpi.pass .kpi-value{color:var(--pass)}.kpi.fail .kpi-value{color:var(--fail)}.kpi.manual .kpi-value{color:var(--other)}.kpi.sec .kpi-value{color:var(--accent-2)}
.layout{display:grid;grid-template-columns:320px minmax(0,1fr);gap:22px;padding:10px 0 34px}.side-card,.section-shell,.footer-card{background:var(--card);border:1px solid var(--border);border-radius:24px;box-shadow:var(--shadow)}.side-card{padding:18px}.side-title{font-size:12px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;margin-bottom:14px}.jump-list{display:flex;flex-direction:column;gap:8px;max-height:calc(100vh - 180px);overflow:auto}.jump-link{display:flex;align-items:center;justify-content:space-between;gap:10px;text-decoration:none;padding:12px 14px;border-radius:16px;border:1px solid transparent;background:var(--surface-2)} .jump-link:hover{border-color:var(--border)} .jump-link .name{font-size:13px;font-weight:600}.jump-link .sub{margin-top:4px;font-size:11px;color:var(--muted);font-family:Consolas, monospace}.jump-link .pct{font-size:14px;font-weight:800;font-family:Consolas, monospace}
.section-card{margin-bottom:16px}.section-header{width:100%;border:none;background:transparent;color:inherit;cursor:pointer;padding:20px 22px;display:flex;align-items:center;justify-content:space-between;gap:16px;text-align:left}.section-left{flex:1;min-width:0}.section-title-row{display:flex;flex-wrap:wrap;align-items:center;gap:10px}.section-name{font-size:18px;font-weight:700}.section-chip{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid transparent;text-transform:uppercase;letter-spacing:.06em}.section-chip.neutral{background:var(--surface-2);color:var(--muted);border-color:var(--border)}.section-chip.pass{background:rgba(34,197,94,.10);color:#86efac;border-color:rgba(34,197,94,.18)}.section-chip.fail{background:rgba(239,68,68,.10);color:#fca5a5;border-color:rgba(239,68,68,.18)}.section-chip.other{background:rgba(56,189,248,.10);color:#7dd3fc;border-color:rgba(56,189,248,.18)}.section-progress-line{margin-top:14px}.section-progress-track{width:100%;height:8px;border-radius:999px;background:rgba(127,127,127,.15);overflow:hidden}.section-progress-fill{height:100%;border-radius:999px;transition:width .35s ease}.section-right{display:flex;align-items:center;gap:14px;flex-shrink:0}.section-pct{font-size:20px;font-weight:800;font-family:Consolas, monospace}.section-chevron{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:var(--surface-2);border:1px solid var(--border);color:var(--muted);transition:transform .2s ease}.section-header.open .section-chevron{transform:rotate(180deg)}.section-body{display:none;border-top:1px solid var(--border)}.section-body.open{display:block}
.section-toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 20px;border-bottom:1px solid var(--border);background:var(--surface-2)}.section-filter-group{display:flex;gap:8px;flex-wrap:wrap}.filter-btn{appearance:none;border:none;cursor:pointer;padding:10px 14px;border-radius:12px;background:var(--surface-3);color:var(--muted);border:1px solid var(--border);font-size:12px;font-weight:700;letter-spacing:.05em;text-transform:uppercase}.filter-btn.active{background:linear-gradient(135deg, rgba(102,168,255,.18), rgba(139,92,246,.14));border-color:rgba(102,168,255,.28);color:var(--text)}.section-mini-stats{display:flex;align-items:center;gap:16px;color:var(--muted);font-size:12px}
.checks-table{width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed}.checks-table thead th{background:var(--surface-2);color:var(--muted);text-align:left;font-size:11px;font-family:Consolas, monospace;text-transform:uppercase;letter-spacing:.08em;padding:14px 18px;border-bottom:1px solid var(--border)}.checks-table td{padding:16px 18px;border-bottom:1px solid rgba(127,127,127,.10);vertical-align:top;font-size:13px}.check-row.fail-row{background:linear-gradient(90deg, rgba(239,68,68,.05), transparent 22%)}.check-row.pass-row{background:linear-gradient(90deg, rgba(34,197,94,.04), transparent 18%)}.check-id{display:inline-flex;align-items:center;padding:6px 10px;border-radius:10px;background:var(--surface-2);border:1px solid var(--border);font-family:Consolas, monospace;font-size:12px;font-weight:600}.control-title{font-size:14px;font-weight:600;line-height:1.5}.control-meta{margin-top:6px;color:var(--muted);font-size:11px;font-family:Consolas, monospace}.status-pill{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border-radius:999px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;border:1px solid transparent;white-space:nowrap}.status-pass{color:#86efac;background:rgba(34,197,94,.10);border-color:rgba(34,197,94,.2)}.status-fail{color:#fca5a5;background:rgba(239,68,68,.10);border-color:rgba(239,68,68,.2)}.status-other{color:#7dd3fc;background:rgba(56,189,248,.10);border-color:rgba(56,189,248,.2)}.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}.dot-pass{background:var(--pass)}.dot-fail{background:var(--fail)}.dot-other{background:var(--other)}.mono-cell{font-family:Consolas, monospace;font-size:12px;line-height:1.6;word-break:break-word}.remediation-cell{color:var(--warn);font-size:13px;line-height:1.6;white-space:pre-wrap}.muted{color:var(--muted)} .footer{padding:24px 0 40px}.footer-card{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 20px;color:var(--muted);font-size:12px}.scroll-top{position:fixed;right:24px;bottom:24px;width:48px;height:48px;border:none;border-radius:16px;background:linear-gradient(135deg,var(--accent),var(--accent-2));color:white;cursor:pointer;box-shadow:0 12px 28px rgba(59,130,246,.28);opacity:0;transform:translateY(12px);transition:.2s ease;z-index:1000}.scroll-top.visible{opacity:1;transform:translateY(0)}.hidden{display:none !important}
@media (max-width:1280px){.layout{grid-template-columns:1fr}.meta-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.jump-list{max-height:none}} @media (max-width:980px){.hero-grid{grid-template-columns:1fr}.score-main{grid-template-columns:1fr}.kpi-grid{grid-template-columns:repeat(2,1fr)}.meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar-inner{flex-direction:column;align-items:stretch;padding:14px 0}.top-actions{justify-content:space-between}.toolbar-search{min-width:unset;width:100%}} @media (max-width:640px){.container{padding:0 16px}.hero-card{padding:22px}.section-header{padding:18px}.section-toolbar{padding:12px 16px;flex-direction:column;align-items:flex-start}.kpi-grid,.meta-grid{grid-template-columns:1fr}.footer-card{flex-direction:column;align-items:flex-start}}
</style>
</head>
<body class="dark">
<div class="topbar"><div class="container"><div class="topbar-inner"><div class="brand"><div class="brand-mark">🛡</div><div class="brand-text"><h1>CIS Intune Windows 11 Assessment</h1><p>v4.0.0 · Level 1 · Full local parser-based benchmark audit</p></div></div><div class="top-actions"><div class="toolbar-pill">Host: <strong>$computerName</strong></div><div class="toolbar-pill">Build: <strong>$osBuild</strong></div><button id="themeToggle" class="theme-toggle" type="button">☀ Light mode</button><div class="toolbar-filter"><button class="top-filter-btn active" data-filter="ALL" type="button">All</button><button class="top-filter-btn" data-filter="PASS" type="button">Pass</button><button class="top-filter-btn" data-filter="FAIL" type="button">Fail</button><button class="top-filter-btn" data-filter="OTHER" type="button">Other</button></div><label class="toolbar-search" for="globalSearch"><span>🔎</span><input id="globalSearch" type="text" placeholder="Search control ID, title, actual, expected, remediation, type..." /></label></div></div></div></div>
<div class="container">
<section class="hero"><div class="hero-card"><div class="hero-grid"><div><div class="eyebrow">Advanced Local Machine Audit</div><h2>$benchName</h2><p class="lead">Full benchmark-style parser using the Tenable .audit file directly, with local registry, audit policy, user-rights, local account, banner, and embedded PowerShell validation.</p><div class="meta-grid"><div class="meta-card"><div class="meta-label">Hostname</div><div class="meta-value">$computerName</div></div><div class="meta-card"><div class="meta-label">Operating System</div><div class="meta-value">$osCaption</div></div><div class="meta-card"><div class="meta-label">OS Build</div><div class="meta-value">$osBuild</div></div><div class="meta-card"><div class="meta-label">Run As</div><div class="meta-value">$runAsUser</div></div><div class="meta-card"><div class="meta-label">Assessment Date</div><div class="meta-value">$reportDate</div></div></div></div><div class="hero-side"><div class="score-card"><div class="score-head"><div class="label">Overall Compliance</div><div class="score-state $healthClass">$healthLabel</div></div><div class="score-main"><div class="radial-wrap"><div class="radial-ring"></div><div class="radial-value"><div><div class="big">${scorePercent}%</div><div class="small">Score</div></div></div></div><div class="score-copy"><h3>$passCount of $totalChecks controls passed</h3><p>Failing controls are expanded automatically. Use global search and category filters to review the benchmark quickly.</p></div></div></div><div class="kpi-grid"><div class="kpi total"><div class="kpi-label">Total</div><div class="kpi-value">$totalChecks</div></div><div class="kpi pass"><div class="kpi-label">Passed</div><div class="kpi-value">$passCount</div></div><div class="kpi fail"><div class="kpi-label">Failed</div><div class="kpi-value">$failCount</div></div><div class="kpi manual"><div class="kpi-label">Other</div><div class="kpi-value">$manualCount</div></div><div class="kpi sec"><div class="kpi-label">Categories</div><div class="kpi-value">$categoryCount</div></div></div></div></div></div></section>
<section class="layout"><aside class="sidebar"><div class="side-card"><div class="side-title">Categories</div><div class="jump-list">$summaryCards</div></div></aside><main class="content">$sectionHtml</main></section>
<footer class="footer"><div class="footer-card"><div>Made with ❤️ by <strong>Florian Daminato</strong></div><div>JSON: $(New-HtmlEncoded $jsonPath)</div><div>CSV: $(New-HtmlEncoded $csvPath)</div></div></footer>
</div>
<button class="scroll-top" id="scrollTop" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="Back to top">↑</button>
<script>
function toggleSection(header){header.classList.toggle('open');header.parentElement.querySelector('.section-body').classList.toggle('open');}
function filterRows(btn, filter){const section=btn.closest('.section-body');section.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');section.querySelectorAll('.check-row').forEach(row=>{const s=(row.dataset.status||'').toUpperCase();const isOther=(s!=='PASS'&&s!=='FAIL');const show=(filter==='ALL')||(filter==='OTHER'&&isOther)||(s===filter);row.classList.toggle('hidden',!show);});}
const scrollBtn=document.getElementById('scrollTop');window.addEventListener('scroll',()=>{scrollBtn.classList.toggle('visible',window.scrollY>320);});
document.querySelectorAll('.section-card').forEach(card=>{const fails=card.querySelectorAll('.fail-row').length;if(fails>0){card.querySelector('.section-header').classList.add('open');card.querySelector('.section-body').classList.add('open');}});
const searchBox=document.getElementById('globalSearch');
const topFilterButtons=[...document.querySelectorAll('.top-filter-btn')];
let globalFilter='ALL';

function applyAllFilters(){
  const q=(searchBox.value||'').trim().toLowerCase();
  document.querySelectorAll('.section-card').forEach(section=>{
    const rows=section.querySelectorAll('.check-row');
    let visibleCount=0;
    rows.forEach(row=>{
      const s=(row.dataset.status||'').toUpperCase();
      const isOther=(s!=='PASS'&&s!=='FAIL');
      const matchesGlobal=(globalFilter==='ALL')||(globalFilter==='OTHER'&&isOther)||(s===globalFilter);
      const hay=(row.dataset.search||'').toLowerCase();
      const matchesSearch=!q||hay.includes(q);
      const show=matchesGlobal && matchesSearch;
      row.classList.toggle('hidden',!show);
      if(show) visibleCount++;
    });
    section.classList.toggle('hidden',visibleCount===0);
    if((q||globalFilter!=='ALL') && visibleCount>0){
      section.querySelector('.section-header').classList.add('open');
      section.querySelector('.section-body').classList.add('open');
    }
  });
}

searchBox.addEventListener('input', applyAllFilters);
topFilterButtons.forEach(btn=>{
  btn.addEventListener('click', ()=>{
    topFilterButtons.forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    globalFilter=btn.dataset.filter||'ALL';
    applyAllFilters();
  });
});
const body=document.body;const themeToggle=document.getElementById('themeToggle');const savedTheme=localStorage.getItem('cisTheme')||'dark';function applyTheme(theme){body.classList.remove('light','dark');body.classList.add(theme);themeToggle.textContent=theme==='dark'?'☀ Light mode':'🌙 Dark mode';localStorage.setItem('cisTheme',theme);} themeToggle.addEventListener('click',()=>applyTheme(body.classList.contains('dark')?'light':'dark'));applyTheme(savedTheme);
</script>
</body>
</html>
"@

$html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -Force

Write-Good "HTML report: $htmlPath"
Write-Good "JSON export:  $jsonPath"
Write-Good "CSV export:   $csvPath"

if (-not $DoNotOpenReport) {
    try { Start-Process $htmlPath } catch {}
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host " $benchName — Local Audit Summary" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Total checks : $totalChecks"
Write-Host " Passed       : $passCount" -ForegroundColor Green
Write-Host " Failed       : $failCount" -ForegroundColor Red
Write-Host " Other        : $manualCount"
Write-Host " Score        : ${scorePercent}%" -ForegroundColor $(if($scorePercent -ge 80){'Green'}elseif($scorePercent -ge 50){'Yellow'}else{'Red'})
Write-Host "=====================================================`n" -ForegroundColor Cyan
