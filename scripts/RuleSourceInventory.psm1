# SPDX-License-Identifier: MIT
# SOURCE CANDIDATE — UNVERIFIED. A conservative source index, not a C# compiler.
Set-StrictMode -Version Latest

function Get-SourceViews([string]$Source) {
    # Keep positions aligned. Strings are retained only in the data view;
    # comments and string contents can never become declarations/constructors.
    # Raw/interpolated strings and directives require manual review: do not
    # attempt to interpret conditional compilation or interpolation expressions.
    if ($Source -match '"""|\$"|\$@"|@\$"|(?m)^\s*#') { return $null }
    $pattern = '//[^\r\n]*|/\*[\s\S]*?\*/|@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*'''
    $code = [Text.StringBuilder]::new($Source)
    $data = [Text.StringBuilder]::new($Source)
    foreach ($m in [regex]::Matches($Source, $pattern)) {
        $comment = $m.Value.StartsWith('//') -or $m.Value.StartsWith('/*')
        for ($i = $m.Index; $i -lt $m.Index + $m.Length; $i++) {
            if ($Source[$i] -ne "`r" -and $Source[$i] -ne "`n") {
                $code[$i] = ' '
                if ($comment) { $data[$i] = ' ' }
            }
        }
    }
    [pscustomobject]@{ Code = $code.ToString(); Data = $data.ToString() }
}

function Get-RuleSourceInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RegistrySource,
        [Parameter(Mandatory)][hashtable]$Sources,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha
    )
    $diagnostics = [Collections.Generic.List[object]]::new()
    $registry = Get-SourceViews $RegistrySource
    if ($null -eq $registry) { throw 'Registry syntax requires manual review.' }
    # Deliberately require the established direct-array factory. No evaluation
    # of factories, dynamic registrations or content packs is attempted.
    $factory = [regex]::Match($registry.Code,
        '(?s)\bCreateDefaultRules\s*\(\s*\)\s*\{\s*return\s+new\s+IDetectionRule\s*\[\s*\]\s*\{(?<entries>.*?)\}\s*;\s*\}')
    if (-not $factory.Success) { throw 'Default registry factory shape is unresolved.' }
    $entries = $factory.Groups['entries'].Value
    $constructors = [regex]::Matches($entries, '\bnew\s+(?<class>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*,?')
    $residual = [regex]::Replace($entries, '\bnew\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*,?', '')
    if (-not [string]::IsNullOrWhiteSpace($residual)) { throw 'Unsupported default registration expression.' }
    if ($constructors.Count -eq 0) { throw 'No direct default registrations found.' }
    $views = @{}
    foreach ($path in @($Sources.Keys | Sort-Object)) {
        $view = Get-SourceViews ([string]$Sources[$path])
        if ($null -eq $view) {
            $diagnostics.Add([pscustomobject]@{ code='UNSUPPORTED_SOURCE_SYNTAX'; path=$path; ruleId=$null })
        } else { $views[$path] = $view }
    }
    $rules = [Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($ctor in $constructors) {
        $class = $ctor.Groups['class'].Value
        $match = [regex]::Match($class, '^(?<id>R[0-9]{3,})_')
        if (-not $match.Success) {
            $diagnostics.Add([pscustomobject]@{ code='UNRESOLVED_REGISTRATION'; path=$null; ruleId=$null; className=$class })
            continue
        }
        $id = $match.Groups['id'].Value
        $number = [long]0
        if (-not [long]::TryParse($id.Substring(1), [ref]$number) -or $number -lt 1 -or
            $id -cne ('R' + $number.ToString('D3', [Globalization.CultureInfo]::InvariantCulture))) {
            $diagnostics.Add([pscustomobject]@{ code='NONCANONICAL_CORE_ID'; path=$null; ruleId=$id })
            continue
        }
        if ($seen.ContainsKey($id)) {
            $diagnostics.Add([pscustomobject]@{ code='DUPLICATE_CORE_ID'; path=$null; ruleId=$id })
            continue
        }
        $seen[$id] = $true
        $definitions = @($views.Keys | Where-Object {
            $_ -like 'Carthago/Engine/Rules/*' -and
            $views[$_].Code -cmatch ('\bclass\s+' + [regex]::Escape($class) + '\b')
        } | Sort-Object)
        if ($definitions.Count -ne 1) {
            $diagnostics.Add([pscustomobject]@{ code='REGISTERED_CLASS_UNRESOLVED'; path=$definitions; ruleId=$id })
        }
        $associations = [Collections.Generic.List[object]]::new()
        foreach ($path in @($views.Keys | Where-Object { $_ -like 'Carthago.Tests/*' } | Sort-Object)) {
            $v = $views[$path]
            if ($v.Code -notmatch '\[\s*(?:Xunit\.)?(?:Fact|Theory)(?:Attribute)?\b') { continue }
            $patterns = [ordered]@{
                'direct-class-candidate' = '\bclass\s+' + [regex]::Escape($id) + '(?![0-9])\w*\b'
                'constructor-reference' = '\bnew\s+' + [regex]::Escape($class) + '\s*\('
            }
            foreach ($kind in $patterns.Keys) {
                foreach ($m in [regex]::Matches($v.Code, $patterns[$kind])) {
                    $associations.Add([pscustomobject]@{ path=$path; kind=$kind; line=1 + ([regex]::Matches($v.Code.Substring(0,$m.Index), "`n").Count); status='NEEDS_REVIEW' })
                }
            }
            # Evidence of explicit tuple/InlineData/switch syntax, not proof
            # of a MemberData binding or actual parameterized test invocation.
            $dataPattern = '(?:\(|\[\s*InlineData\s*\()\s*"' + [regex]::Escape($id) + '"\s*,|"' + [regex]::Escape($id) + '"\s*=>'
            foreach ($m in [regex]::Matches($v.Data, $dataPattern)) {
                $associations.Add([pscustomobject]@{ path=$path; kind='data-row-candidate'; line=1 + ([regex]::Matches($v.Data.Substring(0,$m.Index), "`n").Count); status='NEEDS_REVIEW' })
            }
        }
        $rules.Add([pscustomobject]@{
            ruleId=$id; numericId=$number; registeredClass=$class; ruleSourcePaths=$definitions
            associations=@($associations.ToArray()); associationStatus=$(if ($associations.Count) { 'NEEDS_REVIEW' } else { 'NO_ASSOCIATION_FOUND' })
            authoredMethodCount=$null; authoredInvocationCount=$null
            countReason='Source references do not establish runnable methods, data expansion or scenario coverage.'
            status='CANDIDATE_UNVERIFIED'
        })
    }
    $ordered = @($rules | Sort-Object numericId)
    $previous = [long]0
    foreach ($rule in $ordered) {
        if ($rule.numericId -gt $previous + 1) {
            $diagnostics.Add([pscustomobject]@{ code='CORE_ID_GAP'; firstMissing=$previous + 1; lastMissing=$rule.numericId - 1 })
        }
        $previous = $rule.numericId
    }
    [pscustomobject]@{
        schemaVersion=1; sourceSha=$SourceSha; generatedAtUtc=[DateTime]::UtcNow.ToString('o')
        status='SOURCE CANDIDATE — UNVERIFIED'; readyForExecutionSelection=$false
        testsExecutedByInventory=0; operationallyVerifiedCount=$null
        rules=$ordered; diagnostics=@($diagnostics.ToArray())
        limitations=@('Textual candidate index, not semantic C# analysis.', 'No compiler/project guards, MemberData binding, test outcome or producer provenance established.', 'Content packs and descriptors require separate consumer review.', 'All associations need review; absence does not prove absence of coverage.')
    }
}
Export-ModuleMember -Function Get-RuleSourceInventory
