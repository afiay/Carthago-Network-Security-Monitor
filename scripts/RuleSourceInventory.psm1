# SPDX-License-Identifier: MIT
# SOURCE CANDIDATE — UNVERIFIED. A conservative source index, not a C# compiler.
Set-StrictMode -Version Latest

function Get-SourceViews([string]$Source) {
    # Keep positions aligned. Strings are retained only in the data view;
    # comments and string contents can never become declarations/constructors.
    # Simple C# interpolated strings are opaque: their embedded expressions
    # are neither executable source evidence nor explicit test-data rows.
    # Quoted expressions, raw/verbatim interpolation and compiler directives
    # still require manual review rather than guessed lexical interpretation.
    if ($Source -match '"""|\$@"|@\$"|(?m)^\s*#') { return $null }
    if ($Source -match '\$"(?:\\.|[^"\\])*?\{[^}\r\n]*"') { return $null }
    $pattern = '//[^\r\n]*|/\*[\s\S]*?\*/|\$"(?:\\.|[^"\\])*"|@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*'''
    $code = [Text.StringBuilder]::new($Source)
    $data = [Text.StringBuilder]::new($Source)
    foreach ($m in [regex]::Matches($Source, $pattern)) {
        $comment = $m.Value.StartsWith('//') -or $m.Value.StartsWith('/*')
        for ($i = $m.Index; $i -lt $m.Index + $m.Length; $i++) {
            if ($Source[$i] -ne "`r" -and $Source[$i] -ne "`n") {
                $code[$i] = ' '
                if ($comment -or $m.Value.StartsWith('$"')) { $data[$i] = ' ' }
            }
        }
    }
    [pscustomobject]@{ Code = $code.ToString(); Data = $data.ToString() }
}

function Find-SourceBlockEnd([string]$Code, [int]$Open) {
    $depth = 0
    for ($i = $Open; $i -lt $Code.Length; $i++) {
        if ($Code[$i] -eq '{') { $depth++ }
        if ($Code[$i] -eq '}') {
            $depth--
            if ($depth -eq 0) { return $i }
        }
    }
    return -1
}

function Get-TestSourceDeclarations($View) {
    $code = $View.Code
    $classes = [Collections.Generic.List[object]]::new()
    $methods = [Collections.Generic.List[object]]::new()
    $namespaces = @([regex]::Matches($code, '\bnamespace\s+(?<name>[A-Za-z_][\w.]*)\s*[;{]'))
    # Multiple namespace declarations need a semantic reader, not a guessed prefix.
    if ($namespaces.Count -gt 1) { return [pscustomobject]@{ classes=@(); methods=@(); unresolved=$true } }
    $prefix = if ($namespaces.Count -eq 1) { $namespaces[0].Groups['name'].Value + '.' } else { '' }
    foreach ($m in [regex]::Matches($code, '\bclass\s+(?<name>[A-Za-z_]\w*)\s*(?::[^{};]+)?\s*\{')) {
        $open = $m.Index + $m.Length - 1
        $end = Find-SourceBlockEnd $code $open
        if ($end -lt 0) { return [pscustomobject]@{ classes=@(); methods=@(); unresolved=$true } }
        $parents = @($classes | Where-Object { $_.open -lt $m.Index -and $_.end -gt $end } | Sort-Object open -Descending)
        $identity = $prefix + $m.Groups['name'].Value
        if ($parents.Count) { $identity = $parents[0].identity + '+' + $m.Groups['name'].Value }
        $classes.Add([pscustomobject]@{ start=$m.Index; open=$open; end=$end; identity=$identity })
    }
    # Supported declaration shape only: attributed public void/Task methods.
    # Generic methods, expression bodies, inherited tests, custom attributes and
    # project/compiler eligibility remain unresolved, not inferred runnable.
    $pattern = '(?s)(?<attrs>(?:\[[^\[\]]*\]\s*)+)public\s+(?:async\s+)?(?:void|(?:System\.Threading\.Tasks\.)?Task)\s+(?<name>[A-Za-z_]\w*)\s*\([^{};]*?\)\s*\{'
    foreach ($m in [regex]::Matches($code, $pattern)) {
        $attrs = $m.Groups['attrs'].Value
        if ($attrs -notmatch '\[\s*(?:Xunit\.)?(?:Fact|Theory)(?:Attribute)?\b') { continue }
        $owners = @($classes | Where-Object { $_.open -lt $m.Index -and $_.end -gt $m.Index } | Sort-Object open -Descending)
        if (-not $owners.Count) { continue }
        $owner = $owners[0]
        # Only direct class members, never a method-looking fragment nested in
        # another method/property body. Strings/comments are already masked.
        $between = $code.Substring($owner.open + 1, $m.Index - $owner.open - 1)
        if (([regex]::Matches($between, '\{').Count - [regex]::Matches($between, '\}').Count) -ne 0) { continue }
        $open = $m.Index + $m.Length - 1
        $end = Find-SourceBlockEnd $code $open
        if ($end -lt 0 -or $end -ge $owner.end) { continue }
        $providers = @([regex]::Matches($attrs, '\[\s*(?:Xunit\.)?MemberData\s*\(\s*nameof\s*\(\s*(?<name>[A-Za-z_]\w*)\s*\)') | ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique)
        $methods.Add([pscustomobject]@{
            identity=$owner.identity + '.' + $m.Groups['name'].Value; owningClass=$owner.identity
            start=$m.Index; open=$open; end=$end; memberDataNames=$providers
            bindingStatus='SOURCE_DECLARATION_ONLY'
            isTheory=($attrs -match '\[\s*(?:Xunit\.)?Theory(?:Attribute)?\b')
        })
    }
    [pscustomobject]@{ classes=@($classes.ToArray()); methods=@($methods.ToArray()); unresolved=$false }
}

function New-SourceAssociation([string]$Path, [string]$Kind, [int]$Index, $View, $Declarations) {
    $owners = @($Declarations.classes | Where-Object { $_.start -le $Index -and $_.end -gt $Index } | Sort-Object open -Descending)
    $owner = if ($owners.Count) { $owners[0].identity } else { $null }
    $methods = @($Declarations.methods | Where-Object { $_.owningClass -ceq $owner })
    $containing = @($methods | Where-Object { $_.start -le $Index -and $_.end -gt $Index })
    [pscustomobject]@{
        path=$Path; kind=$Kind; line=1 + ([regex]::Matches($View.Code.Substring(0,$Index), "`n").Count)
        owningClass=$owner; declaredTestMethods=@($methods | ForEach-Object { $_.identity })
        containingTestMethod=$(if ($containing.Count -eq 1) { $containing[0].identity } else { $null })
        status='NEEDS_REVIEW'
    }
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
    $declarations = @{}
    $testDeclarations = [Collections.Generic.List[object]]::new()
    foreach ($path in @($views.Keys | Where-Object { $_ -like 'Carthago.Tests/*' } | Sort-Object)) {
        $declarations[$path] = Get-TestSourceDeclarations $views[$path]
        if ($declarations[$path].unresolved) {
            $diagnostics.Add([pscustomobject]@{ code='TEST_SCOPE_UNRESOLVED'; path=$path; ruleId=$null })
        }
        foreach ($method in $declarations[$path].methods) {
            $testDeclarations.Add([pscustomobject]@{
                path=$path; identity=$method.identity; owningClass=$method.owningClass
                memberDataNames=$method.memberDataNames; bindingStatus=$method.bindingStatus
            })
        }
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
                    $associations.Add((New-SourceAssociation $path $kind $m.Index $v $declarations[$path]))
                }
            }
            # A literal InlineData ID is a candidate for its declaring [Theory]
            # only. A Fact, helper, sibling or string decoy cannot borrow it.
            $inlinePattern = '\[\s*(?:Xunit\.)?InlineData(?:Attribute)?\s*\(\s*"' +
                [regex]::Escape($id) + '"\s*(?=[,)])'
            foreach ($m in [regex]::Matches($v.Data, $inlinePattern)) {
                $bound = @($declarations[$path].methods | Where-Object {
                    $_.isTheory -and $_.start -le $m.Index -and $m.Index -lt $_.open
                })
                if ($bound.Count -eq 1) {
                    $associations.Add((New-SourceAssociation $path 'inline-data-attribute-candidate' $m.Index $v $declarations[$path]))
                }
            }
            # Tuple/switch literals remain unbound MemberData candidates.
            $dataPattern = '\(\s*"' + [regex]::Escape($id) + '"\s*,|"' + [regex]::Escape($id) + '"\s*=>'
            foreach ($m in [regex]::Matches($v.Data, $dataPattern)) {
                $associations.Add((New-SourceAssociation $path 'data-row-candidate' $m.Index $v $declarations[$path]))
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
        schemaVersion=2; sourceSha=$SourceSha; generatedAtUtc=[DateTime]::UtcNow.ToString('o')
        status='SOURCE CANDIDATE — UNVERIFIED'; readyForExecutionSelection=$false
        testsExecutedByInventory=0; operationallyVerifiedCount=$null
        rules=$ordered; testDeclarations=@($testDeclarations.ToArray()); diagnostics=@($diagnostics.ToArray())
        limitations=@('Textual candidate index, not semantic C# analysis.', 'No compiler/project guards, MemberData binding, test outcome or producer provenance established.', 'Simple interpolated strings are opaque; complex interpolation and raw strings remain unsupported.', 'Content packs and descriptors require separate consumer review.', 'All associations need review; absence does not prove absence of coverage.')
    }
}
Export-ModuleMember -Function Get-RuleSourceInventory
