<#
Make the release signing key, once, on a computer you hold. Windows;
packaging/new-signing-key.sh is the same thing for Linux and macOS.

What the key is for: the client checks an update against the signature
before it replaces itself (docs/design/updates.md), and a person checks a
download against it (README, "Verifying a release"). Both check against
`minisign.pub` in the repository, so this key is what everything trusts.

    .\packaging\new-signing-key.ps1              the workflow signs each release
    .\packaging\new-signing-key.ps1 -ByHand      you sign each release yourself

The two differ only in where the private half lives, and produce
signatures nothing can tell apart, so starting with the first and moving
to the second later costs nothing.

  default   An unencrypted key for GitHub's secret store, after which the
            workflow signs every release by itself and you do nothing
            further. No password, deliberately: a password kept in the
            same secret store as the key it protects protects nothing.

  -ByHand   A password-protected key that never leaves this computer. You
            sign each release yourself with the one command it prints.
            Stronger, since a compromise of the repository cannot sign,
            at the cost of a step per release.

Run it on your own computer: not on a server, not in CI, and not where a
transcript is kept. The private half must exist in one place only, and
nobody helping with this repository ever needs to see it -- a key that
has passed through a chat, an issue or a paste site is spent.
#>
[CmdletBinding()]
param(
    [switch]$ByHand,
    [string]$KeyDir = (Join-Path $env:USERPROFILE '.silver-signing')
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command minisign -ErrorAction SilentlyContinue)) {
    Write-Host @'
minisign is not installed. Either:

    winget install jedisct1.minisign

or, if winget does not find it, take minisign-win64.zip from
https://github.com/jedisct1/minisign/releases, unzip it, and put
minisign.exe somewhere on your PATH.

Then run this again.
'@
    exit 1
}

New-Item -ItemType Directory -Force -Path $KeyDir | Out-Null
$key = Join-Path $KeyDir 'minisign.key'
$pub = Join-Path $KeyDir 'minisign.pub'

if (Test-Path $key) {
    Write-Host "$key already exists. Move it aside first, or pass -KeyDir."
    exit 1
}

if ($ByHand) {
    Write-Host "Making a password-protected key in $KeyDir."
    Write-Host 'You will be asked for a password; you type it each time you sign.'
    Write-Host ''
    minisign -G -s $key -p $pub
} else {
    Write-Host "Making a key in $KeyDir, without a password: it is going into"
    Write-Host "GitHub's secret store, where a password would sit beside it."
    Write-Host ''
    minisign -G -W -s $key -p $pub
}
if ($LASTEXITCODE -ne 0) { throw 'minisign could not make the key' }

# Prove the halves match before telling anyone to rely on them.
$check = Join-Path ([System.IO.Path]::GetTempPath()) 'silver-key-selftest.txt'
Set-Content -Path $check -Value 'signing key self-test' -NoNewline
try {
    if ($ByHand) {
        Write-Host ''
        Write-Host 'Signing a test file, to check the key works. Your password again:'
        minisign -S -s $key -m $check | Out-Null
    } else {
        minisign -S -W -s $key -m $check | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw 'the key could not sign a test file' }
    minisign -V -p $pub -m $check | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'the public half does not verify what the private half signed' }
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $check, "$check.minisig"
}

Write-Host ''
Write-Host 'Key checked: it signs, and the public half verifies what it signed.'
Write-Host ''
Write-Host '--- 1. The public half. Send these two lines to be committed as minisign.pub:'
Write-Host ''
Get-Content $pub | ForEach-Object { Write-Host "    $_" }
Write-Host ''
Write-Host '    It is public by design: it is what verifies, never what signs.'
Write-Host ''

if ($ByHand) {
    Write-Host @"
--- 2. The private half stays at
    $key
    and goes nowhere else. Back it up as you would a password manager's
    export. Do not put it in the repository's secrets: the point of
    -ByHand is that the repository cannot sign.

    After each release, download that release's SHA256SUMS and run:

        minisign -Sm SHA256SUMS -t 'Silver Messenger v<version>'

    then attach the SHA256SUMS.minisig it writes to the release.
"@
} else {
    Write-Host @"
--- 2. The private half. Open
    $key
    copy both of its lines, and paste them into

        https://github.com/IAmForeverAloneToo/Silver-Messanger/settings/secrets/actions

        New repository secret
          Name    MINISIGN_SECRET_KEY
          Value   both lines of that file

    Paste it there and nowhere else. There is no second secret: the key
    has no password. Back the file up as you would a password manager's
    export.

    From the next release onwards the workflow signs SHA256SUMS with it.
"@
}
