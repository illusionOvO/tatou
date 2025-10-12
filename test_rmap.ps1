<# ===================== RMAP end-to-end tester (Windows PowerShell) =====================

用法示例：
  .\test_rmap.ps1 `
    -Root "E:\SOFTSEC VT 2025 Group project\tatou" `
    -Base "http://localhost:5000" `
    -Identity "Group_16" `
    -ServerPub "server\keys\server_pub.asc" `
    -DownloadPdf:$false

说明：
- Message1：{"nonceClient","identity"} → gpg 加密（ASCII）→ base64 → POST /rmap-initiate
- 解密回包，校验 nonceClient，取 nonceServer
- Message2：{"nonceServer"} → gpg 加密（ASCII）→ base64 → POST /rmap-get-link
- 打印 {"result":"<32-hex>"}；可选尝试下载 PDF（如果你的服务有该端点）

#>

param(
  [Parameter(Mandatory=$true)] [string]$Root,                  # 仓库根目录
  [Parameter(Mandatory=$true)] [string]$Base,                  # 形如 http://localhost:5000  或 http://host:port
  [Parameter(Mandatory=$true)] [string]$Identity,              # 形如 Group_16
  [Parameter(Mandatory=$true)] [string]$ServerPub,             # 相对或绝对路径，如 server\keys\server_pub.asc
  [switch]$DownloadPdf = $false                                # 如服务支持下载端点才设为 true
)

# ------------------------ helpers ------------------------
$ErrorActionPreference = "Stop"

function A([string]$msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" }
function Die([string]$msg) { Write-Host "`nFATAL: $msg" -ForegroundColor Red; exit 1 }

function Assert-File([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { Die "文件不存在：$path" }
}

function Gpg-Path() {
  $cmd = (Get-Command gpg -ErrorAction SilentlyContinue)
  if ($cmd) { return $cmd.Path }
  Die "未找到 gpg。请安装 Gpg4win 或把 gpg.exe 加入 PATH。"
}

function Encrypt-AsciiArmor([string]$inJson, [string]$outAsc, [string]$serverPubPath) {
  $gpg = Gpg-Path
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName  = $gpg
  $psi.Arguments = @(
    "--batch","--yes","--trust-model","always",
    "--encrypt","--armor",
    "--recipient-file", $serverPubPath,
    "--output", $outAsc,
    $inJson
  ) -join " "
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $p.WaitForExit()
  $err = $p.StandardError.ReadToEnd()
  if ($p.ExitCode -ne 0) { Die "gpg 加密失败：$err" }
}

function Decrypt-AsciiArmor([string]$inAsc, [string]$outJson) {
  $gpg = Gpg-Path
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName  = $gpg
  $psi.Arguments = "--batch --yes --decrypt `"$inAsc`""
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) { Die "gpg 解密失败：$stderr" }
  Set-Content -LiteralPath $outJson -Value $stdout -NoNewline -Encoding UTF8
}

function JsonPost([string]$url, [string]$jsonBody) {
  try {
    $resp = Invoke-WebRequest -Method Post -Uri $url -ContentType "application/json" -Body $jsonBody -UseBasicParsing -ErrorAction Stop
    return @{ Status = 200; Body = $resp.Content }
  } catch {
    $webResp = $_.Exception.Response
    if ($webResp -ne $null) {
      $status = [int]$webResp.StatusCode
      $reader = New-Object IO.StreamReader($webResp.GetResponseStream())
      $body   = $reader.ReadToEnd()
      return @{ Status = $status; Body = $body }
    } else {
      Die ("HTTP 请求失败且无响应对象：{0}" -f $_.Exception.Message)
    }
  }
}

# ------------------------ paths & sanity checks ------------------------
$INIT = "$Base/rmap-initiate"
$GETL = "$Base/rmap-get-link"

$Root = (Resolve-Path -LiteralPath $Root).Path
$ServerPubAbs = (Resolve-Path -LiteralPath (Join-Path $Root $ServerPub)).Path

A "Root: $Root"
A "INIT: $INIT"
A "GETL: $GETL"
A "Identity: $Identity"
A "ServerPub: $ServerPubAbs"

Assert-File $ServerPubAbs

# 输出文件
$msg1_json = Join-Path $Root "msg1.json"
$msg1_asc  = Join-Path $Root "msg1.asc"
$pay1_b64  = Join-Path $Root "payload1.b64"
$resp1_asc = Join-Path $Root "resp1.asc"
$resp1_json= Join-Path $Root "resp1.json"

$msg2_json = Join-Path $Root "msg2.json"
$msg2_asc  = Join-Path $Root "msg2.asc"
$pay2_b64  = Join-Path $Root "payload2.b64"

# ------------------------ message 1 ------------------------
A "生成 64-bit 随机 nonceClient..."
$bytes = New-Object byte[] 8
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$NONCE_C = [BitConverter]::ToUInt64($bytes, 0)
A "nonceClient = $NONCE_C"

A "写入 msg1.json..."
@{"nonceClient" = $NONCE_C; "identity" = $Identity} |
  ConvertTo-Json -Compress |
  Set-Content -LiteralPath $msg1_json -NoNewline -Encoding UTF8

A "使用 server_pub.asc 加密 msg1.json ..."
Encrypt-AsciiArmor -inJson $msg1_json -outAsc $msg1_asc -serverPubPath $ServerPubAbs
Assert-File $msg1_asc

A "生成 payload1.b64..."
[Convert]::ToBase64String([IO.File]::ReadAllBytes($msg1_asc)) |
  Set-Content -LiteralPath $pay1_b64 -NoNewline -Encoding ASCII
$payload1 = Get-Content -Raw -LiteralPath $pay1_b64

# 直接构造 {"payload":"..."} 纯字符串 JSON
$body1 = "{""payload"":""$payload1""}"

A "POST /rmap-initiate ..."
$r1 = JsonPost -url $INIT -jsonBody $body1
A ("INIT 返回：{0}" -f $r1.Status)
if ($r1.Status -ne 200) {
  A "Body:"
  $r1.Body | Out-String | Write-Host
  Die "INIT 未返回 200（上面是服务器提示），先修复后再继续。"
}

# 解析响应 JSON
try { $resp1 = $r1.Body | ConvertFrom-Json } catch { Die "INIT 响应不是 JSON：$($r1.Body)" }
if (-not $resp1.payload) { Die "INIT 响应缺少 payload 字段。" }

A "保存并解密 resp1.asc ..."
[IO.File]::WriteAllBytes($resp1_asc, [Convert]::FromBase64String($resp1.payload))
Decrypt-AsciiArmor -inAsc $resp1_asc -outJson $resp1_json

try { $json1 = Get-Content -Raw -LiteralPath $resp1_json | ConvertFrom-Json } catch { Die "resp1.json 不是 JSON。" }

if ([UInt64]$json1.nonceClient -ne [UInt64]$NONCE_C) { Die "nonceClient 不匹配（握手失败）。" }
$NONCE_S = [UInt64]$json1.nonceServer
A "nonceServer = $NONCE_S"

# ------------------------ message 2 ------------------------
A "写入 msg2.json..."
@{"nonceServer" = $NONCE_S} |
  ConvertTo-Json -Compress |
  Set-Content -LiteralPath $msg2_json -NoNewline -Encoding UTF8

A "使用 server_pub.asc 加密 msg2.json ..."
Encrypt-AsciiArmor -inJson $msg2_json -outAsc $msg2_asc -serverPubPath $ServerPubAbs
Assert-File $msg2_asc

A "生成 payload2.b64..."
[Convert]::ToBase64String([IO.File]::ReadAllBytes($msg2_asc)) |
  Set-Content -LiteralPath $pay2_b64 -NoNewline -Encoding ASCII
$payload2 = Get-Content -Raw -LiteralPath $pay2_b64
$body2 = "{""payload"":""$payload2""}"

A "POST /rmap-get-link ..."
$r2 = JsonPost -url $GETL -jsonBody $body2
A ("GET-LINK 返回：{0}" -f $r2.Status)
A "Body:"
$r2.Body | Out-String | Write-Host

if ($r2.Status -ne 200) { Die "GET-LINK 未返回 200（上面是服务器提示）。" }

try { $resp2 = $r2.Body | ConvertFrom-Json } catch { Die "GET-LINK 响应不是 JSON：$($r2.Body)" }
if (-not $resp2.result) { Die "GET-LINK 响应缺少 result。" }

$secret = $resp2.result
A "✅ 成功！result（secret）= $secret"

# ------------------------ optional: 下载 PDF ------------------------
if ($DownloadPdf) {
  # 如果你的服务存在公开下载端点，按需改这里：
  $downloadUrl = "$Base/get-version/$secret"
  $outPdf = Join-Path $Root "watermarked_$secret.pdf"
  A "尝试下载：$downloadUrl"
  try {
    curl.exe -L -o "$outPdf" "$downloadUrl" | Out-Null
    if (Test-Path $outPdf) { A "PDF 已保存：$outPdf" } else { A "下载端点不可用或未实现。" }
  } catch {
    A "下载失败（可能端点未实现）：$($_.Exception.Message)"
  }
}

A "全部完成。"
