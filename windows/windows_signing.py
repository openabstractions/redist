"""Sign and verify producer-owned Windows files with the exact public certificate.

Authentication and release orchestration have separate existing owners. This
helper runs on fresh signing hosts, or without credentials on verification hosts.
"""
import argparse
import csv
import base64
import hashlib
import json
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import shutil
import tarfile
import tempfile
import zipfile
import urllib.request
import xml.etree.ElementTree as ET

CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
TIME_STAMPING = '1.3.6.1.5.5.7.3.8'
TIMESTAMP_URL = 'http://time.certum.pl'
SECRET_ENV = ('CERTUM_USERNAME', 'CERTUM_OTP_URI', 'CERTUM_EMAIL', 'CERTUM_TOTP_SEED')
# Microsoft-owned NuGet package; the SignTool bytes also match the installed
# SDK 10.0.26100.8249. Kept only on build/verification hosts, never in a release.
SDK_VERSION = '10.0.26100.8249'
SDK_URL = 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/' + SDK_VERSION + '/microsoft.windows.sdk.buildtools.' + SDK_VERSION + '.nupkg'
SDK_BYTES = 22566469
SDK_SHA256 = '1628c77d21ed187c4db998b37b18e267a7f092ae755589e21110c14260b14960'
SIGNTOOL_SHA256 = 'e7b517a6a2828af2d1fba3da60ae1e322a95141bfae192622725329630caa2b3'

# Fixed reviewed code. The file path travels only through the child environment;
# it is never interpolated into PowerShell source. The caller records public
# certificate identities and final artifact hashes, rather than host paths.
INSPECT = r'''
$ErrorActionPreference = 'Stop'
$oaStage = 'authenticode-status'
try {
$signature = Get-AuthenticodeSignature -LiteralPath $env:OA_SIGNATURE_FILE
$oaStage = 'cms-compile'
$cmsSource = @'
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
public static class OASignatureCms {
  [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CryptQueryObject(uint type, string file, uint content, uint format, uint flags,
    out uint encoding, out uint actual, out uint actualFormat, out IntPtr store, out IntPtr message, out IntPtr context);
  [DllImport("crypt32.dll", SetLastError=true)]
  static extern bool CryptMsgGetParam(IntPtr message, uint parameter, uint index, byte[] data, ref uint size);
  [DllImport("crypt32.dll")] static extern bool CryptMsgClose(IntPtr message);
  [DllImport("crypt32.dll")] static extern bool CertCloseStore(IntPtr store, uint flags);
  public static string[] Read(string file) {
    uint encoding, actual, format;
    IntPtr store, message, context;
    if (!CryptQueryObject(1, file, 0x400, 2, 0, out encoding, out actual, out format, out store, out message, out context))
      throw new InvalidOperationException("Native signature query failed: "+Marshal.GetLastWin32Error());
    try {
      uint size=0;
      if (!CryptMsgGetParam(message, 29, 0, null, ref size) || size==0 || size>8388608)
        throw new InvalidOperationException("Embedded signature size is invalid");
      var encoded=new byte[size];
      if (!CryptMsgGetParam(message, 29, 0, encoded, ref size)) throw new InvalidOperationException("Native signature read failed: "+Marshal.GetLastWin32Error());
      var cms=new SignedCms(); cms.Decode(encoded);
      if (cms.SignerInfos.Count!=1) throw new InvalidOperationException("Exactly one embedded signer is required");
      var signer=cms.SignerInfos[0];
      if (cms.ContentInfo.ContentType.Value!="1.3.6.1.4.1.311.2.1.4")
        throw new InvalidOperationException("Authenticode indirect file data is required");
      var content=new AsnReader(cms.ContentInfo.Content, AsnEncodingRules.BER);
      var indirect=content.ReadSequence();
      indirect.ReadEncodedValue();
      var digestInfo=indirect.ReadSequence();
      var algorithm=digestInfo.ReadSequence();
      var fileAlgorithm=algorithm.ReadObjectIdentifier();
      if (algorithm.HasData) algorithm.ReadNull();
      algorithm.ThrowIfNotEmpty();
      var fileHash=digestInfo.ReadOctetString();
      digestInfo.ThrowIfNotEmpty(); indirect.ThrowIfNotEmpty(); content.ThrowIfNotEmpty();
      if (fileAlgorithm=="2.16.840.1.101.3.4.2.1" && fileHash.Length!=32)
        throw new InvalidOperationException("Authenticode SHA256 file digest has invalid size");
      Rfc3161TimestampToken token=null;
      foreach (CryptographicAttributeObject attribute in signer.UnsignedAttributes) {
        if (attribute.Oid.Value=="1.3.6.1.4.1.311.2.4.1") throw new InvalidOperationException("Nested signatures are refused");
        if (attribute.Oid.Value!="1.3.6.1.4.1.311.3.3.1") continue;
        if (token!=null || attribute.Values.Count!=1) throw new InvalidOperationException("Exactly one timestamp is required");
        int used; var raw=attribute.Values[0].RawData;
        if (!Rfc3161TimestampToken.TryDecode(raw, out token, out used) || used!=raw.Length)
          throw new InvalidOperationException("RFC3161 token is invalid");
      }
      X509Certificate2 tsa;
      if (token==null || !token.VerifySignatureForSignerInfo(signer, out tsa))
        throw new InvalidOperationException("RFC3161 token is not bound to this signer");
      return new [] {fileAlgorithm, token.TokenInfo.HashAlgorithmId.Value,
        Convert.ToHexString(SHA256.HashData(signer.Certificate.RawData)).ToLowerInvariant(),
        Convert.ToHexString(SHA256.HashData(tsa.RawData)).ToLowerInvariant(), signer.DigestAlgorithm.Value};
    } finally { if(message!=IntPtr.Zero) CryptMsgClose(message); if(store!=IntPtr.Zero) CertCloseStore(store,0); }
  }
}
'@
Add-Type -TypeDefinition $cmsSource -ReferencedAssemblies @(
  [System.Formats.Asn1.AsnReader].Assembly.Location,
  [Security.Cryptography.Pkcs.SignedCms].Assembly.Location,
  [Security.Cryptography.X509Certificates.X509Certificate2].Assembly.Location,
  [Security.Cryptography.Oid].Assembly.Location)
function Digest($certificate) {
    if ($null -eq $certificate) { return $null }
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
}
function Usage($certificate) {
    if ($null -eq $certificate) { return @() }
    $values = @()
    foreach ($extension in $certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $extension.EnhancedKeyUsages) { $values += $oid.Value }
        }
    }
    return $values
}
function Chain($certificate) {
    if ($null -eq $certificate) { return @{valid=$false;certificates=@();status=@('MissingCertificate')} }
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $valid = $chain.Build($certificate)
        $status = @($chain.ChainStatus | Where-Object { $_.Status -ne [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError } | ForEach-Object { $_.Status.ToString() })
        return @{valid=($valid -and $status.Count -eq 0);status=$status;certificates=@($chain.ChainElements | ForEach-Object { Digest $_.Certificate })}
    } finally { $chain.Dispose() }
}
$leaf = $signature.SignerCertificate
$timestamp = $signature.TimeStamperCertificate
$oaStage = 'leaf-chain'
$chain = Chain $leaf
$oaStage = 'timestamp-chain'
$tsa = Chain $timestamp
$oaStage = 'cms-read'
$cms = if ($leaf) { [OASignatureCms]::Read($env:OA_SIGNATURE_FILE) } else { @($null,$null,$null,$null,$null) }
$oaStage = 'serialization'
@{status=$signature.Status.ToString();sha1=$(if ($leaf) {$leaf.Thumbprint.ToLowerInvariant()} else {$null})
  sha256=(Digest $leaf);subject=$(if ($leaf) {$leaf.Subject} else {$null})
  issuer=$(if ($leaf) {$leaf.Issuer} else {$null});eku=@(Usage $leaf)
  chain_valid=$chain.valid;chain_status=$chain.status;chain=$chain.certificates;timestamp_sha256=(Digest $timestamp)
  timestamp_eku=@(Usage $timestamp);timestamp_chain_valid=$tsa.valid;timestamp_chain_status=$tsa.status
  file_digest_oid=$cms[0];timestamp_digest_oid=$cms[1];cms_leaf_sha256=$cms[2];cms_timestamp_sha256=$cms[3];cms_digest_oid=$cms[4]} | ConvertTo-Json -Depth 5 -Compress
} catch {
  [Console]::Error.WriteLine("OA signature inspection failed; stage=$oaStage.")
  exit 1
}
'''


def identity(policy):
    certificate = policy.get('certificate') if isinstance(policy, dict) else None
    if (not isinstance(certificate, dict)
            or not re.fullmatch('[0-9a-fA-F]{40}', str(certificate.get('sha1')))
            or not re.fullmatch('[0-9a-fA-F]{64}', str(certificate.get('sha256')))
            or any(not isinstance(certificate.get(key), str) or not certificate[key].strip()
                   for key in ('subject', 'issuer'))):
        raise ValueError('complete public certificate identity is required before signing or verification')
    if policy.get('file_digest') != 'SHA256' or policy.get('timestamp') != {'url': TIMESTAMP_URL, 'digest': 'SHA256'}:
        raise ValueError('required SHA256 file and RFC3161 timestamp policy differs')
    return dict(certificate, sha1=certificate['sha1'].lower(), sha256=certificate['sha256'].lower())


def verify_receipt(receipt, policy, root=None, *, policy_sha256):
    """Check public proof structure; hosts independently verify the actual files."""
    expected = identity(policy)
    if (receipt.get('schema') != 1 or receipt.get('result') != 'pass'
            or receipt.get('policy_sha256') != policy_sha256
            or not isinstance(receipt.get('files'), list) or not receipt['files']):
        raise ValueError('invalid Windows signature receipt or public policy binding')
    names = set()
    for row in receipt['files']:
        if not isinstance(row, dict):
            raise ValueError('invalid Windows signature member')
        name = row.get('name')
        if (not isinstance(name, str) or PurePosixPath(name).is_absolute()
                or '..' in PurePosixPath(name).parts or '\\' in name or ':' in name
                or name != PurePosixPath(name).as_posix() or name in names or row.get('certificate') != {
                key: expected[key] for key in ('sha1', 'sha256', 'subject', 'issuer')}
                or row.get('file_digest') != 'SHA256' or row.get('timestamp_digest') != 'SHA256'
                or row.get('timestamp') != 'RFC3161'
                or not isinstance(row.get('chain'), list) or len(row['chain']) < 2
                or row['chain'][0] != expected['sha256']
                or any(not re.fullmatch('[0-9a-f]{64}', str(value)) for value in row['chain'])
                or not re.fullmatch('[0-9a-f]{64}', str(row.get('timestamp_certificate_sha256')))
                or not re.fullmatch('[0-9a-f]{64}', str(row.get('sha256')))
                or type(row.get('bytes')) is not int or row['bytes'] <= 0):
            raise ValueError('invalid expected-certificate signature member')
        names.add(row['name'])
        if root is not None:
            data = member(root, row['name']).read_bytes()
            if (hashlib.sha256(data).hexdigest(), len(data)) != (row['sha256'], row['bytes']):
                raise ValueError('signed member bytes differ from retained proof')
    return receipt


class NativeSignatureFailure(ValueError):
    """Contains only fixed public categories, never native diagnostics."""


def native_failure(operation, artifact, category, exit_code='none', detail='unknown'):
    operation = operation if operation in ('inspect-before-sign', 'inspect-signed', 'sign', 'verify', 'tool-operation') else 'unknown'
    artifact = artifact if artifact in ('pe', 'msi', 'other', 'none') else 'unknown'
    category = category if category in ('native-exit', 'launch-failed', 'timeout', 'malformed-output') else 'unknown'
    exit_code = str(exit_code) if type(exit_code) is int and exit_code in (1, 2) else ('none' if exit_code == 'none' else 'other')
    detail = detail if detail in ('authenticode-status', 'cms-compile', 'leaf-chain', 'timestamp-chain', 'cms-read', 'serialization', 'keyset-missing', 'untrusted-root', 'timestamp-trust', 'no-selected-certificate') else 'unknown'
    return NativeSignatureFailure('required Windows signature operation failed or warned; operation=' + operation
                     + '; format=' + artifact + '; category=' + category + '; exit=' + exit_code + '; detail=' + detail)


def artifact_format(path):
    suffix = Path(path).suffix
    return 'pe' if suffix in ('.exe', '.dll', '.node') else ('msi' if suffix == '.msi' else 'other')


def signtool_indicator(output):
    # Microsoft certificate/trust return values. These are observed indicators,
    # not a diagnosis of the provider's underlying failure. Conflicts refuse
    # classification; unknown native text is never returned.
    indicators = set()
    for code, label in (('80090016', 'keyset-missing'), ('800b0109', 'untrusted-root'),
                        ('80096005', 'timestamp-trust')):
        if re.search(r'(?i)(?<![a-z0-9])0x' + code + r'(?![a-z0-9])', output):
            indicators.add(label)
    if 'SignTool Error: No certificates were found that met all the given criteria.' in output.splitlines():
        indicators.add('no-selected-certificate')
    return next(iter(indicators)) if len(indicators) == 1 else 'unknown'


def selection_counts(output):
    counts = {}
    observed = []
    for field, label in (('eku', 'EKU'), ('expiry', 'expiry'), ('hash', 'Hash'), ('private_key', 'Private Key')):
        matches = list(re.finditer(r'^After ' + label + r' filter, ([0-9]{1,9}) certs were left\.$', output, re.MULTILINE))
        number = int(matches[0].group(1)) if len(matches) == 1 else None
        counts[field] = ('zero' if number == 0 else 'one' if number == 1 else 'many') if number is not None else 'unknown'
        if number is not None:
            observed.append((field, matches[0].start(), number))
    counts['first_reject'] = 'unknown'
    if (len(observed) == 4 and all(left[1] < right[1] and left[2] >= right[2]
                                   for left, right in zip(observed, observed[1:]))):
        counts['first_reject'] = next((field for field, _, number in observed if number == 0), 'none')
    return counts


SELECTION_METADATA = r'''
$ErrorActionPreference = 'Stop'
$row = @{expected_leaf='unknown';association='unknown';provider='unknown';key_spec='unknown';session='unknown'}
try {
    . $env:OA_SELECTION_AUTH -LibraryOnly -PolicyPath $env:OA_SELECTION_POLICY
    $policy = Read-CertumPolicy $env:OA_SELECTION_POLICY
    Assert-CertumRunner $policy
    if ($policy.certificate.sha1 -ine $env:OA_SELECTION_SHA1) { throw 'policy differs' }
    $sessionFile = Assert-CertumSessionPath (Join-Path $env:RUNNER_TEMP 'signing-session.json')
    $session = Get-Content -LiteralPath $sessionFile -Raw | ConvertFrom-Json -AsHashtable
    if ($session.schema -ne 1 -or $session.source_sha -cne $env:GITHUB_SHA -or
        $session.policy_sha256 -ine (Get-FileHash -LiteralPath $env:OA_SELECTION_POLICY -Algorithm SHA256).Hash -or
        $session.certificate.sha256 -ine $policy.certificate.sha256) { throw 'session binding differs' }
    $expected = Join-Path $env:ProgramFiles 'Certum\SimplySign Desktop\SimplySignDesktop.exe'
    if (($session.process_id -isnot [int] -and $session.process_id -isnot [long]) -or
        $session.process_id -le 0 -or $session.process_id -gt [int]::MaxValue -or
        -not [string]::Equals($session.executable,$expected,[StringComparison]::Ordinal) -or
        -not $session.process_started) { throw 'session ownership differs' }
    $started = ([datetime]$session.process_started).ToUniversalTime()
    $process = Get-Process -Id $session.process_id -ErrorAction SilentlyContinue
    if ($null -eq $process) { $row.session='absent' }
    elseif ($process.StartTime.ToUniversalTime().Ticks -eq $started.Ticks -and
        [string]::Equals($process.Path,$expected,[StringComparison]::Ordinal)) { $row.session='alive' }
    else { $row.session='mismatch' }
    $matches = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Thumbprint -ieq $policy.certificate.sha1})
    $row.expected_leaf = if ($matches.Count -eq 0) {'zero'} elseif ($matches.Count -eq 1) {'one'} else {'many'}
    if ($matches.Count -eq 1) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SelectionProperty {
 [StructLayout(LayoutKind.Sequential)] public struct ProviderInfo {
  public IntPtr container; public IntPtr provider; public uint type; public uint flags;
  public uint count; public IntPtr parameters; public uint spec;
 }
 [DllImport("crypt32.dll", SetLastError=true)] public static extern bool CertGetCertificateContextProperty(IntPtr cert,uint property,IntPtr data,ref uint size);
}
'@
        [uint32]$size=0
        if (-not [SelectionProperty]::CertGetCertificateContextProperty($matches[0].Handle,2,[IntPtr]::Zero,[ref]$size)) {
            if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq -2146885628) { $row.association='absent' }
        } elseif ($size -ge [Runtime.InteropServices.Marshal]::SizeOf([type][SelectionProperty+ProviderInfo]) -and $size -le 1048576) {
            $buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal([int]$size)
            try {
                if ([SelectionProperty]::CertGetCertificateContextProperty($matches[0].Handle,2,$buffer,[ref]$size)) {
                    $info=[Runtime.InteropServices.Marshal]::PtrToStructure($buffer,[type][SelectionProperty+ProviderInfo])
                    $row.association='present'
                    $row.provider=if ($info.type -eq 0) {'ksp'} elseif ($info.type -eq 1) {'csp'} else {'other'}
                    $row.key_spec=if ($info.spec -eq 1) {'exchange'} elseif ($info.spec -eq 2) {'signature'} elseif ($info.spec -eq [uint32]::MaxValue) {'ncrypt'} else {'other'}
                }
            } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
        }
    }
} catch { } # Public fixed unknowns retain query/guard uncertainty; no ErrorRecord output.
$row | ConvertTo-Json -Compress
'''


def selection_metadata(expected):
    unknown = dict(expected_leaf='unknown', association='unknown', provider='unknown', key_spec='unknown', session='unknown')
    encoded = base64.b64encode(SELECTION_METADATA.encode('utf-16-le')).decode('ascii')
    try:
        output = run(['pwsh', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], env=dict(os.environ,
                     OA_SELECTION_AUTH=str(Path(__file__).with_name('certum_simplysign.ps1').resolve()),
                     OA_SELECTION_POLICY=str(Path(__file__).with_name('certum_simplysign.json').resolve()),
                     OA_SELECTION_SHA1=expected['sha1']))
        row = json.loads(output)
        allowed = {'expected_leaf': ('zero', 'one', 'many'), 'association': ('present', 'absent'),
                   'provider': ('csp', 'ksp', 'other'), 'key_spec': ('exchange', 'signature', 'ncrypt', 'other'),
                   'session': ('alive', 'absent', 'mismatch')}
        return {key: row.get(key) if row.get(key) in values else 'unknown' for key, values in allowed.items()}
    except (ValueError, TypeError, AttributeError, KeyError):
        return unknown


def selection_observation(counts, metadata):
    allowed = {'eku': ('zero', 'one', 'many'), 'expiry': ('zero', 'one', 'many'),
               'hash': ('zero', 'one', 'many'), 'private_key': ('zero', 'one', 'many'),
               'first_reject': ('eku', 'expiry', 'hash', 'private_key', 'none'),
               'expected_leaf': ('zero', 'one', 'many'), 'association': ('present', 'absent'),
               'provider': ('csp', 'ksp', 'other'), 'key_spec': ('exchange', 'signature', 'ncrypt', 'other'),
               'session': ('alive', 'absent', 'mismatch')}
    row = dict(counts, **metadata)
    return 'Windows signature selection observation; ' + '; '.join(
        key + '=' + (row.get(key) if row.get(key) in values else 'unknown') for key, values in allowed.items()) + '.'


def run(argv, *, env=None, operation='tool-operation', artifact='none'):
    child = dict(os.environ if env is None else env)
    for name in SECRET_ENV:
        child.pop(name, None)
    try:
        result = subprocess.run([str(value) for value in argv], env=child, capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=180)
    except OSError:
        raise native_failure(operation, artifact, 'launch-failed') from None
    except subprocess.TimeoutExpired:
        raise native_failure(operation, artifact, 'timeout') from None
    # SignTool returns 2 for warnings, including a missing timestamp. Required
    # production signatures accept only a successful, warning-free result.
    if result.returncode != 0:
        detail = 'unknown'
        if operation in ('inspect-before-sign', 'inspect-signed'):
            marker = re.search(r'^OA signature inspection failed; stage=(authenticode-status|cms-compile|leaf-chain|timestamp-chain|cms-read|serialization)\.$',
                               result.stderr or '', re.MULTILINE)
            if marker:
                detail = marker.group(1)
        elif operation in ('sign', 'verify'):
            detail = signtool_indicator((result.stdout or '') + '\n' + (result.stderr or ''))
        error = native_failure(operation, artifact, 'native-exit', result.returncode, detail)
        if operation == 'sign':
            error.selection = selection_counts((result.stdout or '') + '\n' + (result.stderr or ''))
        raise error
    return result.stdout


def inspect_signature(path, *, operation='inspect-signed'):
    encoded = base64.b64encode(INSPECT.encode('utf-16-le')).decode('ascii')
    output = run(['pwsh', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                 env=dict(os.environ, OA_SIGNATURE_FILE=str(Path(path).resolve())),
                 operation=operation, artifact=artifact_format(path))
    try:
        result = json.loads(output)
        if not isinstance(result, dict):
            raise ValueError('invalid inspection object')
        return result
    except (ValueError, TypeError):
        raise native_failure(operation, artifact_format(path), 'malformed-output') from None


def verify(path, policy, signtool):
    expected = identity(policy)
    path = Path(path)
    signature = inspect_signature(path)
    if (signature.get('status') != 'Valid'
            or any(signature.get(key) != expected[key] for key in ('sha1', 'sha256', 'subject', 'issuer'))
            or CODE_SIGNING not in signature.get('eku', []) or signature.get('chain_valid') is not True
            or signature.get('chain_status') != [] or signature.get('timestamp_chain_status') != []
            or not isinstance(signature.get('chain'), list) or len(signature['chain']) < 2
            or signature['chain'][0] != expected['sha256']
            or not re.fullmatch('[0-9a-f]{64}', str(signature.get('timestamp_sha256')))
            or TIME_STAMPING not in signature.get('timestamp_eku', [])
            or signature.get('timestamp_chain_valid') is not True
            or signature.get('file_digest_oid') != '2.16.840.1.101.3.4.2.1'
            or signature.get('cms_digest_oid') != '2.16.840.1.101.3.4.2.1'
            or signature.get('timestamp_digest_oid') != '2.16.840.1.101.3.4.2.1'
            or signature.get('cms_leaf_sha256') != expected['sha256']
            or signature.get('cms_timestamp_sha256') != signature.get('timestamp_sha256')):
        raise ValueError('required Windows signature policy refused; operation=verify; format=' + artifact_format(path) + '; category=signature-criteria')
    output = run([signtool, 'verify', '/pa', '/all', '/tw', '/v', path], operation='verify', artifact=artifact_format(path))
    data = path.read_bytes()
    return {'name': path.name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
            'certificate': {key: signature[key] for key in ('sha1', 'sha256', 'subject', 'issuer')},
            'chain': signature['chain'], 'timestamp_certificate_sha256': signature['timestamp_sha256'],
            'file_digest': 'SHA256', 'timestamp_digest': 'SHA256', 'timestamp': 'RFC3161',
            'verification': 'embedded Authenticode /pa /all /tw; expected leaf/EKU; online trusted chains',
            'tool_output_sha256': hashlib.sha256(output.encode()).hexdigest()}


def sign(path, policy, signtool):
    expected = identity(policy)
    signature = inspect_signature(path, operation='inspect-before-sign')
    created = signature.get('status') == 'NotSigned'
    if created:
        try:
            run([signtool, 'sign', '/debug', '/sha1', expected['sha1'], '/u', CODE_SIGNING,
                 '/fd', 'SHA256', '/tr', TIMESTAMP_URL, '/td', 'SHA256', '/v', Path(path)], operation='sign', artifact=artifact_format(path))
        except NativeSignatureFailure as error:
            print(selection_observation(getattr(error, 'selection', {}), selection_metadata(expected)), file=sys.stderr)
            raise
    elif signature.get('status') != 'Valid':
        raise ValueError('required Windows signature policy refused; operation=sign; format=' + artifact_format(path) + '; category=existing-invalid-signature')
    return dict(verify(path, policy, signtool), new_signature=created)


def member(root, name):
    relative = PurePosixPath(name)
    if (relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name
            or relative.as_posix() != name or relative.suffix.lower() not in ('.exe', '.dll', '.node', '.msi')):
        raise ValueError('signature target must be a canonical executable member of the owned artifact')
    root = Path(root).resolve()
    target = root / relative
    current = target
    while current != root:
        if current.is_symlink() or current.is_junction():
            raise ValueError('signature target cannot use a linked artifact member')
        current = current.parent
    if not target.is_file() or not target.resolve().is_relative_to(root):
        raise ValueError('signature target is absent or outside its artifact')
    return target


def signature_targets(payload_rows, binaries_root, architecture):
    """Select existing payload PEs from the authoritative installer roster."""
    if architecture not in ('x64', 'arm64'):
        raise ValueError('unsupported Windows signing architecture')
    root = Path(binaries_root)
    targets = []
    for row in payload_rows:
        if len(row) != 7:
            raise ValueError('invalid payload signing row')
        _, path, _, _, _, sign_required, _ = row
        if sign_required != 'yes':
            continue
        name = PurePosixPath(path).name
        if architecture == 'arm64' and name == 'abstraction_ipc.dll':
            continue
        target = root / name
        if target.is_file():
            targets.append(target)
    actual = {path for path in root.iterdir() if path.suffix.lower() in ('.exe', '.dll')}
    if actual != set(targets):
        raise ValueError('Windows binaries include an executable outside payload signing authority')
    if not targets:
        raise ValueError('Windows payload signing inventory is empty')
    return sorted(targets)


def consume_artifact(artifact_id, digest, name, source, run_id, attempt, destination):
    """Admit only the immutable output ID wired from this run's producer job."""
    repo = os.environ['GITHUB_REPOSITORY']
    if (not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('[0-9a-f]{64}', digest)
            or any(type(value) is not int or value < 1 for value in (artifact_id, run_id, attempt))):
        raise ValueError('invalid Windows producer artifact identity')
    metadata = json.loads(run(['gh', 'api', f'repos/{repo}/actions/artifacts/{artifact_id}']))
    if (metadata.get('id') != artifact_id or metadata.get('name') != name
            or metadata.get('expired') is not False or metadata.get('digest') != 'sha256:' + digest
            or metadata.get('workflow_run', {}).get('id') != run_id
            or metadata.get('workflow_run', {}).get('head_sha') != source
            or not name.endswith('-' + str(attempt))):
        raise ValueError('Windows producer artifact differs from exact run/source/attempt/digest')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        archive_path = Path(temporary) / 'artifact.zip'
        with archive_path.open('wb') as target:
            result = subprocess.run(['gh', 'api', f'repos/{repo}/actions/artifacts/{artifact_id}/zip'],
                                    stdout=target, stderr=subprocess.PIPE, timeout=1200)
        with archive_path.open('rb') as source_file:
            actual_digest = hashlib.file_digest(source_file, 'sha256').hexdigest()
        if result.returncode or actual_digest != digest:
            raise ValueError('Windows producer artifact download digest differs')
        with zipfile.ZipFile(archive_path) as archive:
            seen = set()
            for entry in archive.infolist():
                path = PurePosixPath(entry.filename)
                if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                        or ':' in entry.filename or path.as_posix().rstrip('/') != entry.filename.rstrip('/')
                        or entry.filename in seen or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                    raise ValueError('unsafe Windows producer artifact member')
                seen.add(entry.filename)
                target = destination / path
                if target.exists() and not entry.is_dir():
                    raise ValueError('Windows artifact would replace an admitted member')
            archive.extractall(destination)


def consume_main(argv):
    parser = argparse.ArgumentParser(description=consume_artifact.__doc__)
    for name in ('artifact-id', 'run-id', 'attempt'):
        parser.add_argument('--' + name, required=True, type=int)
    for name in ('digest', 'name', 'source', 'out'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    consume_artifact(args.artifact_id, args.digest, args.name, args.source,
                     args.run_id, args.attempt, args.out)
    return 0


def payload_rows(path):
    with Path(path).open(encoding='utf-8') as source:
        return list(csv.reader((line for line in source if line.strip() and not line.startswith(('#', '>'))), delimiter='\t'))


def prepare_tools(root, github_env=None):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    package = root / ('Microsoft.Windows.SDK.BuildTools.' + SDK_VERSION + '.nupkg')
    if not package.exists():
        with urllib.request.urlopen(SDK_URL, timeout=120) as response, package.open('wb') as target:
            shutil.copyfileobj(response, target)
    with package.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if package.stat().st_size != SDK_BYTES or digest != SDK_SHA256:
        raise ValueError('Windows SDK signing tools package differs from its exact Microsoft pin')
    prefix = 'bin/10.0.26100.0/x64/'
    with zipfile.ZipFile(package) as archive:
        for entry in archive.infolist():
            if entry.filename.startswith(prefix) and not entry.is_dir():
                name = entry.filename[len(prefix):]
                relative = PurePosixPath(name)
                if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name or name in ('', '.', '..'):
                    raise ValueError('unexpected pinned Windows SDK signing member')
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))
    tool = root / 'signtool.exe'
    if hashlib.sha256(tool.read_bytes()).hexdigest() != SIGNTOOL_SHA256:
        raise ValueError('SignTool differs from the exact reviewed Microsoft SDK binary')
    if github_env:
        with Path(github_env).open('a', encoding='utf-8') as output:
            output.write('SIGNTOOL=' + tool.as_posix() + '\n')
    return tool


def native_source(pypi, npm):
    python = [row for row in payload_rows(pypi) if row[0] == 'abstraction-ipc']
    javascript = [row for row in payload_rows(npm) if row[0] == '@openabstractions/ipc']
    if (len(python) != 1 or len(javascript) != 1 or python[0][1:3] != javascript[0][1:3]
            or not re.fullmatch('[0-9a-f]{40}', python[0][2])):
        raise ValueError('canonical Windows DLL needs identical exact Python and npm source pins')


def bundle_owner():
    path = Path(__file__).with_name('apps') / 'build_bundle.py'
    spec = importlib.util.spec_from_file_location('oa_signed_bundle_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_chain(root, release, out, policy, policy_sha256):
    root, release, out = Path(root), Path(release), Path(out)
    verify_receipt(json.loads((root / 'signatures.json').read_bytes()), policy, root,
                   policy_sha256=policy_sha256)
    metadata = json.loads((root / 'apps/chain.json').read_bytes())
    def pin(path):
        data = path.read_bytes()
        return {'file': str(path.resolve()), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    core = root / 'core/abstraction-x64.msi'
    if core.read_bytes() != (release / core.name).read_bytes():
        raise ValueError('signed core MSI differs from independently verified release')
    apps = []
    for row in metadata['apps']:
        app = root / 'apps/apps' / row['id'] / Path(row['file']).name
        apps.append(dict(id=row['id'], title=row['title'], **pin(app)))
    out.mkdir(parents=True, exist_ok=True)
    for row in apps:
        destination = out / 'apps' / row['id']
        destination.mkdir(parents=True)
        shutil.copyfile(row['file'], destination / Path(row['file']).name)
    (out / 'chain.json').write_text(json.dumps({'version': metadata['version'], 'core': pin(core), 'apps': apps}, indent=2) + '\n')


def check_bundle(root, policy, signtool, *, signing, policy_sha256):
    root = Path(root)
    owner = bundle_owner()
    receipt_path = root / 'bundle-receipt.json'
    receipt = json.loads(receipt_path.read_bytes())
    bundle = member(root, receipt['bundle']['name'])
    if (receipt['bundle'].get('sha256') != hashlib.sha256(bundle.read_bytes()).hexdigest()
            or receipt['bundle'].get('bytes') != bundle.stat().st_size):
        raise ValueError('signed Setup bytes differ from its final receipt')
    if signing and receipt['bundle'].get('signed') is True:
        return check_bundle(root, policy, signtool, signing=False, policy_sha256=policy_sha256)
    if receipt['bundle'].get('signed') is not (False if signing else True):
        raise ValueError('Setup receipt has no explicit expected signing state')
    original_chain = receipt['chain']
    # The core is an embedded payload; application MSIs remain beside Setup.
    # Extraction parses data through the pinned WiX tool and executes no payload.
    with tempfile.TemporaryDirectory() as temporary:
        engine = Path(temporary) / 'engine.exe'
        run(['wix', 'burn', 'detach', bundle, '-engine', engine])
        engine_proof = sign(engine, policy, signtool) if signing else verify(engine, policy, signtool)
        if signing:
            attached = Path(temporary) / bundle.name
            run(['wix', 'burn', 'reattach', bundle, '-engine', engine, '-o', attached])
            shutil.copyfile(attached, bundle)
        outer_proof = sign(bundle, policy, signtool) if signing else verify(bundle, policy, signtool)
        if not signing and any(receipt.get('signatures', {}).get(role, {}).get('sha256') != proof['sha256']
                               for role, proof in (('engine', engine_proof), ('bundle', outer_proof))):
            raise ValueError('signed Setup engine or outer signature proof differs')
        extracted = Path(temporary) / 'containers'
        run(['wix', 'burn', 'extract', bundle, '-o', extracted, '-oba', Path(temporary) / 'ba'])
        manifest = owner.manifest_chain((Path(temporary) / 'ba/manifest.xml').read_text(encoding='utf-8-sig'))
        if [row['id'] for row in manifest] != [row['id'] for row in original_chain]:
            raise ValueError('signed Setup changed the package chain')
        for row, found in zip(original_chain, manifest):
            paths = list(extracted.rglob(row['name'])) if row is original_chain[0] else [member(root, row['name'])]
            if len(paths) != 1:
                raise ValueError('signed Setup lacks its exact embedded core MSI')
            data = paths[0].read_bytes()
            if (hashlib.sha256(data).hexdigest(), len(data)) != (row['sha256'], row['bytes']):
                raise ValueError('signed Setup MSI differs from its pinned chain')
            if found['bytes'] != len(data) or found['sha512'] != hashlib.sha512(data).hexdigest():
                raise ValueError('signed Setup manifest differs from exact signed MSI bytes')
            row['signature'] = verify(paths[0], policy, signtool)
    receipt['bundle'].update(sha256=outer_proof['sha256'], bytes=outer_proof['bytes'], signed=True)
    receipt['signatures'] = {'engine': engine_proof, 'bundle': outer_proof}
    receipt['policy_sha256'] = policy_sha256
    if signing:
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
        sums = [root / row['name'] for row in original_chain[1:]] + [bundle, receipt_path]
        (root / 'SHA256SUMS.setup').write_text(''.join(
            hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n' for path in sums))
    return receipt


def verify_msi_payload(path, policy, signtool, canonical_dll=None, *, signed_container=True):
    proof = verify(path, policy, signtool) if signed_container else None
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary)
        run(['wix', 'msi', 'decompile', path, '-x', destination / 'files', '-o', destination / 'package.wxs'])
        # WiX also extracts Binary-table custom actions from its own pinned
        # extensions. File-table payloads are the installer roster's authority.
        allowed = {PurePosixPath(row[1]).name for row in payload_rows(Path(__file__).with_name('payload.tsv'))
                   if row[5] == 'yes'}
        files = []
        for element in ET.parse(destination / 'package.wxs').iter():
            if element.tag.rsplit('}', 1)[-1] != 'File':
                continue
            name = element.get('Name') or Path(element.get('Source', '')).name
            if Path(name).suffix.lower() not in ('.exe', '.dll'):
                continue
            if name not in allowed:
                raise ValueError('MSI installs an executable outside payload signing authority')
            matches = list((destination / 'files').rglob(name))
            if len(matches) != 1:
                raise ValueError('MSI payload executable extraction is absent or ambiguous')
            files.append(matches[0])
        if not files:
            raise ValueError('core MSI has no signed executable payload')
        for file in files:
            verify(file, policy, signtool)
        libraries = [file for file in files if file.name == 'abstraction_ipc.dll']
        if Path(path).name == 'abstraction-x64.msi':
            if len(libraries) != 1 or canonical_dll is None or libraries[0].read_bytes() != Path(canonical_dll).read_bytes():
                raise ValueError('x64 MSI canonical signed DLL differs from language packages')
        if Path(path).name == 'abstraction-arm64.msi' and libraries:
            raise ValueError('Windows ARM64 has no qualified IPC DLL')
    return proof


def smoke_build(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / 'hello.cs'
        source.write_text('public static class Hello { public static int Main() { return 0; } }\n')
        compiler = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        run([compiler, '/nologo', '/target:exe', '/out:' + str((root / 'hello.exe').resolve()), source])
        manifest = Path(temporary) / 'hello.wxs'
        manifest.write_text('''<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Package Name="OA signing smoke" Manufacturer="OpenAbstractions" Version="0.0.1" UpgradeCode="CFC1E7EF-C2A3-4F78-A125-D88F4D27F813" Scope="perUser"><StandardDirectory Id="LocalAppDataFolder"><Directory Id="INSTALLFOLDER" Name="OA signing smoke"><Component Id="Marker" Guid="49A91DC7-5175-485C-9DD6-CBB8129EB074"><RegistryValue Root="HKCU" Key="Software\\OpenAbstractions\\SigningSmoke" Name="Fixed" Value="1" Type="integer" KeyPath="yes" /></Component></Directory></StandardDirectory><Feature Id="Complete"><ComponentRef Id="Marker" /></Feature></Package></Wix>''')
        run(['wix', 'build', '-arch', 'x64', '-o', root / 'hello.msi', manifest])
    # Build tools can emit intermediate debug databases. The public contract is
    # exactly two fixed executable artifacts before signature proof is added.
    for file in root.iterdir():
        if file.name not in ('hello.exe', 'hello.msi'):
            file.unlink()


def phase_main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare-tools', 'check-native-source', 'prepare-chain',
                        'smoke-build', 'smoke-sign', 'sign-pe', 'verify-pe', 'sign-msi',
                        'verify-msis', 'verify-language', 'sign-bundle', 'verify-bundle'))
    for name in ('root', 'policy', 'receipt', 'payload', 'pypi', 'npm', 'release', 'out', 'canonical'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--signtool')
    parser.add_argument('--github-env', type=Path)
    args = parser.parse_args(argv)
    if args.operation == 'prepare-tools':
        prepare_tools(args.root, args.github_env)
        return 0
    if args.operation == 'check-native-source':
        native_source(args.pypi, args.npm)
        return 0
    if args.operation == 'smoke-build':
        smoke_build(args.root)
        return 0
    if args.operation == 'prepare-chain':
        prepare_chain(args.root, args.release, args.out, json.loads(args.policy.read_bytes()),
                      hashlib.sha256(args.policy.read_bytes()).hexdigest())
        return 0
    policy = json.loads(args.policy.read_bytes())
    identity(policy)
    operation = verify if args.operation.startswith('verify') else sign
    root = args.root.resolve()
    if args.operation == 'verify-language':
        canonical = args.canonical.resolve()
        library = member(canonical, 'abstraction_ipc.dll').read_bytes()
        addon = member(canonical, 'oa_ipc_node.node').read_bytes()
        wheels = list((root / 'pypi').glob('abstraction_ipc-*-win_amd64.whl'))
        if len(wheels) != 1:
            raise ValueError('exact canonical Windows IPC wheel is absent')
        with zipfile.ZipFile(wheels[0]) as archive:
            if archive.read('abstraction/ipc/_native/abstraction_ipc.dll') != library:
                raise ValueError('wheel canonical signed DLL bytes differ')
        matches = []
        for package in (root / 'npm').glob('*.tgz'):
            with tarfile.open(package, 'r:gz') as archive:
                entries = {entry.name: entry for entry in archive.getmembers()}
                libraries = [name for name in entries if name.endswith('/abstraction_ipc.dll')]
                addons = [name for name in entries if name.endswith('/oa_ipc_node.node')]
                if libraries or addons:
                    if len(libraries) != 1 or len(addons) != 1:
                        raise ValueError('npm native member inventory differs')
                    if archive.extractfile(entries[libraries[0]]).read() != library or archive.extractfile(entries[addons[0]]).read() != addon:
                        raise ValueError('npm canonical signed native bytes differ')
                    matches.append(package)
        if len(matches) != 1:
            raise ValueError('exact Windows npm native package is absent or ambiguous')
        verify(canonical / 'abstraction_ipc.dll', policy, args.signtool)
        verify(canonical / 'oa_ipc_node.node', policy, args.signtool)
        return 0
    if args.operation == 'verify-msis':
        targets = [member(root, 'abstraction-x64.msi'), member(root, 'abstraction-arm64.msi')]
        proofs = [verify_msi_payload(path, policy, args.signtool, args.canonical) for path in targets]
        args.receipt.write_text(json.dumps({'schema': 1, 'result': 'pass', 'files': proofs}, indent=2) + '\n')
        return 0
    if args.operation in ('sign-bundle', 'verify-bundle'):
        check_bundle(root, policy, args.signtool, signing=args.operation == 'sign-bundle',
                     policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest())
        return 0
    if args.operation in ('sign-pe', 'verify-pe'):
        targets = []
        for architecture, folder in (('x64', 'amd64'), ('arm64', 'arm64')):
            directory = root / 'runtime/a' / folder
            if directory.exists():
                targets.extend(signature_targets(payload_rows(args.payload), directory, architecture))
        targets.extend([member(root, 'native/abstraction_ipc.dll'), member(root, 'native/oa_ipc_node.node')])
    elif args.operation == 'sign-msi':
        targets = [member(root, 'core/abstraction-x64.msi'), member(root, 'core/abstraction-arm64.msi')]
        for path in targets:
            verify_msi_payload(path, policy, args.signtool, root / 'canonical/native/abstraction_ipc.dll', signed_container=False)
        targets.extend(sorted((root / 'apps/apps').glob('*/*.msi')))
    elif args.operation == 'smoke-sign':
        targets = [member(root, 'hello.exe'), member(root, 'hello.msi')]
    else:
        raise ValueError('unknown Windows signature phase')
    # Serialize targets already selected above as relative wire member names.
    proofs = [dict(operation(path, policy, args.signtool), name=Path(os.path.relpath(path, root)).as_posix()) for path in targets]
    receipt = {'schema': 1, 'policy_sha256': hashlib.sha256(args.policy.read_bytes()).hexdigest(), 'result': 'pass', 'files': proofs}
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    if args.operation == 'smoke-sign':
        names = ['hello.exe', 'hello.msi', 'signatures.json']
        public = {'schema': 1, 'kind': 'windows-signing-probe', 'result': 'pass',
                  'source': os.environ['CANDIDATE_SHA'], 'version': os.environ['RELEASE_VERSION'],
                  'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
                  'oa_job_intent': os.environ['OA_JOB_INTENT'], 'policy_sha256': receipt['policy_sha256'],
                  'workflow_sha256': hashlib.sha256(Path('.github/workflows/candidate.yml').read_bytes()).hexdigest(),
                  'files': [{'name': name, 'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest(),
                             'bytes': (root / name).stat().st_size} for name in names]}
        (root / 'signing-probe.json').write_text(json.dumps(public, indent=2) + '\n')
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'consume':
        return consume_main(argv[1:])
    if argv and argv[0] not in ('sign', 'verify', '--help', '-h'):
        return phase_main(argv)
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        'Hosted owner phases: prepare-tools, check-native-source, sign-pe, verify-pe, '
        'sign-msi, verify-msis, verify-language, prepare-chain, sign-bundle, verify-bundle, '
        'smoke-build, smoke-sign. Use PHASE --help for its inputs. '
        'consume --help describes exact immutable producer artifact intake.'))
    parser.add_argument('operation', choices=('sign', 'verify'))
    parser.add_argument('--policy', type=Path, required=True, help='public Certum certificate policy; never credentials')
    parser.add_argument('--signtool', required=True, help='the pinned host Windows SDK SignTool executable')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--file', action='append', required=True, help='producer-owned relative artifact member')
    parser.add_argument('--receipt', type=Path, required=True)
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_bytes())
        identity(policy)
        if len(set(args.file)) != len(args.file):
            raise ValueError('duplicate signature target')
        paths = [(name, member(args.root, name)) for name in args.file]
        operation = sign if args.operation == 'sign' else verify
        results = [dict(operation(path, policy, args.signtool), name=name) for name, path in paths]
        receipt = {'schema': 1, 'policy_sha256': hashlib.sha256(args.policy.read_bytes()).hexdigest(),
                   'result': 'pass', 'files': results}
        args.receipt.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('FAIL ' + str(error), file=sys.stderr)
        return 1
    print('Verified ' + str(len(results)) + ' Windows signatures with the required public certificate policy')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print('FAIL ' + str(error), file=sys.stderr)
        raise SystemExit(1)
