"""Sign and verify producer-owned Windows files with the exact public certificate.

Authentication and release orchestration have separate existing owners. This
helper runs on fresh signing hosts, or without credentials on verification hosts.
"""
import argparse
import base64
import hashlib
import json
import importlib.util
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import sys
import shutil
import tarfile
import tempfile
import time
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

# One reviewed diagnostic input, never a caller-selected signing target.
DIAGNOSTIC_HOST = dict(name='launch-helper.exe', bytes=31233536,
    sha256='bde5f82b9e1ad0bd0b768142c9eaa49a30ac27a2c463ca7087e1f22fc79cc4d0',
    producer_source='73fce69327a4cec05f3560b3850b19ac55da375f',
    native_inputs_sha256='dee2082462f45b2cd2268131b7beddcb396dd7136eb5b8162aea8df528af976e')
DIAGNOSTIC_TAG = 'diagnostic-sign-comfy-self1829-bde5f82b9e1a'


def diagnostic_origin(source):
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('diagnostic source must be an exact commit')
    return dict(schema=1, kind='reviewed-comfy-self1829-sign-copy', source=source, **DIAGNOSTIC_HOST)


def diagnostic_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate diagnostic provenance field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def diagnostic_asset(release, asset, source):
    """Authenticate the existing same-repository draft transport before intake."""
    body = json.dumps(diagnostic_origin(source), sort_keys=True) + '\n'
    if (not isinstance(release, dict) or release.get('draft') is not True
            or release.get('published_at') is not None or release.get('immutable') is not False
            or release.get('tag_name') != DIAGNOSTIC_TAG or release.get('target_commitish') != source
            or release.get('author', {}).get('login') != 'ReinisLusis'
            or release.get('body', '').replace('\r\n', '\n') != body
            or release.get('assets') != [asset]):
        raise ValueError('diagnostic staging must be the exact owned unpublished draft')
    if (not isinstance(asset, dict) or type(asset.get('id')) is not int or asset['id'] < 1
            or asset.get('name') != DIAGNOSTIC_HOST['name'] or asset.get('state') != 'uploaded'
            or asset.get('size') != DIAGNOSTIC_HOST['bytes']
            or asset.get('digest') != 'sha256:' + DIAGNOSTIC_HOST['sha256']
            or asset.get('uploader', {}).get('login') != 'ReinisLusis'):
        raise ValueError('diagnostic asset differs from the reviewed host')
    return asset


def diagnostic_pe_payload(data, *, signed):
    """Retain every executable/resource byte except Authenticode's header fields."""
    import struct
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('diagnostic host must be an AMD64 PE executable')
    pe = struct.unpack_from('<I', data, 60)[0]
    if pe < 64 or pe + 264 > len(data) or data[pe:pe+4] != b'PE\0\0':
        raise ValueError('diagnostic PE header is invalid')
    machine, sections = struct.unpack_from('<HH', data, pe+4)
    size, flags = struct.unpack_from('<HH', data, pe+20)
    optional = pe + 24
    if (machine != 0x8664 or not 1 <= sections <= 96 or size != 240
            or not flags & 2 or flags & 0x2000
            or struct.unpack_from('<H', data, optional)[0] != 0x20b
            or struct.unpack_from('<I', data, optional+108)[0] != 16
            or optional + size + sections * 40 > len(data)):
        raise ValueError('diagnostic PE type or section roster differs')
    security = optional + 144
    offset, length = struct.unpack_from('<II', data, security)
    if signed:
        if offset < optional + size + sections*40 or offset % 8 or length < 8 or offset+length != len(data):
            raise ValueError('diagnostic signature must be the sole appended certificate table')
        cert_size, revision, kind = struct.unpack_from('<IHH', data, offset)
        if cert_size < 8 or (cert_size+7)//8*8 != length or revision != 0x200 or kind != 2:
            raise ValueError('diagnostic certificate table is invalid')
        payload = bytearray(data[:offset])
    else:
        if offset or length or len(data) % 8:
            raise ValueError('diagnostic input must be unsigned and aligned')
        payload = bytearray(data)
    for index in range(sections):
        section = optional + size + index * 40
        raw_size, raw_offset = struct.unpack_from('<II', data, section+16)
        if raw_size and (raw_offset < optional+size+sections*40 or raw_offset+raw_size > len(payload)):
            raise ValueError('diagnostic PE section escapes the payload')
    payload[optional+64:optional+68] = b'\0' * 4
    payload[security:security+8] = b'\0' * 8
    return bytes(payload)


def diagnostic_input(path):
    data = Path(path).read_bytes()
    if len(data) != DIAGNOSTIC_HOST['bytes'] or hashlib.sha256(data).hexdigest() != DIAGNOSTIC_HOST['sha256']:
        raise ValueError('diagnostic host bytes differ from the reviewed input')
    return diagnostic_pe_payload(data, signed=False)


def diagnostic_main(argv):
    parser = argparse.ArgumentParser(description='One reviewed ComfySelf1829 diagnostic signing copy')
    parser.add_argument('phase', choices=('intake', 'check', 'sign', 'verify'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--release-id', type=int)
    parser.add_argument('--asset-id', type=int)
    parser.add_argument('--intake-attempt', help='exact original intake producer attempt from its bound job output; required for check/sign/verify')
    parser.add_argument('--policy', type=Path)
    parser.add_argument('--signtool')
    args = parser.parse_args(argv)
    origin = diagnostic_origin(args.source)
    if args.phase == 'intake':
        expected = {'GITHUB_ACTIONS':'true', 'GITHUB_REPOSITORY':'openabstractions/redist',
            'GITHUB_SHA':args.source, 'GITHUB_REF':'refs/heads/release/0.8.0',
            'GITHUB_EVENT_NAME':'workflow_dispatch', 'GITHUB_ACTOR':'ReinisLusis',
            'GITHUB_TRIGGERING_ACTOR':'ReinisLusis',
            'GITHUB_WORKFLOW_REF':'openabstractions/redist/.github/workflows/candidate.yml@refs/heads/release/0.8.0'}
        if any(os.environ.get(key) != value for key,value in expected.items()):
            raise ValueError('diagnostic intake requires the exact native signing workflow')
        if not args.release_id or args.release_id < 1 or not args.asset_id or args.asset_id < 1:
            raise ValueError('diagnostic intake requires exact staging IDs')
        api = 'repos/openabstractions/redist/'
        release = diagnostic_json(run(['gh','api',api+'releases/'+str(args.release_id)]))
        if release.get('id') != args.release_id:
            raise ValueError('diagnostic staging release ID differs')
        asset = diagnostic_json(run(['gh','api',api+'releases/assets/'+str(args.asset_id)]))
        if asset.get('id') != args.asset_id:
            raise ValueError('diagnostic staging asset ID differs')
        diagnostic_asset(release, asset, args.source)
        # A draft must never have materialized its proposed tag.
        refs = diagnostic_json(run(['gh','api',api+'git/matching-refs/tags/'+DIAGNOSTIC_TAG]))
        if refs:
            raise ValueError('diagnostic staging tag must remain absent')
        args.root.mkdir(parents=True, exist_ok=False)
        target = args.root / DIAGNOSTIC_HOST['name']
        with target.open('xb') as output:
            subprocess.run(['gh','api','-H','Accept: application/octet-stream',
                api+'releases/assets/'+str(args.asset_id)], stdout=output, check=True)
        diagnostic_input(target)
        shutil.copyfile(target, args.root/'unsigned.exe')
        (args.root/'intake.json').write_text(json.dumps(dict(origin, release_id=args.release_id,
            asset_id=args.asset_id, run_id=os.environ['GITHUB_RUN_ID'],
            run_attempt=os.environ['GITHUB_RUN_ATTEMPT']), sort_keys=True)+'\n', encoding='utf-8')
    else:
        if not re.fullmatch('[1-9][0-9]*', args.intake_attempt or ''):
            raise ValueError('diagnostic check/sign/verify requires the exact intake producer attempt (--intake-attempt)')
        original = args.root/'unsigned.exe'
        payload = diagnostic_input(original)
        intake = diagnostic_json((args.root/'intake.json').read_bytes())
        if (set(intake) != set(origin) | {'release_id','asset_id','run_id','run_attempt'}
                or any(intake.get(key) != value for key,value in origin.items())
                or any(type(intake.get(key)) is not int or intake[key] < 1 for key in ('release_id','asset_id'))
                or intake.get('run_id') != os.environ.get('GITHUB_RUN_ID')
                or not re.fullmatch('[1-9][0-9]*', str(intake.get('run_id')))
                or intake.get('run_attempt') != args.intake_attempt):
            raise ValueError('diagnostic input provenance differs')
        target = args.root/DIAGNOSTIC_HOST['name']
        if args.phase == 'check':
            diagnostic_input(target)
            return 0
        if not args.policy or not args.signtool:
            raise ValueError('diagnostic signature requires the normal policy and SignTool')
        policy = json.loads(args.policy.read_bytes())
        if identity(policy)['sha1'] != 'b57eaddec40bdafb142a2cc6349600ece235c16f':
            raise ValueError('diagnostic certificate policy differs')
        if args.phase == 'sign':
            diagnostic_input(target)
            proof = sign(target, policy, args.signtool)
            receipt = dict(schema=1, result='pass', policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest(),
                files=[dict(proof, name=DIAGNOSTIC_HOST['name'])])
            (args.root/'signatures.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
        proof = verify(target, policy, args.signtool)
        if diagnostic_pe_payload(target.read_bytes(), signed=True) != payload:
            raise ValueError('diagnostic signed payload or resources changed')
        receipt = diagnostic_json((args.root/'signatures.json').read_bytes())
        verify_receipt(receipt, policy, args.root, policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest())
        if (len(receipt['files']) != 1 or receipt['files'][0]['name'] != DIAGNOSTIC_HOST['name']
                or receipt['files'][0].get('new_signature') is not True
                or any(receipt['files'][0].get(key) != proof.get(key) for key in
                       ('sha256','bytes','certificate','timestamp_certificate_sha256','file_digest','timestamp_digest','timestamp'))):
            raise ValueError('diagnostic normal signature receipt differs')
        diagnostic_input(original)
        (args.root/('signed-observation.json' if args.phase == 'sign' else 'verification.json')).write_text(
            json.dumps(dict(origin, intake=intake, signed=proof, payload_resources_unchanged=True), indent=2)+'\n', encoding='utf-8')
    return 0

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


def validate_msi_members(rows):
    """Canonical observations of all payload tables, without extraction paths."""
    if not isinstance(rows, list) or not rows or len(rows) > 100000:
        raise ValueError('missing or oversized final MSI member observations')
    keys, paths = set(), set()
    for row in rows:
        if not isinstance(row, dict) or row.get('table') not in ('File', 'Binary', 'Icon'):
            raise ValueError('invalid final MSI member table')
        if set(row) != {'table', 'id', 'bytes', 'sha256'} | ({'path'} if row['table'] == 'File' else set()):
            raise ValueError('invalid final MSI member fields')
        if (not isinstance(row['id'], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,255}', row['id'])
                or type(row['bytes']) is not int or row['bytes'] < 0
                or not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256'])
                or (row['table'], row['id'].casefold()) in keys):
            raise ValueError('invalid or duplicate final MSI member')
        keys.add((row['table'], row['id'].casefold()))
        if row['table'] == 'File':
            path = row['path']
            if (not isinstance(path, str) or not path or len(path) > 32767
                    or any(c in path for c in '\\:\0*?"<>|')
                    or any(ord(c) < 32 or ord(c) == 127 for c in path)
                    or any(not part or part in ('.', '..') or part.rstrip(' .') != part for part in path.split('/'))
                    or path.casefold() in paths):
                raise ValueError('invalid or duplicate logical MSI installed path')
            paths.add(path.casefold())
    if rows != sorted(rows, key=lambda row: (row['table'], row['id'])):
        raise ValueError('final MSI members are not in canonical table/key order')
    return rows


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
        if 'msi_members' in row:
            if not name.endswith('.msi'):
                raise ValueError('MSI observations belong only to MSI containers')
            validate_msi_members(row['msi_members'])
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
    return _verify_signature(path, expected, signtool, signature)


def _verify_signature(path, expected, signtool, signature):
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


def verify_upstream(path, pin, signtool):
    """Verify exact admitted supplier bytes, recording their observed signer.

    The source-owned pin and immutable producer intake are caller expectations;
    a signature receipt cannot select this role or grant its own authority.
    """
    path = Path(path)
    data = path.read_bytes()
    if (hashlib.sha256(data).hexdigest(), len(data)) != (pin['sha256'], pin['bytes']):
        raise ValueError('official host differs from its reviewed supplier pin')
    signature = inspect_signature(path)
    observed = {key: signature.get(key) for key in ('sha1', 'sha256', 'subject', 'issuer')}
    expected = identity({'certificate': observed, 'file_digest': 'SHA256',
                         'timestamp': {'url': TIMESTAMP_URL, 'digest': 'SHA256'}})
    proof = _verify_signature(path, expected, signtool, signature)
    if (proof['sha256'], proof['bytes']) != (pin['sha256'], pin['bytes']):
        raise ValueError('official host changed during native signature verification')
    return dict(proof, kind='upstream-signature', authority='exact supplier bytes and admitted producer input')


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


INTAKE_RECEIPT = 'artifact-intake.json'


def extract_retained_artifact(archive_path, artifact_id, digest, name, source, run_id, attempt, destination, *, receipt=None):
    """Recheck retained bytes using independently API-validated caller context.

    The caller owns source/run/attempt and actual prior API descriptor trust;
    a retained descriptor or this local receipt cannot authenticate itself.
    Explicit bound receipts permit read-only reuse of a complete extraction.
    """
    if (not isinstance(source, str) or not re.fullmatch('[0-9a-f]{40}', source)
            or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
            or any(type(value) is not int or value < 1 for value in (artifact_id, run_id, attempt))
            or not isinstance(name, str) or not name.endswith('-' + str(attempt))):
        raise ValueError('invalid Windows producer artifact identity')
    destination, archive_path = Path(destination), Path(archive_path)
    reserved = destination / INTAKE_RECEIPT
    def linked(path):
        return (path.is_symlink() or path.is_junction()
                or path.exists() and getattr(path.lstat(), 'st_file_attributes', 0) & 0x400)
    if linked(destination) or linked(archive_path) or not archive_path.is_file() or archive_path.stat().st_nlink != 1:
        raise ValueError('Windows artifact archive or destination is missing or linked')
    if receipt is not None and Path(receipt).resolve() != reserved.resolve():
        raise ValueError('Windows intake receipt must use its reserved output name')
    def checked_file(name):
        # Archive members include data and the intake JSON. The signing target
        # selector's executable suffix restriction does not apply to intake.
        path = destination / PurePosixPath(name)
        current = path
        while current != destination:
            if linked(current):
                raise ValueError('Windows artifact extracted member is linked')
            current = current.parent
        if (not path.is_file() or not path.resolve().is_relative_to(destination.resolve())
                or path.stat().st_nlink != 1):
            raise ValueError('Windows artifact extracted member is missing, linked or outside its owned extraction')
        return path
    with archive_path.open('rb') as source_file:
        if hashlib.file_digest(source_file, 'sha256').hexdigest() != digest:
            raise ValueError('Windows producer artifact download digest differs')
        source_file.seek(0)
        with zipfile.ZipFile(source_file) as archive:
            seen, payload, directories, spellings = set(), {}, set(), {}
            for entry in archive.infolist():
                path = PurePosixPath(entry.filename)
                if (not path.parts or path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                        or ':' in entry.filename or path.as_posix().rstrip('/') != entry.filename.rstrip('/')
                        or any(part.rstrip(' .') != part or PureWindowsPath(part).is_reserved()
                               or any(ord(char) < 32 or char in '<>"|?*' for char in part) for part in path.parts)
                        or entry.filename.casefold().rstrip('/') in seen
                        or (entry.external_attr >> 16) & 0o170000 == 0o120000
                        or path.parts[0].casefold() == INTAKE_RECEIPT.casefold()):
                    raise ValueError('unsafe Windows producer artifact member or reserved intake receipt collision')
                seen.add(entry.filename.casefold().rstrip('/'))
                for index in range(1, len(path.parts) + 1):
                    spelling = '/'.join(path.parts[:index])
                    if spellings.setdefault(spelling.casefold(), spelling) != spelling:
                        raise ValueError('Windows artifact member components contain a case alias')
                directories.update(parent.as_posix() for parent in path.parents if parent.parts)
                target = destination / path
                current = target
                while current != destination:
                    if linked(current):
                        raise ValueError('Windows artifact extraction cannot use a linked member')
                    current = current.parent
                if entry.is_dir():
                    directories.add(path.as_posix())
                else:
                    payload[entry.filename] = archive.read(entry)
            files = [{'name': key, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                     for key, data in sorted(payload.items())]
            proof = {'schema': 1, 'kind': 'windows-artifact-intake', 'source': source,
                     'run_id': run_id, 'run_attempt': attempt,
                     'artifact': {'id': artifact_id, 'name': name, 'sha256': digest}, 'files': files}
            resume = receipt is not None and reserved.exists()
            receipt_bytes = None
            reservation = None
            reservation_identity = None
            if resume:
                receipt_file = checked_file(INTAKE_RECEIPT)
                receipt_identity = receipt_file.stat()
                receipt_bytes = receipt_file.read_bytes()
                if json.loads(receipt_bytes) != proof:
                    raise ValueError('retained Windows intake receipt differs from the exact archive context')
            else:
                for key in payload:
                    if (destination / key).exists():
                        raise ValueError('Windows artifact would replace an admitted member')
                if receipt is not None and destination.exists():
                    for path in destination.rglob('*'):
                        if (linked(path) or not path.is_dir()
                                or path.relative_to(destination).as_posix() not in directories):
                            raise ValueError('unbound Windows extraction is partial or contains foreign members')
                destination.mkdir(parents=True, exist_ok=True)
                if receipt is not None or os.name == 'nt':
                    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, 'O_BINARY', 0)
                    if receipt is None:
                        # The OS deletes this exact reservation object on close;
                        # no path-based cleanup can remove a replacement object.
                        flags |= os.O_TEMPORARY
                    descriptor = os.open(reserved, flags, 0o600)
                    try:
                        reservation = os.fdopen(descriptor, 'w+b')
                    except BaseException:
                        os.close(descriptor)
                        raise
                    reservation_identity = os.fstat(reservation.fileno())
            try:
                if not resume:
                    for key in payload:
                        if (destination / key).exists():
                            raise ValueError('Windows artifact collides with reserved intake receipt')
                    archive.extractall(destination)
                if receipt is not None:
                    actual_files, actual_directories = set(), set()
                    for path in destination.rglob('*'):
                        if linked(path):
                            raise ValueError('retained Windows extraction contains a linked member')
                        relative = path.relative_to(destination).as_posix()
                        if path.is_file(): actual_files.add(relative)
                        elif path.is_dir(): actual_directories.add(relative)
                        else: raise ValueError('retained Windows extraction contains an unsupported member')
                    if actual_files != set(payload) | {INTAKE_RECEIPT} or actual_directories != directories:
                        raise ValueError('retained Windows extraction is not the closed archive inventory')
                identities = set()
                for key, data in payload.items():
                    target = checked_file(key)
                    stat = target.stat(); identity = (stat.st_dev, stat.st_ino)
                    if identity in identities or target.read_bytes() != data:
                        raise ValueError('Windows artifact extracted inventory differs')
                    identities.add(identity)
                source_file.seek(0)
                if hashlib.file_digest(source_file, 'sha256').hexdigest() != digest:
                    raise ValueError('Windows producer artifact changed during extraction verification')
                if resume:
                    current = checked_file(INTAKE_RECEIPT)
                    stat = current.stat()
                    if ((stat.st_dev, stat.st_ino) != (receipt_identity.st_dev, receipt_identity.st_ino)
                            or current.read_bytes() != receipt_bytes):
                        raise ValueError('retained Windows intake receipt changed during verification')
                elif reservation is not None:
                    current = checked_file(INTAKE_RECEIPT)
                    stat, held = current.stat(), os.fstat(reservation.fileno())
                    identity = (reservation_identity.st_dev, reservation_identity.st_ino)
                    if ((stat.st_dev, stat.st_ino) != identity or (held.st_dev, held.st_ino) != identity
                            or held.st_nlink != 1 or held.st_size != 0):
                        raise ValueError('fresh Windows intake reservation changed during extraction')
                    if receipt is not None:
                        encoded = (json.dumps(proof, indent=2) + '\n').encode('utf-8')
                        reservation.write(encoded); reservation.flush()
                        current = checked_file(INTAKE_RECEIPT)
                        stat = current.stat()
                        reservation.seek(0)
                        if ((stat.st_dev, stat.st_ino) != identity or reservation.read() != encoded):
                            raise ValueError('fresh Windows intake receipt changed during publication')
                elif reserved.exists() or linked(reserved):
                    raise ValueError('foreign Windows intake receipt appeared during extraction')
                return proof
            finally:
                if reservation is not None:
                    # Failed explicit receipts remain recognized partial state.
                    # Never delete a path whose object another writer replaced.
                    reservation.close()


def consume_artifact(artifact_id, digest, name, source, run_id, attempt, destination, *, receipt=None):
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
        for attempt_index in range(3):
            # Retry only the immutable read whose backing storage reported 503.
            # Opening wb discards every partial archive before the next GET.
            with archive_path.open('wb') as target:
                result = subprocess.run(['gh', 'api', f'repos/{repo}/actions/artifacts/{artifact_id}/zip'],
                                        stdout=target, stderr=subprocess.PIPE, timeout=1200)
            error = result.stderr.decode('utf-8', errors='replace') if isinstance(result.stderr, bytes) else str(result.stderr or '')
            transient = result.returncode and bool(re.search(r'HTTP 503|ServerBusy', error, re.IGNORECASE))
            if not transient or attempt_index == 2:
                break
            time.sleep(15 * (attempt_index + 1))
        if result.returncode:
            raise ValueError('Windows producer artifact download digest differs')
        return extract_retained_artifact(archive_path, artifact_id, digest, name, source,
                                         run_id, attempt, destination, receipt=receipt)


def consume_main(argv):
    parser = argparse.ArgumentParser(description=consume_artifact.__doc__)
    for name in ('artifact-id', 'run-id', 'attempt'):
        parser.add_argument('--' + name, required=True, type=int)
    for name in ('digest', 'name', 'source', 'out'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args(argv)
    consume_artifact(args.artifact_id, args.digest, args.name, args.source,
                     args.run_id, args.attempt, args.out,
                     receipt=args.receipt)
    return 0


def payload_rows(path):
    spec = importlib.util.spec_from_file_location('oa_installer_roster_owner', Path(__file__).with_name('validate.py'))
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner.rows(Path(path).resolve())


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


NATIVE_MEMBERS = {
    'ipc': ('abstraction_ipc.dll', 'oa_ipc_node.node'),
}


def npm_native_owner():
    """The same declared family and archive receiver used by npm assembly."""
    path = Path(__file__).resolve().parent.parent / 'scripts/npm_packages.py'
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('oa_native_npm_packages', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def declared_native_families(roster):
    """Select the new component only from the candidate's existing source roster."""
    family = npm_native_owner().FACADE_NATIVE
    rows = [row for row in payload_rows(roster) if row[0] == family['python']]
    if not rows:
        return []
    if (len(rows) != 1 or len(rows[0]) != 4 or rows[0][1] != family['repository']
            or not re.fullmatch('[0-9a-f]{40}', rows[0][2])
            or rows[0][3] != family['python_directory']):
        raise ValueError('candidate native family source declaration differs')
    return ['facade']


def native_family_environment(path, families):
    if path:
        with Path(path).open('a', encoding='utf-8') as output:
            output.write('OA_FACADE_NATIVE=' + ('1' if families else '0') + '\n')


def native_member_names(additional=None):
    """Explicit producer families; IPC remains the original mandatory family."""
    additional = list(additional or [])
    if len(additional) != len(set(additional)) or any(name != 'facade' for name in additional):
        raise ValueError('native producer family selection differs')
    names = list(NATIVE_MEMBERS['ipc'])
    if additional:
        family = npm_native_owner().FACADE_NATIVE
        names += [family['libraries']['win32-x64'], family['addon']]
        # The existing ARM64 Panel target consumes only the shared C ABI DLL;
        # it does not declare an ARM64 npm family or Node addon.
        names += ['arm64/' + family['libraries']['win32-x64']]
    return tuple('native/' + name for name in names)


def canonical_appmodel_member(canonical_root, msi, families):
    if not families:
        return None
    filename = npm_native_owner().FACADE_NATIVE['libraries']['win32-x64']
    if Path(msi).name == 'abstraction-x64.msi':
        return member(canonical_root, filename)
    if Path(msi).name == 'abstraction-arm64.msi':
        return member(canonical_root, 'arm64/' + filename)
    raise ValueError('AppModel canonical payload requires a selected core architecture')


def native_source(pypi, npm, additional=None, source_root=None):
    python_rows, javascript_rows = payload_rows(pypi), payload_rows(npm)
    python = [row for row in python_rows if row[0] == 'abstraction-ipc']
    javascript = [row for row in javascript_rows if row[0] == '@openabstractions/ipc']
    if (len(python) != 1 or len(javascript) != 1 or python[0][1:3] != javascript[0][1:3]
            or not re.fullmatch('[0-9a-f]{40}', python[0][2])):
        raise ValueError('canonical Windows DLL needs identical exact Python and npm source pins')
    native_member_names(additional)
    if additional:
        family = npm_native_owner().FACADE_NATIVE
        python = [row for row in python_rows if row[0] == family['python']]
        javascript = [row for row in javascript_rows if row[0] == family['javascript']]
        if (len(python) != 1 or len(javascript) != 1 or len(python[0]) != 4 or len(javascript[0]) != 4
                or python[0][1:3] != javascript[0][1:3]
                or python[0][1] != family['repository']
                or not re.fullmatch('[0-9a-f]{40}', python[0][2])
                or python[0][3] != family['python_directory'] or javascript[0][3] != family['javascript_directory']):
            raise ValueError('canonical AppModel DLL needs identical exact Python native and npm facade source pins')
        if any(len(row) != 4 or row[2] != python[0][2] for row in python_rows
               if len(row) > 1 and row[1] == family['repository']):
            raise ValueError('all candidate facade components must use one source commit')
        # The existing checkout step binds every repository HEAD to these
        # immutable rows. Admit the new component before any compiler runs.
        if source_root is None:
            raise ValueError('AppModel native source requires the checked candidate source root')
        facade = Path(source_root) / 'abstraction-facade'
        for relative in ('cpp/CMakeLists.txt', 'cpp/src/appmodel.cpp',
                         'cpp/include/abstraction/facade/appmodel.h',
                         'javascript/appmodel/addon.cpp', 'py-native/pyproject.toml'):
            if not (facade / relative).is_file():
                raise ValueError('candidate facade native source is absent: ' + relative)
        from git_env import source_git_environment
        environment = source_git_environment()
        environment.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
        head = run(['git', '-C', facade, 'rev-parse', '--verify', 'HEAD^{commit}'], env=environment,
                   operation='native-source-head', artifact='facade').strip()
        if head != python[0][2]:
            raise ValueError('candidate facade checkout differs from selected source commit')


def facade_language_members(root, canonical):
    """Receive the one shared AppModel producer through both language packages."""
    owner = npm_native_owner()
    family = owner.FACADE_NATIVE
    library_name, addon_name = family['libraries']['win32-x64'], family['addon']
    library = member(canonical, library_name).read_bytes()
    addon = member(canonical, addon_name).read_bytes()
    wheels = list((root / 'pypi').glob('abstraction_facade_native-*-win_amd64.whl'))
    if len(wheels) != 1:
        raise ValueError('exact canonical Windows AppModel wheel is absent or ambiguous')
    wheel_member = 'abstraction_facade_native/_native/' + library_name
    with zipfile.ZipFile(wheels[0]) as archive:
        if archive.namelist().count(wheel_member) != 1 or archive.read(wheel_member) != library:
            raise ValueError('AppModel wheel canonical signed DLL bytes differ')
    matches = []
    for package in (root / 'npm').glob('*.tgz'):
        with tarfile.open(package, 'r:gz') as archive:
            entries = archive.getmembers()
            libraries = [entry for entry in entries if entry.name.endswith('/' + library_name)]
            addons = [entry for entry in entries if entry.name.endswith('/' + addon_name)]
            if not libraries and not addons:
                continue
            if (len(libraries) != 1 or len(addons) != 1
                    or not libraries[0].isfile() or not addons[0].isfile()):
                raise ValueError('AppModel npm native member inventory differs')
            try:
                owner.facade_native_members(archive)
            except owner.Refused as error:
                raise ValueError(str(error)) from error
            if archive.extractfile(libraries[0]).read() != library or archive.extractfile(addons[0]).read() != addon:
                raise ValueError('AppModel npm canonical signed native bytes differ')
            matches.append(package)
    if len(matches) != 1:
        raise ValueError('exact Windows AppModel npm native package is absent or ambiguous')
    return member(canonical, library_name), member(canonical, addon_name)


def bundle_owner():
    path = Path(__file__).with_name('apps') / 'build_bundle.py'
    spec = importlib.util.spec_from_file_location('oa_signed_bundle_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def producer_hosts(chain, expected_producers, *, source, run_id, run_attempt, delivery_root=None,delivery_directories=None):
    """Join caller-owned reviewed pins to facts from actual artifact intake.

    Retained intake JSON is provenance evidence. The workflow must supply the
    expected source/run/attempt and source-owned supplier pins independently.
    """
    apps = {app['id']: app for app in chain['apps']}
    catalog_admitted={}
    if isinstance(expected_producers,dict):
        catalog=set(expected_producers)-set(apps)
        if delivery_directories is not None and (not isinstance(delivery_directories,dict) or set(delivery_directories)-catalog):
            raise ValueError('catalog receiving directories name an unselected application')
        if catalog:
            if delivery_root is None:
                raise ValueError('application omitted from installer chain without actual catalog delivery')
            pair_path=Path(__file__).resolve().parent.parent/'scripts/app_pair_receipt.py'
            spec=importlib.util.spec_from_file_location('native_catalog_delivery',pair_path)
            pair=importlib.util.module_from_spec(spec);spec.loader.exec_module(pair)
            for app_id in catalog:
                actual=pair.inspect_native_delivery(delivery_root,expected_producers[app_id],
                    source=source,run_id=run_id,run_attempt=run_attempt,
                    archive_directory=(delivery_directories or {}).get(app_id))
                if actual['app']!=app_id:raise ValueError('catalog application differs from selected delivery')
                catalog_admitted[app_id]=dict(expected_producers[app_id],delivery=actual)
            expected_producers={key:value for key,value in expected_producers.items() if key in apps}
    if not apps:
        if expected_producers:
            raise ValueError('producer host expectations name no selected host')
        return catalog_admitted
    if (not re.fullmatch('[0-9a-f]{40}', str(source))
            or any(type(value) is not int or value < 1 for value in (run_id, run_attempt))
            or not isinstance(expected_producers, dict) or set(expected_producers) != set(apps)):
        raise ValueError('official hosts require exact admitted producer expectations')
    admitted = dict(catalog_admitted)
    for app_id, app in apps.items():
        expected = expected_producers[app_id]
        modern = 'embedded_integration' in app
        fields = {'source', 'run_id', 'run_attempt', 'artifact', 'intake',
                  'embedded_integration' if modern else 'expected_payload'}
        if 'host' in app:
            fields.add('host')
        if not isinstance(expected, dict) or set(expected) != fields:
            raise ValueError('invalid expected official-host producer binding')
        proof, artifact = expected['intake'], expected['artifact']
        pin = expected.get('host')
        if (not isinstance(artifact, dict) or set(artifact) != {'id', 'name', 'sha256'}
                or type(artifact['id']) is not int or artifact['id'] < 1
                or not isinstance(artifact['name'], str) or not artifact['name'].endswith('-' + str(run_attempt))
                or not re.fullmatch('[0-9a-f]{64}', str(artifact['sha256']))):
            raise ValueError('invalid producer artifact')
        own_host=isinstance(pin,dict) and set(pin)=={'name','sha256','bytes','unsigned','signature'}
        if 'host' in app and (not isinstance(pin, dict) or set(pin) not in ({'name', 'sha256', 'bytes'}, {'name','sha256','bytes','unsigned','signature'})
                or not isinstance(pin['name'], str)
                or type(pin['bytes']) is not int or pin['bytes'] < 1
                or not re.fullmatch('[0-9a-f]{64}', str(pin['sha256']))):
            raise ValueError('invalid official-host artifact or supplier pin')
        if (not isinstance(proof, dict) or set(proof) != {'schema', 'kind', 'source', 'run_id', 'run_attempt', 'artifact', 'files'}
                or type(proof['schema']) is not int or proof['schema'] != 1 or proof['kind'] != 'windows-artifact-intake'
                or any(type(value[key]) is not int for value in (expected, proof) for key in ('run_id', 'run_attempt'))
                or any(expected[key] != value or proof[key] != value
                       for key, value in (('source', source), ('run_id', run_id), ('run_attempt', run_attempt)))
                or proof['artifact'] != artifact or not isinstance(proof['files'], list)):
            raise ValueError('official-host intake differs from expected source/run/attempt/artifact')
        names = set()
        for row in proof['files']:
            if (not isinstance(row, dict) or set(row) != {'name', 'sha256', 'bytes'}
                    or not isinstance(row['name'], str) or not row['name']
                    or PurePosixPath(row['name']).is_absolute() or '..' in PurePosixPath(row['name']).parts
                    or '\\' in row['name'] or ':' in row['name'] or row['name'] in names
                    or PurePosixPath(row['name']).as_posix() != row['name']
                    or not re.fullmatch('[0-9a-f]{64}', str(row['sha256']))
                    or type(row['bytes']) is not int or row['bytes'] < 0):
                raise ValueError('invalid closed producer extracted inventory')
            names.add(row['name'])
        if modern:
            # The selected-source receiver owns wrapper validation. This join
            # retains its exact tuple through the API-admitted byte inventory.
            bundle = bundle_owner()
            embedded = bundle.embedded_integration(expected['embedded_integration'])
            if (set(app) != {'id', 'title', 'host', 'embedded_integration'} or app_id != 'comfyui'
                    or 'preparation' not in app['host'] or 'preflight' in app['host']
                    or embedded != app['embedded_integration'] or not own_host):
                raise ValueError('embedded integration differs from the admitted custom Desktop')
            # Source policy and original integration are joined by the selected
            # producer against its complete signed Desktop tree. The raw
            # runtime manifest is also an actual API-admitted transport member.
            for role in ('backend_manifest',):
                member = embedded[role]
                if not any(all(row[key] == member[key] for key in ('bytes', 'sha256'))
                           and row['name'] == 'provenance/inputs/' + member['name']
                           for row in proof['files']):
                    raise ValueError('embedded integration member is absent from producer intake: ' + role)
        else:
            payload = validate_expected_payload(expected['expected_payload'])
            if (payload['msi'] not in proof['files']
                    or Path(payload['msi']['name']).name != Path(app['file']).name):
                raise ValueError('app MSI is not the admitted producer input')
        raw_pin={key:pin[key] for key in ('name','sha256','bytes')} if pin is not None else None
        if own_host:
            unsigned=pin['unsigned'];signature=pin['signature']
            if (not isinstance(unsigned,dict) or set(unsigned)!={'sha256','bytes'} or type(unsigned['bytes']) is not int or unsigned['bytes']<=0
                    or not re.fullmatch('[0-9a-f]{64}',str(unsigned['sha256'])) or not isinstance(signature,dict)
                    or signature.get('name')!=Path(pin['name']).name
                    or any(signature.get(key)!=pin[key] for key in ('sha256','bytes'))):
                raise ValueError('invalid own-host signing transformation')
            raw_pin=dict(name=pin['name'],**unsigned)
        if pin is not None and (raw_pin not in proof['files'] or Path(pin['name']).name != Path(app['host']['file']).name
                or (pin['sha256'], pin['bytes']) != (app['host']['sha256'], app['host']['bytes'])):
            raise ValueError('official host is not the reviewed admitted supplier member')
        if pin is not None:
            admitted[app_id] = {key: expected[key] for key in ('source', 'run_id', 'run_attempt', 'artifact', 'host')}
            if modern:
                admitted[app_id]['embedded_integration'] = embedded
    return admitted



def application_context_policy():
    """Load the existing selected-source owner from this exact candidate."""
    path = Path(__file__).resolve().parent.parent / 'scripts/train/steps/build_application_msis.py'
    spec = importlib.util.spec_from_file_location('application_context_policy', path)
    owner = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), owner.__dict__)
    return owner


def _application_file_state(path):
    """Bounded content measurement for the two app-context transport owners."""
    path = Path(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    current = path.stat()
    def state(stat):
        # Windows stat reports creation time as ctime while fstat reports a different field.
        # Compare common identity/size/mtime/link fields; both admission passes hash all bytes.
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_nlink)
    if (state(before) != state(after) or state(after) != state(current) or current.st_nlink != 1
            or path.is_symlink() or path.is_junction() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400):
        raise ValueError('application transport member changed or linked during measurement')
    return (current.st_dev, current.st_ino), digest, current.st_size


def retained_application_context(root, context_path, *, source, run_id, artifact_id, artifact_name,
                                 artifact_digest, artifact_attempt, version, required, sources):
    """Receive prior mandatory signer observations inside exact API-admitted bytes.

    The reviewed DAG supplies the enclosing descriptor independently. Source
    selection is recomputed from this candidate; JSON supplies no authority.
    Current native/container verification remains mandatory at each consumer.
    """
    root, context_path = Path(root), Path(context_path)
    if root.is_symlink() or root.is_junction() or getattr(root.lstat(), 'st_file_attributes', 0) & 0x400:
        raise ValueError('application context extraction root is linked')
    root = root.resolve()
    if (not isinstance(source, str) or not re.fullmatch('[0-9a-f]{40}', source)
            or any(type(value) is not int or value < 1 for value in (run_id, artifact_id, artifact_attempt))
            or artifact_name not in ('windows-msi-signed-' + str(artifact_attempt),
                                     'windows-app-signed-' + str(artifact_attempt),
                                     'setup-bundle-raw-' + str(artifact_attempt),
                                     'setup-bundle-' + str(artifact_attempt))
            or not isinstance(artifact_digest, str) or not re.fullmatch('[0-9a-f]{64}', artifact_digest)):
        raise ValueError('application context requires independent enclosing artifact identity')
    intake_path = msi_extracted_member(root, 'SourceDir\\' + INTAKE_RECEIPT)
    intake_bytes = intake_path.read_bytes()
    intake = json.loads(intake_bytes)
    header = dict(schema=1, kind='windows-artifact-intake', source=source, run_id=run_id,
                  run_attempt=artifact_attempt,
                  artifact=dict(id=artifact_id, name=artifact_name, sha256=artifact_digest))
    if (not isinstance(intake, dict) or set(intake) != set(header) | {'files'}
            or any(intake[key] != value for key, value in header.items())
            or type(intake['schema']) is not int or type(intake['run_id']) is not int
            or type(intake['run_attempt']) is not int or type(intake['artifact'].get('id')) is not int
            or not isinstance(intake['files'], list)):
        raise ValueError('application context enclosing intake differs from independent expectations')
    names, identities, observed = set(), set(), {}
    for row in intake['files']:
        if (not isinstance(row, dict) or set(row) != {'name', 'sha256', 'bytes'}
                or not isinstance(row['name'], str) or row['name'] in names
                or PurePosixPath(row['name']).as_posix() != row['name'] or '\\' in row['name']
                or row['name'].casefold() == INTAKE_RECEIPT.casefold()
                or type(row['bytes']) is not int or row['bytes'] < 0):
            raise ValueError('application context intake has an invalid member')
        path = msi_extracted_member(root, 'SourceDir\\' + row['name'].replace('/', '\\'))
        identity, digest, size = _application_file_state(path)
        if identity in identities or digest != row['sha256'] or size != row['bytes']:
            raise ValueError('application context member changed after API intake')
        names.add(row['name']); identities.add(identity); observed[row['name']] = (identity, digest, size)
    actual = set()
    for path in root.rglob('*'):
        if path.is_symlink() or path.is_junction() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('application context extraction contains a link')
        if path.is_file(): actual.add(path.relative_to(root).as_posix())
        elif not path.is_dir(): raise ValueError('application context extraction contains an unsupported member')
    if actual != names | {INTAKE_RECEIPT}:
        raise ValueError('application context extraction is not the closed admitted inventory')
    if context_path.resolve() != (root / 'app-chain-context.json').resolve() or 'app-chain-context.json' not in names:
        raise ValueError('application context must be an admitted artifact member')
    if observed['app-chain-context.json'][2] > 8 << 20:
        raise ValueError('application context exceeds its bounded metadata size')
    context_identity, context_digest, context_size = observed['app-chain-context.json']
    with msi_extracted_member(root, 'SourceDir\\app-chain-context.json').open('rb') as stream:
        held = os.fstat(stream.fileno())
        if (held.st_dev, held.st_ino) != context_identity or held.st_nlink != 1:
            raise ValueError('application context identity changed before consumption')
        context_bytes = stream.read(context_size + 1)
    if len(context_bytes) != context_size or hashlib.sha256(context_bytes).hexdigest() != context_digest:
        raise ValueError('consumed application context bytes differ from admitted pin')
    context = json.loads(context_bytes)
    if (not isinstance(context, dict) or set(context) != {'version', 'source', 'run_id', 'run_attempt', 'sources', 'expected_producers'}
            or context['version'] != version or context['source'] != source or context['run_id'] != run_id
            or type(context['run_id']) is not int or type(context['run_attempt']) is not int or context['run_attempt'] < 1
            or context['sources'] != sources or not isinstance(context['expected_producers'], dict)
            or set(context['expected_producers']) != set(required)):
        raise ValueError('retained application context differs from current selected source policy')
    for binding in context['expected_producers'].values():
        if (not isinstance(binding, dict) or binding.get('source') != source or binding.get('run_id') != run_id
                or binding.get('run_attempt') != context['run_attempt']):
            raise ValueError('retained application binding differs from original producer identity')
    for name, state in observed.items():
        path = msi_extracted_member(root, 'SourceDir\\' + name.replace('/', '\\'))
        if _application_file_state(path) != state:
            raise ValueError('application context member changed during admission')
    if intake_path.read_bytes() != intake_bytes:
        raise ValueError('application context intake changed during admission')
    return (dict(expected_producers=context['expected_producers'], source=source,
                 run_id=run_id, run_attempt=context['run_attempt']),
            dict(sha256=context_digest, bytes=context_size))


def copy_chain_distribution(chain_path, out, context_path=None, *, context_pin=None):
    """Copy every external app role from the existing chain, with sealed pins."""
    owner = bundle_owner(); chain = owner.read_chain(Path(chain_path)); owner.chain_context(chain)
    owner.check_pins(chain)
    out = Path(out).absolute()
    copies = []
    names = {path.name.casefold() for path in out.iterdir()} if out.exists() else set()
    for _, _, package, app in owner.chain_packages(chain):
        if app is None: continue  # Core is embedded; existing release carries its separate MSI.
        source = member(Path(package['file']).parent, Path(package['file']).name)
        name = source.name
        if name.casefold() in names: raise ValueError('flat Setup distribution has a package name collision')
        names.add(name.casefold()); copies.append((source, name, package))
    if context_path is not None:
        context_path = Path(context_path)
        if 'app-chain-context.json' in names: raise ValueError('flat Setup distribution context collides')
        if (not isinstance(context_pin, dict) or set(context_pin) != {'sha256', 'bytes'}
                or type(context_pin['bytes']) is not int or not 0 <= context_pin['bytes'] <= 8 << 20
                or not isinstance(context_pin['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', context_pin['sha256'])):
            raise ValueError('flat Setup distribution requires its admitted context pin')
        if _application_file_state(context_path)[1:] != (context_pin['sha256'], context_pin['bytes']):
            raise ValueError('flat Setup distribution context changed after admission')
        copies.append((context_path, 'app-chain-context.json', context_pin))
        context=json.loads(context_path.read_bytes())
        pair_path=Path(__file__).resolve().parent.parent/'scripts/app_pair_receipt.py'
        spec=importlib.util.spec_from_file_location('native_catalog_copy',pair_path)
        pair=importlib.util.module_from_spec(spec);spec.loader.exec_module(pair)
        for binding in context['expected_producers'].values():
            if 'delivery' not in binding:continue
            pair.inspect_native_delivery(context_path.parent,binding,source=context['source'],
                run_id=context['run_id'],run_attempt=context['run_attempt'])
            delivery=binding['delivery'];directory=delivery['directory']
            for selected in (delivery['binary'],*delivery['source']['parts']):
                name=directory+'/'+selected['name']
                if name.casefold() in names:raise ValueError('catalog delivery collides with Setup distribution')
                names.add(name.casefold())
                copies.append((context_path.parent/name,name,selected))
    out.mkdir(parents=True, exist_ok=True)
    for source, name, pin in copies:
        state = _application_file_state(source)
        if state[1:] != (pin['sha256'], pin['bytes']):
            raise ValueError('flat Setup distribution source changed')
        destination = out / name
        destination.parent.mkdir(parents=True,exist_ok=True)
        for parent in (destination.parent,*destination.parent.parents):
            if parent.is_symlink() or parent.is_junction() or getattr(parent.lstat(),'st_file_attributes',0)&0x400:
                raise ValueError('Setup distribution destination is redirected')
            if parent==out.absolute():break
        with source.open('rb') as stream, destination.open('xb') as target:
            if (os.fstat(stream.fileno()).st_dev, os.fstat(stream.fileno()).st_ino) != state[0]:
                raise ValueError('flat Setup distribution source identity changed')
            shutil.copyfileobj(stream, target, length=1 << 20)
        if _application_file_state(source) != state or _application_file_state(destination)[1:] != state[1:]:
            raise ValueError('flat Setup distribution copy changed')


def prepare_chain(root, release, out, policy, policy_sha256, *, expected_producers=None,
                  source=None, run_id=None, run_attempt=None, signtool=None):
    root, release, out = Path(root), Path(release), Path(out)
    signatures = verify_receipt(json.loads((root / 'signatures.json').read_bytes()), policy, root,
                                policy_sha256=policy_sha256)
    owner = bundle_owner()
    staged_metadata = json.loads((root / 'apps/chain.json').read_bytes())
    if not isinstance(staged_metadata, dict) or set(staged_metadata) != {'version', 'apps'}:
        raise ValueError('staged app chain requires exactly version and apps')
    def pin(path):
        data = path.read_bytes()
        return {'file': str(path.resolve()), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    core = root / 'core/abstraction-x64.msi'
    if core.read_bytes() != (release / core.name).read_bytes():
        raise ValueError('signed core MSI differs from independently verified release')
    metadata = owner.validate_chain(dict(staged_metadata, core=pin(core)), root / 'apps')
    producer_hosts(metadata, expected_producers, source=source, run_id=run_id, run_attempt=run_attempt,delivery_root=root)
    own_names = {row['name'] for row in signatures['files']}
    own_proofs = {row['name']: row for row in signatures['files']}
    copies = []
    for _, _, package, row in owner.chain_packages(metadata):
        if row is not None:
            path = member(root, 'apps/apps/' + row['id'] + '/' + Path(package['file']).name)
            if package is not row.get('host') and Path(os.path.relpath(path, root)).as_posix() not in own_names:
                raise ValueError('own app MSI, preflight or preparation lacks its OA signature receipt')
            if package is row.get('host') and (pin(path)['sha256'], pin(path)['bytes']) != (package['sha256'], package['bytes']):
                raise ValueError('official host changed after admitted producer input')
            if package is row:
                if signtool is None:
                    raise ValueError('app payload readback requires the pinned signing tool')
                verify_msi_payload(path, policy, signtool,
                                   expected_payload=expected_producers[row['id']]['expected_payload'],
                                   container_proof=own_proofs[Path(os.path.relpath(path, root)).as_posix()])
            package.update(pin(path))
            copies.append((package, out / 'apps' / row['id'] / path.name))
    # Validate flat distribution names before writing any chain output.
    owner.chain_context(metadata)
    out.mkdir(parents=True, exist_ok=True)
    for package, destination in copies:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(package['file'], destination)
        package['file'] = destination.relative_to(out).as_posix()
    shutil.copyfile(core, out / core.name)
    metadata['core']['file'] = core.name
    (out / 'chain.json').write_text(json.dumps(metadata, indent=2) + '\n')
    owner.check_pins(owner.read_chain(out / 'chain.json'))


def verify_go_content(final_path, authenticated_raw_pin):
    """Match signed bytes to an independently admitted stripped CGO0 Go EXE.

    This read-only predicate grants no source or signature authority. The caller
    must independently authenticate the original pin and run the existing full
    OA signature verifier against the same unchanged final file. Only the
    observed Go1.26.5 internal-linker x64/arm64 layout is supported.
    """
    import stat
    import struct
    pin = authenticated_raw_pin
    if (not isinstance(pin, dict) or set(pin) != {'sha256', 'bytes'}
            or not isinstance(pin['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', pin['sha256'])
            or type(pin['bytes']) is not int or pin['bytes'] < 1):
        raise ValueError('invalid authenticated Go output pin')
    path = Path(final_path).absolute()
    def physical():
        for part in (path, *path.parents):
            info = part.lstat()
            if part.is_symlink() or part.is_junction() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('linked Go content input')
        info = path.lstat()
        if path.suffix.lower() != '.exe' or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Go content input must be an ordinary single-link EXE')
        return info
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
    def metadata(info):
        # Windows lstat/fstat expose different ctime meanings in Python3.12.
        # Compare each API's change timestamp to its own initial observation.
        return identity(info) + (info.st_ctime_ns,)
    before = physical()
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if identity(opened) != identity(before):
            raise ValueError('Go content input changed before read')
        data = stream.read()
        def unpack(fmt, offset):
            if offset < 0 or offset + struct.calcsize(fmt) > len(data):
                raise ValueError('truncated Go PE header')
            return struct.unpack_from(fmt, data, offset)
        if data[:2] != b'MZ':
            raise ValueError('Go content input lacks DOS header')
        pe, = unpack('<I', 60)
        if pe < 64 or data[pe:pe + 4] != b'PE\0\0':
            raise ValueError('Go content input lacks PE header')
        machine, count = unpack('<HH', pe + 4)
        symbols, symbol_count = unpack('<II', pe + 12)
        optional_size, characteristics = unpack('<HH', pe + 20)
        optional = pe + 24
        magic, = unpack('<H', optional)
        alignment, = unpack('<I', optional + 36)
        headers, = unpack('<I', optional + 60)
        directories, = unpack('<I', optional + 108)
        if (machine not in (0x8664, 0xaa64) or magic != 0x20b or optional_size != 240
                or not characteristics & 2 or characteristics & 0x2000 or not 1 <= count <= 9
                or alignment != 512 or headers % 512 or directories != 16 or symbol_count != 0
                or optional + optional_size + count * 40 > headers or headers > pin['bytes']):
            raise ValueError('unsupported internal Go PE layout')
        sections, end = {}, headers
        for index in range(count):
            offset = optional + optional_size + index * 40
            name = data[offset:offset + 8].rstrip(b'\0')
            size, start = unpack('<II', offset + 16)
            if (name in sections or size == 0 or size % 512 or start != end
                    or start + size > pin['bytes']):
                raise ValueError('noncontiguous, overlapping or invalid Go PE sections')
            sections[name] = (start, size)
            end = start + size
        names = [b'.text', b'.rdata', b'.data']
        if machine == 0x8664:
            names += [b'.pdata', b'.xdata']
        names += [b'.idata', b'.reloc', b'.symtab']
        if list(sections) not in (names, names + [b'.rsrc']) or end != pin['bytes']:
            raise ValueError('unsupported Go sections or original overlay')
        sym_start, sym_size = sections[b'.symtab']
        if (symbols != sym_start or sym_size != 512
                or data[sym_start:sym_start + sym_size] != b'\4\0\0\0' + b'\0' * 508):
            raise ValueError('Go content input is not stripped')
        # Go debug/buildinfo's inline strings, bounded to the actual .data
        # section. These are format restrictions; caller source admission is
        # still required, and the complete original bytes are hashed below.
        start, size = sections[b'.data']
        info = data[start:start + size]
        if info[:32] != b'\xff Go buildinf:\x08\x02' + b'\0' * 16:
            raise ValueError('unsupported Go build information')
        def inline_string(offset):
            length = 0
            for index in range(10):
                if offset + index >= len(info):
                    break
                value = info[offset + index]
                length |= (value & 127) << (index * 7)
                if value < 128:
                    begin = offset + index + 1
                    if (index and value == 0) or begin + length > len(info):
                        break
                    return info[begin:begin + length], begin + length
            raise ValueError('invalid inline Go build information')
        version, next_offset = inline_string(32)
        module, _ = inline_string(next_offset)
        if version != b'go1.26.5' or len(module) < 33 or module[-17] != 10:
            raise ValueError('unsupported Go version or module information')
        settings = [line[6:] for line in module[16:-16].split(b'\n') if line.startswith(b'build\t')]
        expected = [b'-buildmode=exe', b'-compiler=gc', b'CGO_ENABLED=0', b'GOOS=windows',
                    b'GOARCH=' + (b'amd64' if machine == 0x8664 else b'arm64')]
        if any(sum(line.split(b'=', 1)[0] == value.split(b'=', 1)[0] for line in settings) != 1
               or value not in settings for value in expected):
            raise ValueError('unsupported Go producer settings')
        certificate, certificate_size = unpack('<II', optional + 144)
        if (certificate != pin['bytes'] or certificate % 8 or certificate_size < 8
                or certificate + certificate_size != len(data)):
            raise ValueError('Go certificate must be the exact final tail')
        length, revision, kind = unpack('<IHH', certificate)
        if (length < 8 or (revision, kind) != (0x200, 2) or (length + 7) & ~7 != certificate_size
                or data[certificate + length:] != b'\0' * (certificate_size - length)):
            raise ValueError('unsupported Go certificate table')
        original = bytearray(data[:pin['bytes']])
        original[optional + 64:optional + 68] = b'\0' * 4
        original[optional + 144:optional + 152] = b'\0' * 8
        if hashlib.sha256(original).hexdigest() != pin['sha256']:
            raise ValueError('signed Go content differs from authenticated original')
        stream.seek(0)
        if (stream.read() != data or metadata(os.fstat(stream.fileno())) != metadata(opened)
                or metadata(physical()) != metadata(before)):
            raise ValueError('Go content input changed during read')
    return dict(pin)


def restore_bundle_engine(engine, expected):
    """Restore WiX 5 CopyEngineWithSignatureFixup on a fresh detached copy."""
    import struct
    path = Path(engine)
    data = bytearray(path.read_bytes())
    def read(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('truncated Setup PE/Burn metadata')
        return struct.unpack_from(fmt, data, offset)
    if data[:2] != b'MZ':
        raise ValueError('Setup engine lacks supported PE header')
    pe, = read('<I', 60)
    if pe < 64 or data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Setup engine lacks supported PE signature')
    machine, count = read('<HH', pe + 4)
    optional_size, = read('<H', pe + 20)
    optional = pe + 24
    magic, = read('<H', optional)
    directory = {0x10b: 96, 0x20b: 112}.get(magic)
    if (directory is None or (machine, magic) not in ((0x14c, 0x10b), (0x8664, 0x20b), (0xaa64, 0x20b))
            or optional_size < directory + 40 or not 1 <= count <= 96):
        raise ValueError('unsupported Setup PE layout')
    directories, = read('<I', optional + directory - 4)
    if directories < 5:
        raise ValueError('Setup PE lacks security directory')
    section_table = optional + optional_size
    headers_end = section_table + count * 40
    read('<B', headers_end - 1)
    ranges, burn = [], []
    for index in range(count):
        section = section_table + index * 40
        size, offset = read('<II', section + 16)
        if size:
            if offset < headers_end or offset + size > len(data):
                raise ValueError('Setup section outside detached engine')
            if any(offset < end and start < offset + size for start, end in ranges):
                raise ValueError('overlapping Setup sections')
            ranges.append((offset, offset + size))
        if data[section:section + 8] == b'.wixburn':
            burn.append((offset, size))
    if len(burn) != 1 or burn[0][1] < 52:
        raise ValueError('Setup needs one complete .wixburn section')
    offset, size = burn[0]
    signature, version = read('<II', offset)
    stub, checksum, certificate, certificate_size, container_format, containers, ux = read('<IIIIIII', offset + 24)
    if (signature != 0x00f14300 or version != 2 or container_format != 1
            or not 1 <= containers <= (size - 48) // 4
            or stub < max(end for _, end in ranges) or stub + ux > certificate
            or certificate % 8 or certificate_size < 8 or certificate + certificate_size != len(data)
            or any(end > certificate for _, end in ranges)):
        raise ValueError('invalid Setup Burn engine/certificate bounds')
    length, revision, kind = read('<IHH', certificate)
    if length < 8 or length > certificate_size or (revision, kind) != (0x200, 2):
        raise ValueError('invalid Setup engine certificate table')
    struct.pack_into('<I', data, optional + 64, checksum)
    struct.pack_into('<II', data, optional + directory + 32, certificate, certificate_size)
    data[offset + 28:offset + 40] = b'\0' * 12
    if (expected.get('bytes') != len(data)
            or expected.get('sha256') != hashlib.sha256(data).hexdigest()):
        raise ValueError('restored Setup engine differs from its signed receipt')
    path.write_bytes(data)


def verify_bundle_actions(receipt,chain,ba,policy,signtool):
    """Read the signed native BA payload, separate from application package roles."""
    owner=bundle_owner();expected=receipt.get('bootstrapper_native')
    if not chain['apps']:
        if expected is not None:raise ValueError('core-only bundle has an unexpected BA native role')
        return None
    if (not isinstance(expected,dict) or set(expected)!={'name','sha256','bytes','inputs','receipt_sha256'}
            or expected['name']!=owner.ACTIONS_NAME
            or expected['inputs']!=owner.bundle_actions_inputs([app['id'] for app in chain['apps']])['inputs']
            or not re.fullmatch('[0-9a-f]{64}',str(expected['receipt_sha256']))):
        raise ValueError('bundle BA native source/map differs from admitted builder receipt')
    files=list(Path(ba).rglob(owner.ACTIONS_NAME))
    if len(files)!=1:raise ValueError('bundle lacks its exact embedded BA native payload')
    target=member(ba,files[0].relative_to(ba).as_posix())
    if setup_file_pin(target)!={key:expected[key] for key in ('name','sha256','bytes')}:
        raise ValueError('embedded BA native payload differs from admitted receipt')
    proof=verify(target,policy,signtool)
    if any(proof[key]!=expected[key] for key in ('name','sha256','bytes')):
        raise ValueError('embedded BA native payload changed during signature verification')
    return proof


def check_bundle(root, policy, signtool, *, signing, policy_sha256, expected_producers=None,
                 source=None, run_id=None, run_attempt=None, installed_readback=False):
    if installed_readback and signing:
        raise ValueError('installed readback requires independent signed bundle verification')
    root = Path(root)
    owner = bundle_owner()
    receipt_path = root / 'bundle-receipt.json'
    receipt = json.loads(receipt_path.read_bytes())
    bundle = member(root, receipt['bundle']['name'])
    if (receipt['bundle'].get('sha256') != hashlib.sha256(bundle.read_bytes()).hexdigest()
            or receipt['bundle'].get('bytes') != bundle.stat().st_size):
        raise ValueError('signed Setup bytes differ from its final receipt')
    if signing and receipt['bundle'].get('signed') is True:
        return check_bundle(root, policy, signtool, signing=False, policy_sha256=policy_sha256,
                            expected_producers=expected_producers, source=source, run_id=run_id, run_attempt=run_attempt)
    if receipt['bundle'].get('signed') is not (False if signing else True):
        raise ValueError('Setup receipt has no explicit expected signing state')
    original_chain = receipt['chain']
    names = set()
    for row in original_chain:
        name = row.get('name')
        if (not isinstance(name, str) or not name or name != PurePosixPath(name).name
                or '\\' in name or ':' in name or name in ('.', '..') or name in names):
            raise ValueError('Setup receipt package names must be unique flat members')
        names.add(name)
    if 'chain_context' in receipt:
        chain = owner.read_chain_context(receipt['chain_context'], root)
    elif len(original_chain) == 1 and original_chain[0]['id'] == owner.CORE_ID:
        # Historical core-only receipts predate context. They retain the full
        # core manifest and native signature checks; application roles need context.
        row = original_chain[0]
        chain = {'core': {'file': row['name'], 'sha256': row['sha256'], 'bytes': row['bytes']}, 'apps': []}
    else:
        raise ValueError('application Setup requires its bound chain context')
    expected_chain = list(owner.chain_packages(chain))
    if (len(original_chain) != len(expected_chain)
            or any((row['id'], row['name'], row['sha256'], row['bytes']) !=
                   (pid, Path(package['file']).name, package['sha256'], package['bytes'])
                   for row, (pid, _, package, _) in zip(original_chain, expected_chain))):
        raise ValueError('Setup receipt differs from its bound package chain')
    hosts = producer_hosts(chain, expected_producers, source=source, run_id=run_id, run_attempt=run_attempt,delivery_root=root)
    for app in chain['apps']:
        if 'embedded_integration' in app:
            continue
        path = member(root, Path(app['file']).name)
        proof = verify(path, policy, signtool)
        if (proof['sha256'], proof['bytes']) != (app['sha256'], app['bytes']):
            raise ValueError('own package changed during native signature verification')
        verify_msi_payload(path, policy, signtool, signed_container=False,
                           expected_payload=expected_producers[app['id']]['expected_payload'],
                           container_proof=proof)
    upstream = {}
    installed = None
    installed_paths = None
    # Core and own native helpers are embedded. Official hosts and app MSIs
    # remain external; every role is derived from the validated chain owner.
    # Extraction parses data through the pinned WiX tool and executes no payload.
    with tempfile.TemporaryDirectory() as temporary:
        engine = Path(temporary) / 'engine.exe'
        run(['wix', 'burn', 'detach', bundle, '-engine', engine])
        if not signing:
            restore_bundle_engine(engine, receipt.get('signatures', {}).get('engine', {}))
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
        manifest = (Path(temporary) / 'ba/manifest.xml').read_text(encoding='utf-8-sig')
        ba_proof=verify_bundle_actions(receipt,chain,Path(temporary)/'ba',policy,signtool)
        if ba_proof is not None:
            if not signing and receipt.get('bootstrapper_native_signature')!=ba_proof:
                raise ValueError('bundle BA native signature differs from final receipt')
            receipt['bootstrapper_native_signature']=ba_proof
        for row, (_, kind, package, app) in zip(original_chain, expected_chain):
            role = ('core' if app is None else 'official-host' if package is app.get('host') else
                    'preflight' if package is app.get('host', {}).get('preflight') else
                    'preparation' if package is app.get('host', {}).get('preparation') else 'app-msi')
            embedded = role in ('core', 'preflight', 'preparation')
            paths = list(extracted.rglob(row['name'])) if embedded else [member(root, row['name'])]
            if len(paths) != 1:
                raise ValueError('signed Setup lacks its exact embedded package')
            if role == 'core' and installed_readback:
                paths[0] = member(extracted, paths[0].relative_to(extracted).as_posix())
                setup_file_pin(paths[0])
            data = paths[0].read_bytes()
            if (hashlib.sha256(data).hexdigest(), len(data)) != (row['sha256'], row['bytes']):
                raise ValueError('signed Setup package differs from its pinned chain')
            if role in ('preflight', 'preparation') and member(root, row['name']).read_bytes() != data:
                raise ValueError('embedded native helper differs from its sealed external copy')
            package['sha512'] = hashlib.sha512(data).hexdigest()
            row.update(role=role, type=kind, embedded=embedded)
            if role == 'official-host':
                expected_host=hosts[app['id']]['host']
                if 'signature' in expected_host:
                    actual=verify(paths[0],policy,signtool)
                    if actual!=expected_host['signature']:raise ValueError('own host differs from authenticated signing transformation')
                    upstream[app['id']]=dict(actual,input=hosts[app['id']])
                else:
                    upstream[app['id']] = dict(verify_upstream(paths[0], expected_host, signtool),input=hosts[app['id']])
            else:
                row['signature'] = verify(paths[0], policy, signtool)
                if (row['signature']['sha256'], row['signature']['bytes']) != (row['sha256'], row['bytes']):
                    raise ValueError('own package changed during native signature verification')
                if role == 'core' and installed_readback:
                    destination = Path(temporary) / 'core-readback'
                    destination.mkdir()
                    run(['wix', 'msi', 'decompile', paths[0], '-x', destination / 'files', '-o', destination / 'package.wxs'])
                    runtime = [file for name, file in core_msi_files(destination) if name == 'openabstractions.exe']
                    if len(runtime) != 1:
                        raise ValueError('verified Setup core needs exactly one runtime')
                    runtime_pin = setup_file_pin(runtime[0])
                    proof = verify(runtime[0], policy, signtool)
                    if any(proof.get(key) != runtime_pin[key] for key in ('sha256', 'bytes')) or setup_file_pin(runtime[0]) != runtime_pin:
                        raise ValueError('Setup runtime changed during native policy verification')
                    installed = {'core': setup_file_pin(paths[0]), 'runtime': runtime_pin}
                    installed_paths = (paths[0], runtime[0])
                    if any(installed['core'][key] != row[key] for key in ('sha256', 'bytes')):
                        raise ValueError('Setup core changed during runtime readback')
        owner.check_manifest(manifest, chain)
        if installed_paths and any(setup_file_pin(path) != installed[key] for key, path in zip(('core', 'runtime'), installed_paths)):
            raise ValueError('Setup core or runtime changed before readback completed')
    receipt['bundle'].update(sha256=outer_proof['sha256'], bytes=outer_proof['bytes'], signed=True)
    receipt['signatures'] = {'engine': engine_proof, 'bundle': outer_proof}
    receipt['policy_sha256'] = policy_sha256
    if upstream:
        receipt['upstream_signatures'] = upstream
    if signing:
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
        sums = [root / row['name'] for row in original_chain[1:]] + [bundle, receipt_path]
        (root / 'SHA256SUMS.setup').write_text(''.join(
            hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n' for path in sums))
    if installed_readback:
        if installed is None or setup_file_pin(bundle) != {key: receipt['bundle'][key] for key in ('name', 'sha256', 'bytes')}:
            raise ValueError('Setup changed or has no verified core runtime readback')
        return receipt, installed
    return receipt


def setup_file_pin(path):
    """Measure an ordinary owned input; this conveys content, not authority."""
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1:
        raise ValueError('Setup input must be an ordinary unlinked file')
    data = path.read_bytes()
    return {'name': path.name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def setup_installed_inputs(receipt, installed, fixture, policy, source, run_id, run_attempt, version):
    if not re.fullmatch('[0-9a-f]{40}', source or '') or type(run_id) is not int or run_id < 1 or type(run_attempt) is not int or run_attempt < 1:
        raise ValueError('Setup installed inputs require exact source/run/attempt')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version or '') or receipt['bundle']['name'] != 'OpenAbstractions-Setup-' + version + '.exe':
        raise ValueError('Setup installed inputs require the exact versioned bundle')
    fixture = Path(fixture)
    return {'schema': 1, 'kind': 'setup-installed-inputs', 'source_sha': source,
            'run_id': run_id, 'run_attempt': run_attempt, 'version': version,
            'bundle': {key: receipt['bundle'][key] for key in ('name', 'sha256', 'bytes')},
            **installed, 'verifier': setup_file_pin(Path(__file__)), 'policy': setup_file_pin(policy),
            'producer': setup_file_pin(fixture),
            'fixture': setup_file_pin(fixture.with_name('test_user_runtime.ps1')),
            'module': setup_file_pin(fixture.with_name('OAFixture.psm1'))}


def check_setup_installed(inputs, result, *, source, run_id, run_attempt, version):
    if (inputs.get('schema') != 1 or inputs.get('kind') != 'setup-installed-inputs' or
            inputs.get('source_sha') != source or type(inputs.get('run_id')) is not int or type(inputs.get('run_attempt')) is not int or
            inputs.get('run_id') != run_id or inputs.get('run_attempt') != run_attempt or inputs.get('version') != version):
        raise ValueError('Setup installed input source/run/attempt differs')
    if (result.get('result') != 'pass' or result.get('ready') is not True or result.get('cleanup_verified') is not True or
            any(type(result.get(key)) is not int or result[key] != 0 for key in ('install_exit', 'uninstall_exit', 'activation_exit')) or
            result.get('signed') is not True or result.get('authenticode', {}).get('valid') is not True or
            result.get('authenticode', {}).get('status') != 'Valid'):
        raise ValueError('Setup install readiness or exact cleanup is incomplete')
    expected = {'artifact_source': source, 'acceptance_tool': source,
                'bundle_sha256': inputs['bundle']['sha256'], 'bundle_bytes': inputs['bundle']['bytes'],
                'installed_runtime_sha256': inputs['runtime']['sha256'],
                'producer_sha256': inputs['producer']['sha256'], 'fixture_sha256': inputs['fixture']['sha256'],
                'module_sha256': inputs['module']['sha256'], 'machine_version': version}
    if any(result.get(key) != value for key, value in expected.items()):
        raise ValueError('Setup installed result differs from verified inputs')
    context = result.get('execution_context', {})
    if (context.get('hosted_elevated') is not True or context.get('elevated') is not True or
            context.get('github_actions') != 'true' or context.get('runner_environment') != 'github-hosted' or
            context.get('runner_os') != 'Windows' or context.get('process_bitness') != 64 or
            not isinstance(context.get('sid'), str) or not context['sid'].startswith('S-1-5-') or
            type(context.get('native_session')) is not int or context['native_session'] < 0):
        raise ValueError('Setup result lacks the explicit hosted elevated account/session context')
    return result


def opencode_content_policy(plugin_version=None):
    """Finite upstream content pins; these confer no verified publisher identity."""
    prefix='LocalAppDataFolder/Programs/OpenAbstractions/apps/opencode/bootstrap/'
    common={'application':'opencode','version':'1.18.34','lock_sha256':'f9f409ec58f87bee16ef9011268bb4fd005d2f817a3c578b4c849424ef1e6750'}
    npm={'url':'https://registry.npmjs.org/@msgpackr-extract/msgpackr-extract-win32-x64/-/msgpackr-extract-win32-x64-3.0.4.tgz',
         'integrity':'sha512-CmCXPQrkbwExx3j946/PtHWHbYJiCRBRDl4BlkRQcJB/YOwQxJRTpoo7aTsortjgoJ1x7opzTSxn7C+ASSLVjQ=='}
    rows={}
    for member,sha in [('node.abi115.node','300b188fb8c997214cb65bf1b00729da293176c7d57035e40c2f432ea384dd89'),
                       ('node.napi.node','6958541c624784dfcebfc4f3c360c57f71cfeedd0530c2393845061729081a08')]:
        rows[prefix+'config/node_modules/@msgpackr-extract/msgpackr-extract-win32-x64/'+member]={
            'sha256':sha,'bytes':112640,'source':dict(common,**npm,member='package/'+member)}
    rows[prefix+'cache/bin/rg.exe']={'sha256':'decdd4992f3f1b9a5ef9898f1b40ab16886d579d6516b4efd3d5eaa19364e408','bytes':4266496,
        'source':dict(common,url='https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep-15.1.0-x86_64-pc-windows-msvc.zip',
                      integrity='sha256-124510b94b6baa3380d051fdf4650eaa80a302c876d611e9dba0b2e18d87493a',
                      member='ripgrep-15.1.0-x86_64-pc-windows-msvc/rg.exe')}
    if plugin_version is not None:
        if not isinstance(plugin_version,str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?',plugin_version):
            raise ValueError('invalid selected OpenCode plugin version')
        plugin='LocalAppDataFolder/Programs/OpenAbstractions/apps/opencode/plugin/'+plugin_version+'/node_modules/@msgpackr-extract/msgpackr-extract-win32-x64/'
        source={'application':'opencode','version':'1.18.31','lock_sha256':'8920c6f07ac511ee6ed728e75a17476f54528ddf93e46c77c997a006694f281b'}
        for member in ('node.abi115.node','node.napi.node'):
            original=rows[prefix+'config/node_modules/@msgpackr-extract/msgpackr-extract-win32-x64/'+member]
            rows[plugin+member]={'sha256':original['sha256'],'bytes':original['bytes'],'source':dict(source,**npm,member='package/'+member)}
    return rows


def opencode_content_cli():
    return ('LocalAppDataFolder/Programs/OpenAbstractions/apps/opencode/cli/opencode.exe',
            {'sha256':'5283c2cd5b4285855daa97e6f7d17bf48146227cdf2a940e79e0f2b7869fd06e','bytes':180599176})


def validate_expected_payload(expected):
    """Validate caller-owned app expectations; this object grants no authority."""
    required = {'schema', 'msi', 'files', 'binaries', 'own_pe', 'supplier_pe'}
    if (not isinstance(expected, dict) or not required <= set(expected)
            or set(expected) - required - {'icons', 'registration', 'supplier_content_pe'}
            or type(expected['schema']) is not int or expected['schema'] not in (1,2)
            or (expected['schema']==1 and 'supplier_content_pe' in expected)
            or (expected['schema']==2 and 'supplier_content_pe' not in expected)):
        raise ValueError('invalid expected app payload')
    expected = dict(expected, icons=expected.get('icons', []))
    if 'registration' in expected:
        registration = expected['registration']
        if (not isinstance(registration, dict) or set(registration) != {'schema', 'application', 'setup_command'}
                or type(registration['schema']) is not int or registration['schema'] != 1
                or not isinstance(registration['application'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', registration['application'])
                or not isinstance(registration['setup_command'], str)
                or not re.fullmatch(r'"\[HostFolder\]\.\.\\[A-Za-z0-9_.-]+\\Scripts\\pythonw\.exe" -I -B "\[ExtensionFolder\][A-Za-z0-9_.-]+\.py"', registration['setup_command'])):
            raise ValueError('invalid checked extension registration expectation')
    def bytepin(row):
        return (type(row.get('bytes')) is int and row['bytes'] >= 0
                and re.fullmatch('[0-9a-f]{64}', str(row.get('sha256'))))
    def relative(name):
        return (isinstance(name, str) and name and name == PurePosixPath(name).as_posix()
                and not PurePosixPath(name).is_absolute() and not any(
                    part in ('.', '..') or part.rstrip(' .') != part
                    or any(c in part for c in '\\:\0*?"<>|') for part in name.split('/')))
    msi = expected['msi']
    if (not isinstance(msi, dict) or set(msi) != {'name', 'sha256', 'bytes'}
            or not relative(msi['name']) or not bytepin(msi)):
        raise ValueError('invalid expected app MSI pin')
    keys, paths = set(), set()
    for table, field in (('File', 'files'), ('Binary', 'binaries'), ('Icon', 'icons')):
        if not isinstance(expected[field], list):
            raise ValueError('invalid closed app table inventory')
        for row in expected[field]:
            fields = {'id', 'sha256', 'bytes'} | ({'path'} if table == 'File' else set())
            if (not isinstance(row, dict) or set(row) != fields
                    or not isinstance(row['id'], str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_.]*', row['id'])
                    or (table, row['id'].casefold()) in keys or not bytepin(row)):
                raise ValueError('invalid or duplicate expected app table row')
            keys.add((table, row['id'].casefold()))
            if table == 'File':
                if not relative(row['path']) or row['path'].casefold() in paths:
                    raise ValueError('invalid or duplicate installed app path')
                paths.add(row['path'].casefold())
    roles = set()
    for field, extra in (('own_pe', 'signature'), ('supplier_pe', 'pin')):
        if not isinstance(expected[field], list):
            raise ValueError('invalid app PE roles')
        for role in expected[field]:
            if (not isinstance(role, dict) or set(role) != {'table', 'id', extra}
                    or role['table'] not in ('File', 'Binary') or not isinstance(role['id'], str)
                    or (role['table'], role['id'].casefold()) not in keys
                    or (role['table'], role['id'].casefold()) in roles):
                raise ValueError('unlisted or duplicate app PE role')
            roles.add((role['table'], role['id'].casefold()))
            if extra == 'pin' and (not isinstance(role['pin'], dict)
                    or set(role['pin']) != {'sha256', 'bytes'} or not bytepin(role['pin'])):
                raise ValueError('invalid reviewed supplier PE pin')
    content=expected.get('supplier_content_pe',[])
    if not isinstance(content,list):
        raise ValueError('invalid source-selected content PE roles')
    plugin_versions=set()
    for row in expected['files']:
        match=re.fullmatch(r'LocalAppDataFolder/Programs/OpenAbstractions/apps/opencode/plugin/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/node_modules/@msgpackr-extract/msgpackr-extract-win32-x64/(?:node\.abi115\.node|node\.napi\.node)',row['path'])
        if match:plugin_versions.add(match.group(1))
    if len(plugin_versions)>1:
        raise ValueError('multiple selected OpenCode plugin versions')
    policy=opencode_content_policy(next(iter(plugin_versions))) if plugin_versions else opencode_content_policy()
    selected=set()
    for role in content:
        if (not isinstance(role,dict) or set(role)!={'table','id','pin'} or role['table']!='File'
                or not isinstance(role['id'],str) or (role['table'],role['id'].casefold()) in roles):
            raise ValueError('invalid or duplicate source-selected content PE role')
        rows=[row for row in expected['files'] if row['id']==role['id']]
        if len(rows)!=1 or rows[0]['path'] not in policy or role['pin']!=policy[rows[0]['path']]:
            raise ValueError('content PE differs from fixed reviewed upstream closure')
        selected.add(rows[0]['path']);roles.add((role['table'],role['id'].casefold()))
        if any(rows[0][key]!=role['pin'][key] for key in ('sha256','bytes')):
            raise ValueError('content PE table bytes differ from reviewed upstream closure')
    if expected['schema']==2 and selected!=set(policy):
        raise ValueError('content PE closure is incomplete')
    if expected['schema']==2:
        path,pin=opencode_content_cli()
        cli=[row for row in expected['files'] if row['path']==path and all(row[key]==pin[key] for key in pin)]
        if len(cli)!=1 or not any(role['table']=='File' and role['id']==cli[0]['id'] and role['pin']==pin for role in expected['supplier_pe']):
            raise ValueError('content PE helper version requires its exact selected signed CLI')
    return expected


def msi_extracted_member(extracted, source):
    """Resolve a WiX member within this owned extraction, without links."""
    if (not extracted.is_dir() or extracted.is_symlink() or extracted.is_junction()
            or getattr(extracted.lstat(), 'st_file_attributes', 0) & 0x400):
        raise ValueError('MSI extraction root is missing or linked')
    extracted = extracted.resolve()
    absolute = Path(source)
    if absolute.is_absolute():
        # WiX emits absolute Binary sources when -x is an absolute directory.
        # Admit only an exact native path below this extraction; containment
        # and every existing component are checked again below before reading.
        if source != str(absolute):
            raise ValueError('MSI extraction source is not canonical')
        try:
            relative = PureWindowsPath('SourceDir', *absolute.relative_to(extracted).parts)
        except ValueError as error:
            raise ValueError('MSI extraction source is outside its owned extraction') from error
    else:
        relative = PureWindowsPath(source)
        if source != '\\'.join(relative.parts):
            raise ValueError('MSI extraction source is not canonical SourceDir-relative')
    parts = relative.parts
    if (relative.drive or relative.root or len(parts) < 2 or parts[0] != 'SourceDir'
            or any(part in ('.', '..') or part.rstrip(' .') != part
                   or any(char in part for char in '\0/:*?"<>|') for part in parts)):
        raise ValueError('MSI extraction source is not canonical SourceDir-relative')
    target = extracted.joinpath(*parts[1:])
    current = target
    while current != extracted:
        if current.is_symlink() or current.is_junction():
            raise ValueError('MSI extraction source cannot use a linked member')
        current = current.parent
    if (not target.is_file() or not target.resolve().is_relative_to(extracted)
            or target.stat().st_nlink != 1
            or getattr(target.lstat(), 'st_file_attributes', 0) & 0x400):
        raise ValueError('MSI extraction source is missing, linked or outside its owned extraction')
    return target


def msi_member_readback(destination, *, extraction=None, source=None):
    extraction = destination / 'files' if extraction is None else extraction
    if (not extraction.is_dir() or extraction.is_symlink() or extraction.is_junction()
            or getattr(extraction.lstat(), 'st_file_attributes', 0) & 0x400):
        raise ValueError('app MSI extraction root is missing or linked')
    extracted = extraction.resolve()
    actual, members, identities, installed = {'files': [], 'binaries': [], 'icons': []}, {}, set(), set()
    directories = {}
    def directory_path(element, directory, anchored):
        tag = element.tag.rsplit('}', 1)[-1]
        if tag in ('StandardDirectory', 'Directory'):
            if tag == 'StandardDirectory':
                if directory:
                    raise ValueError('app MSI standard directory anchor must be the root')
                anchored = True
            name = element.get('Id') if tag == 'StandardDirectory' else element.get('Name')
            if not name or name in ('.', '..') or any(c in name for c in '/\\:\0*?"<>|') or name.rstrip(' .') != name:
                raise ValueError('app MSI directory is not canonical')
            directory += (name,)
        if tag == 'DirectoryRef':
            raise ValueError('app MSI unresolved directory reference')
        return directory, anchored
    def index_directories(element, directory=(), anchored=False):
        directory, anchored = directory_path(element, directory, anchored)
        if element.tag.rsplit('}', 1)[-1] in ('StandardDirectory', 'Directory'):
            identifier = element.get('Id')
            if not identifier or identifier in directories:
                raise ValueError('app MSI directory identity is missing or ambiguous')
            directories[identifier] = (directory, anchored)
        for child in element:
            index_directories(child, directory, anchored)
    def visit(element, directory=(), anchored=False):
        tag = element.tag.rsplit('}', 1)[-1]
        directory, anchored = directory_path(element, directory, anchored)
        if tag == 'Component' and element.get('Directory') is not None:
            reference = element.get('Directory')
            if reference not in directories or not directories[reference][1]:
                raise ValueError('app MSI Component directory is unknown or unanchored')
            directory, anchored = directories[reference]
        if tag in ('File', 'Binary', 'Icon'):
            key = (tag, element.get('Id'))
            if key in members or not key[1]:
                raise ValueError('duplicate or missing app MSI table key')
            target = msi_extracted_member(extracted, element.get('Source' if tag == 'File' else 'SourceFile', ''))
            identity = str(target.resolve()).casefold()
            if identity in identities:
                raise ValueError('MSI extraction source is mapped more than once')
            identities.add(identity)
            data = target.read_bytes()
            row = {'id': key[1], 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            if tag == 'File':
                name = element.get('Name', '')
                if not anchored or not directory or not name or name in ('.', '..') or any(c in name for c in '/\\:\0*?"<>|') or name.rstrip(' .') != name:
                    raise ValueError('app MSI installed file path is not canonical')
                row['path'] = '/'.join((*directory, name))
                if row['path'].casefold() in installed:
                    raise ValueError('duplicate installed app file path')
                installed.add(row['path'].casefold())
            actual[{'File': 'files', 'Binary': 'binaries', 'Icon': 'icons'}[tag]].append(row)
            members[key] = (target, data, row)
        for child in element:
            visit(child, directory, anchored)
    tree = ET.parse(destination / 'package.wxs' if source is None else source).getroot()
    index_directories(tree)
    visit(tree)
    for target in extracted.rglob('*'):
        if target.is_symlink() or target.is_junction() or getattr(target.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('app MSI extraction contains a linked member')
        if target.is_file() and str(target.resolve()).casefold() not in identities:
            raise ValueError('app MSI extraction contains a foreign member')
    return actual, members, extracted, tree


def final_msi_members(actual):
    rows = [dict(row, table=table) for table, field in
            (('File', 'files'), ('Binary', 'binaries'), ('Icon', 'icons')) for row in actual.get(field, [])]
    return validate_msi_members(sorted(rows, key=lambda row: (row['table'], row['id'])))


def app_msi_readback(destination, expected, policy, signtool):
    expected=validate_expected_payload(expected)
    actual, members, extracted, tree = msi_member_readback(destination)
    identities = {str(target.resolve()).casefold() for target, _, _ in members.values()}
    if 'registration' in expected:
        extension_registration_readback(tree, expected['registration'])
    for field in ('files', 'binaries', 'icons'):
        if sorted(actual[field], key=lambda row: row['id']) != sorted(expected[field], key=lambda row: row['id']):
            raise ValueError('closed app MSI ' + field + ' inventory differs')
    # MZ members require a valid PE header and an explicit source-owned role,
    # irrespective of extension. Malformed executable-like input refuses.
    pe = set()
    for key, (_, data, _) in members.items():
        if data.startswith(b'MZ'):
            if key[0] == 'Icon':
                raise ValueError('app MSI Icon cannot contain PE-shaped bytes')
            offset = int.from_bytes(data[60:64], 'little') if len(data) >= 64 else 0
            if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
                raise ValueError('app MSI contains malformed PE input')
            pe.add(key)
    roles = {(row['table'], row['id']): (field, row) for field in ('own_pe', 'supplier_pe','supplier_content_pe') for row in expected.get(field,[])}
    if set(roles) != pe:
        raise ValueError('app MSI native PE roster differs from source-owned roles')
    for key, (field, role) in roles.items():
        target, _, row = members[key]
        pin = {name: row[name] for name in ('sha256', 'bytes')}
        if field == 'own_pe':
            retained = role['signature']
            digest = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
            verify_receipt({'schema': 1, 'result': 'pass', 'policy_sha256': digest, 'files': [retained]},
                           policy, policy_sha256=digest)
            if any(retained[name] != pin[name] for name in pin):
                raise ValueError('own PE differs from its post-sign proof')
            proof = verify(target, policy, signtool)
        elif field == 'supplier_pe':
            if role['pin'] != pin:
                raise ValueError('supplier PE differs from its reviewed pin')
            proof = verify_upstream(target, role['pin'], signtool)
        else:
            if any(role['pin'][name]!=pin[name] for name in pin):
                raise ValueError('content PE differs from fixed upstream digest')
            proof=pin
        if any(proof[name] != pin[name] for name in pin) or target.read_bytes() != members[key][1]:
            raise ValueError('app PE changed during verification')
    for target, data, _ in members.values():
        checked = msi_extracted_member(extracted, 'SourceDir\\' + '\\'.join(target.relative_to(extracted).parts))
        if checked.read_bytes() != data:
            raise ValueError('app member changed during native verification')
    for target in extracted.rglob('*'):
        if (target.is_symlink() or target.is_junction()
                or getattr(target.lstat(), 'st_file_attributes', 0) & 0x400
                or target.is_file() and str(target.resolve()).casefold() not in identities):
            raise ValueError('app MSI extraction changed during native verification')
    return actual


def extension_registration_readback(tree, expected):
    """Bind the opt-in setup/target/consent chain to compiled MSI actions."""
    actions = {}
    sequence = {}
    for element in tree.iter():
        tag = element.tag.rsplit('}', 1)[-1]
        if tag == 'CustomAction':
            key = element.get('Id')
            if key in actions:
                raise ValueError('duplicate extension action')
            actions[key] = element
        if tag == 'InstallExecuteSequence':
            for row in element:
                key = row.get('Action', row.tag.rsplit('}', 1)[-1])
                if key in sequence:
                    raise ValueError('duplicate extension execute action')
                sequence[key] = row
    required = {
        'SetValidatePreparedHost': {'Property':'ValidatePreparedHost','Value':'[HostFolder]'},
        'ValidatePreparedHost': {'BinaryRef':'HostFolderAction','DllEntry':'ValidatePreparedHost','Execute':'deferred','Impersonate':'yes','Return':'check'},
        'SetRecordPreparedTarget': {'Property':'RecordPreparedTarget','Value':'[HostFolder]'},
        'RecordPreparedTarget': {'BinaryRef':'HostFolderAction','DllEntry':'RecordPreparedTarget','Execute':'deferred','Impersonate':'yes','Return':'check'},
        'PrepareTargetRollback': {'BinaryRef':'HostFolderAction','DllEntry':'PrepareTargetRollback','Execute':'immediate','Return':'check'},
        'RollbackPreparedTarget': {'BinaryRef':'HostFolderAction','DllEntry':'RollbackPreparedTarget','Execute':'rollback','Impersonate':'yes','Return':'check'},
        'SetValidateRecordedTarget': {'Property':'ValidateRecordedTarget','Value':'[HostFolder]'},
        'ValidateRecordedTarget': {'BinaryRef':'HostFolderAction','DllEntry':'ValidateRecordedTarget','Execute':'deferred','Impersonate':'yes','Return':'check'},
        'RunExtensionSetup': {'Directory':'ExtensionFolder','ExeCommand':expected['setup_command'],'Execute':'deferred','Impersonate':'yes','Return':'check'},
        'ValidateRegistrationHost': {'BinaryRef':'HostFolderAction','DllEntry':'ValidateRegistrationHost','Execute':'immediate','Return':'check'},
        'RegisterApplication': {'Property':'OaPanel','ExeCommand':'--register-application "[ExtensionFolder]application-manifest.json"','Execute':'immediate','Return':'asyncNoWait'},
        'CheckRemovalRegistration': {'BinaryRef':'HostFolderAction','DllEntry':'CheckRemovalRegistration','Execute':'immediate','Return':'check'},
        'RemoveApplication': {'Property':'OaPanel','ExeCommand':'--remove-application '+expected['application'],'Execute':'immediate','Return':'asyncNoWait'},
    }
    defaults = {'Execute':'immediate','Return':'check','Impersonate':'yes'}
    for key, attributes in required.items():
        action = actions.get(key)
        if action is None or any(action.get(name, defaults.get(name)) != value for name,value in attributes.items()):
            raise ValueError('compiled extension setup/registration action differs: '+key)
        if any(action.get(name,default)!=attributes.get(name,default) for name,default in defaults.items()):
            raise ValueError('compiled extension action execution policy differs: '+key)
        # A second execution target cannot accompany the authenticated target.
        targets = {'BinaryRef','FileRef','Directory','Property','Script','DllEntry','ExeCommand','Value','JScriptCall','VBScriptCall','Error'}
        if set(action.attrib) & targets != set(attributes) & targets:
            raise ValueError('compiled extension action has a foreign target')
    conditions = {'SetValidatePreparedHost':'', 'ValidatePreparedHost':'NOT REMOVE',
        'SetRecordPreparedTarget':'','RecordPreparedTarget':'NOT REMOVE',
        'PrepareTargetRollback':'NOT REMOVE','RollbackPreparedTarget':'NOT REMOVE',
        'SetValidateRecordedTarget':'','ValidateRecordedTarget':'REMOVE OR Installed',
        'RunExtensionSetup':'NOT REMOVE',
        'ValidateRegistrationHost':'NOT REMOVE AND NOT UPGRADINGPRODUCTCODE',
        'RegisterApplication':'OaPanel AND NOT REMOVE AND NOT UPGRADINGPRODUCTCODE',
        'CheckRemovalRegistration':'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE',
        'RemoveApplication':'OaPanel AND OaRemovalRegistrationOwned AND REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'}
    for key, condition in conditions.items():
        row = sequence.get(key)
        if row is None or row.get('Condition', (row.text or '').strip()) != condition:
            raise ValueError('compiled extension registration condition differs: '+key)
        if sum(row.get(field) is not None for field in ('Sequence','Before','After'))!=1:
            raise ValueError('compiled extension action sequence is ambiguous')
    # WiX may express decompiled sequence positions numerically or relative to
    # another action. Resolve both forms against Windows Installer anchors.
    anchors = {'RemoveFiles':3500, 'InstallFiles':4000, 'InstallFinalize':6600}
    def position(key, visiting=()):
        if key in anchors: return anchors[key]
        if key in visiting or key not in sequence:
            raise ValueError('unresolved extension action sequence')
        row = sequence[key]
        if row.get('Sequence') is not None:
            try: return int(row.get('Sequence'))
            except ValueError: raise ValueError('invalid extension action sequence') from None
        for direction, offset in (('Before',-0.25),('After',0.25)):
            if row.get(direction): return position(row.get(direction),(*visiting,key))+offset
        raise ValueError('missing extension action sequence')
    for earlier,later in (('InstallFiles','ValidatePreparedHost'),
            ('SetValidatePreparedHost','ValidatePreparedHost'),
            ('ValidatePreparedHost','PrepareTargetRollback'),('PrepareTargetRollback','RollbackPreparedTarget'),
            ('RollbackPreparedTarget','RecordPreparedTarget'),('SetRecordPreparedTarget','RecordPreparedTarget'),
            ('RecordPreparedTarget','RunExtensionSetup'),('RunExtensionSetup','InstallFinalize'),
            ('SetValidateRecordedTarget','ValidateRecordedTarget'),('ValidateRecordedTarget','RemoveFiles'),
            ('InstallFinalize','ValidateRegistrationHost'),('ValidateRegistrationHost','RegisterApplication'),
            ('CheckRemovalRegistration','RemoveApplication'),('RemoveApplication','RemoveFiles')):
        if position(earlier) >= position(later):
            raise ValueError('compiled extension registration order differs')


def core_msi_files(destination):
    """Read the source-owned native core File roster from one WiX extraction."""
    # WiX also extracts Binary-table custom actions from its own pinned
    # extensions. File-table payloads are the installer roster's authority.
    allowed = {PurePosixPath(row[1]).name for row in payload_rows(Path(__file__).with_name('payload.tsv'))
               if row[5] == 'yes'}
    files = []
    names, sources = set(), set()
    extraction = destination / 'files'
    if not extraction.is_dir() or extraction.is_symlink() or extraction.is_junction():
        raise ValueError('core MSI extraction root is missing or linked')
    extracted = extraction.resolve()
    for element in ET.parse(destination / 'package.wxs').iter():
        if element.tag.rsplit('}', 1)[-1] != 'File':
            continue
        name = element.get('Name', '')
        if (not name or any(value in name for value in ('/', '\\', ':', '\0', '*', '?', '"', '<', '>', '|'))
                or name.rstrip(' .') != name or name in ('.', '..')):
            raise ValueError('MSI installed file name is not canonical')
        executable = PureWindowsPath(name).suffix.lower() in ('.exe', '.dll')
        if executable and name not in allowed:
            raise ValueError('MSI installs an executable outside payload signing authority')
        source = element.get('Source', '')
        target = msi_extracted_member(extracted, source)
        identity = str(target.resolve()).casefold()
        if identity in sources:
            raise ValueError('MSI extraction source is mapped more than once')
        sources.add(identity)
        if not executable:
            continue
        if name.casefold() in names:
            raise ValueError('MSI installed executable name is mapped more than once')
        names.add(name.casefold())
        files.append((name, target))
    if not files:
        raise ValueError('core MSI has no signed executable payload')
    return files


def verify_msi_payload(path, policy, signtool, canonical_dll=None, *, signed_container=True,
                        expected_payload=None, container_proof=None, canonical_appmodel=None):
    if expected_payload is not None:
        expected_payload = validate_expected_payload(expected_payload)
        pin = expected_payload['msi']
        if container_proof is not None:
            digest = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
            verify_receipt({'schema': 1, 'result': 'pass', 'policy_sha256': digest, 'files': [container_proof]},
                           policy, policy_sha256=digest)
            pin = container_proof
        data = Path(path).read_bytes()
        if (hashlib.sha256(data).hexdigest(), len(data)) != (pin['sha256'], pin['bytes']):
            raise ValueError('app MSI differs from its admitted container or OA signing proof')
    original = Path(path).read_bytes()
    if expected_payload is None and container_proof is not None:
        digest = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
        verify_receipt({'schema': 1, 'result': 'pass', 'policy_sha256': digest, 'files': [container_proof]},
                       policy, policy_sha256=digest)
        if (container_proof['sha256'], container_proof['bytes']) != (hashlib.sha256(original).hexdigest(), len(original)):
            raise ValueError('final MSI differs from its admitted signing proof')
    proof = verify(path, policy, signtool) if signed_container else container_proof
    if proof is not None and (proof['sha256'], proof['bytes']) != (hashlib.sha256(original).hexdigest(), len(original)):
        raise ValueError('final MSI container differs from its signature proof')
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary)
        run(['wix', 'msi', 'decompile', path, '-x', destination / 'files', '-o', destination / 'package.wxs'])
        if expected_payload is not None:
            actual = app_msi_readback(destination, expected_payload, policy, signtool)
            if Path(path).read_bytes() != data:
                raise ValueError('app MSI changed during payload readback')
            return dict(proof, msi_members=final_msi_members(actual)) if proof is not None else None
        files = core_msi_files(destination)
        actual, members, _, _ = msi_member_readback(destination)
        for _, file in files:
            verify(file, policy, signtool)
        libraries = [file for name, file in files if name == 'abstraction_ipc.dll']
        if Path(path).name == 'abstraction-x64.msi':
            if len(libraries) != 1 or canonical_dll is None or libraries[0].read_bytes() != Path(canonical_dll).read_bytes():
                raise ValueError('x64 MSI canonical signed DLL differs from language packages')
        if Path(path).name == 'abstraction-arm64.msi' and libraries:
            raise ValueError('Windows ARM64 has no qualified IPC DLL')
        appmodel = [file for name, file in files if name == 'abstraction_facade_appmodel.dll']
        if Path(path).name in ('abstraction-x64.msi', 'abstraction-arm64.msi') and canonical_appmodel is not None:
            if len(appmodel) != 1 or appmodel[0].read_bytes() != Path(canonical_appmodel).read_bytes():
                raise ValueError('MSI canonical signed AppModel DLL differs from its selected architecture')
        elif appmodel:
            raise ValueError('MSI has no qualified canonical AppModel DLL for this architecture')
        if any(target.read_bytes() != data for target, data, _ in members.values()):
            raise ValueError('core MSI member changed during readback')
        if Path(path).read_bytes() != original:
            raise ValueError('MSI container changed during payload readback')
        if proof is not None:
            proof = dict(proof, msi_members=final_msi_members(actual))
    return proof


def sign_app_msi(path, policy, signtool, expected_payload):
    """Sign a pinned container only after its signed members pass readback."""
    verify_msi_payload(path, policy, signtool, signed_container=False, expected_payload=expected_payload)
    proof = sign(path, policy, signtool)
    return verify_msi_payload(path, policy, signtool, signed_container=False,
                              expected_payload=expected_payload, container_proof=proof)


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
                        'copy-chain', 'smoke-build', 'smoke-sign', 'sign-pe', 'verify-pe', 'sign-msi',
                        'verify-msis', 'verify-language', 'sign-bundle', 'verify-bundle', 'check-setup-installed'))
    for name in ('root', 'policy', 'receipt', 'payload', 'pypi', 'npm', 'release', 'out', 'canonical'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--signtool')
    parser.add_argument('--github-env', type=Path)
    parser.add_argument('--producer-bindings', type=Path)
    parser.add_argument('--producer-context', type=Path)
    parser.add_argument('--artifact-id', type=int)
    parser.add_argument('--artifact-name')
    parser.add_argument('--artifact-digest')
    parser.add_argument('--artifact-attempt', type=int)
    parser.add_argument('--source')
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--run-attempt', type=int)
    parser.add_argument('--installed-inputs', type=Path)
    parser.add_argument('--installed-result', type=Path)
    parser.add_argument('--setup-fixture', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--scope',choices=('all','native','runtime','apps','core'),default='all',
                        help='existing signing phase subset; retained inputs are verified before joining')
    parser.add_argument('--retained-signatures',type=Path)
    parser.add_argument('--native-family', action='append', choices=('facade',),
                        help='additional source-bound native family; IPC remains required')
    parser.add_argument('--native-roster', type=Path,
                        help='select additional native families from the candidate Python source roster')
    args = parser.parse_args(argv)
    if args.native_roster:
        if args.native_family:
            parser.error('explicit native family and candidate roster are distinct selections')
        args.native_family = declared_native_families(args.native_roster)
    allowed = ({'all','native','runtime'} if args.operation in ('sign-pe','verify-pe') else
               {'all','apps','core'} if args.operation == 'sign-msi' else {'all'})
    if args.scope not in allowed or (args.retained_signatures is not None and args.scope not in ('runtime','core')):
        parser.error('scope or retained signatures do not belong to this phase')
    if (args.native_family or args.native_roster) and args.operation not in ('check-native-source', 'sign-pe', 'verify-pe', 'verify-language', 'verify-msis', 'sign-msi'):
        parser.error('native family does not belong to this phase')
    native_member_names(args.native_family)
    admitted_context_pin = None
    def producer_context():
        nonlocal admitted_context_pin
        if args.producer_context:
            if args.producer_bindings:
                raise ValueError('retained context and raw producer bindings are distinct inputs')
            owner = application_context_policy()
            version = args.version.removeprefix('v') if args.version else None
            required = owner.installer_scope(version)
            _, sources = owner.selected_sources(required, version, producer_source=args.source)
            received, admitted_context_pin = retained_application_context(args.producer_context.parent, args.producer_context,
                source=args.source, run_id=args.run_id, artifact_id=args.artifact_id,
                artifact_name=args.artifact_name, artifact_digest=(args.artifact_digest or '').removeprefix('sha256:'),
                artifact_attempt=args.artifact_attempt, version=version, required=required, sources=sources)
            return received
        return dict(expected_producers=json.loads(args.producer_bindings.read_bytes()) if args.producer_bindings else None,
                    source=args.source or os.environ.get('CANDIDATE_SHA'),
                    run_id=args.run_id or int(os.environ.get('GITHUB_RUN_ID', '0')),
                    run_attempt=args.run_attempt or int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')))
    if args.operation == 'prepare-tools':
        prepare_tools(args.root, args.github_env)
        return 0
    if args.operation == 'check-native-source':
        native_source(args.pypi, args.npm, args.native_family, args.root)
        native_family_environment(args.github_env, args.native_family)
        return 0
    if args.operation == 'smoke-build':
        smoke_build(args.root)
        return 0
    if args.operation == 'copy-chain':
        if args.producer_context: producer_context()
        copy_chain_distribution(args.root / 'chain.json', args.out, args.producer_context, context_pin=admitted_context_pin)
        return 0
    if args.operation == 'prepare-chain':
        prepare_chain(args.root, args.release, args.out, json.loads(args.policy.read_bytes()),
                      hashlib.sha256(args.policy.read_bytes()).hexdigest(), signtool=args.signtool, **producer_context())
        return 0
    policy = json.loads(args.policy.read_bytes())
    identity(policy)
    operation = verify if args.operation.startswith('verify') else sign
    root = args.root.resolve()
    if args.operation == 'check-setup-installed':
        inputs = json.loads(args.installed_inputs.read_bytes())
        expected = setup_installed_inputs({'bundle': inputs['bundle']},
            {key: inputs[key] for key in ('core', 'runtime')}, args.setup_fixture, args.policy,
            args.source, args.run_id, args.run_attempt, args.version)
        if expected != inputs or setup_file_pin(member(root, inputs['bundle']['name'])) != inputs['bundle']:
            raise ValueError('Setup installed input producer/policy or final bundle changed')
        check_setup_installed(inputs, json.loads(args.installed_result.read_bytes()),
                              source=args.source, run_id=args.run_id, run_attempt=args.run_attempt, version=args.version)
        return 0
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
        if args.native_family:
            for path in facade_language_members(root, canonical):
                verify(path, policy, args.signtool)
        return 0
    if args.operation == 'verify-msis':
        if args.canonical is None:
            raise ValueError('verify-msis requires the canonical signed IPC DLL (--canonical)')
        payloads, retained = {}, {}
        if (root / 'core').exists():
            targets = [member(root, 'core/abstraction-x64.msi'), member(root, 'core/abstraction-arm64.msi')]
            chain = json.loads(msi_extracted_member(root, 'SourceDir\\apps\\chain.json').read_bytes())
            context = producer_context()
            producer_hosts(chain, delivery_root=root, **context)
            retained = {row['name']: row for row in verify_receipt(
                json.loads(msi_extracted_member(root, 'SourceDir\\signatures.json').read_bytes()), policy, root,
                policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest())['files']}
            for app, binding in context['expected_producers'].items():
                if 'expected_payload' not in binding: continue
                payload = binding['expected_payload']
                name = 'apps/apps/' + app + '/' + Path(payload['msi']['name']).name
                path = member(root, name); targets.append(path); payloads[path] = payload
        else:
            targets = [member(root, 'abstraction-x64.msi'), member(root, 'abstraction-arm64.msi')]
        proofs = []
        for path in targets:
            name = Path(os.path.relpath(path, root)).as_posix()
            if retained and name not in retained:
                raise ValueError('final MSI lacks its original signing proof')
            proof = verify_msi_payload(path, policy, args.signtool, args.canonical,
                expected_payload=payloads.get(path), container_proof=retained.get(name),
                canonical_appmodel=canonical_appmodel_member(args.canonical.parent, path, args.native_family)
                    if path not in payloads else None)
            proofs.append(dict(proof, name=name))
        args.receipt.write_text(json.dumps({'schema': 1, 'result': 'pass',
            'policy_sha256':hashlib.sha256(args.policy.read_bytes()).hexdigest(), 'files': proofs}, indent=2) + '\n')
        return 0
    if args.operation in ('sign-bundle', 'verify-bundle'):
        if args.installed_inputs and (args.operation != 'verify-bundle' or not args.setup_fixture or args.installed_inputs.exists()):
            raise ValueError('fresh installed inputs require verify-bundle and its exact Setup fixture')
        result = check_bundle(root, policy, args.signtool, signing=args.operation == 'sign-bundle',
                     policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest(),
                     installed_readback=bool(args.installed_inputs), **producer_context())
        if args.installed_inputs:
            receipt, installed = result
            data = setup_installed_inputs(receipt, installed, args.setup_fixture, args.policy,
                                          args.source, args.run_id, args.run_attempt, args.version)
            with args.installed_inputs.open('x', encoding='utf-8') as target:
                target.write(json.dumps(data, indent=2) + '\n')
        return 0
    if args.operation in ('sign-pe', 'verify-pe'):
        targets = []
        for architecture, folder in (('x64', 'amd64'), ('arm64', 'arm64')):
            directory = root / 'runtime/a' / folder
            if args.scope != 'native' and directory.exists():
                targets.extend(signature_targets(payload_rows(args.payload), directory, architecture))
        if args.scope != 'runtime':
            selected = [member(root, name) for name in native_member_names(args.native_family)]
            actual = {path for path in (root / 'native').rglob('*') if path.suffix.lower() in ('.dll', '.node')}
            if actual != set(selected):
                raise ValueError('native executable inventory differs from selected producer families')
            targets.extend(selected)
    elif args.operation == 'sign-msi':
        targets = ([] if args.scope == 'apps' else
                   [member(root, 'core/abstraction-x64.msi'), member(root, 'core/abstraction-arm64.msi')])
        for path in targets:
            verify_msi_payload(path, policy, args.signtool, root / 'canonical/native/abstraction_ipc.dll', signed_container=False,
                canonical_appmodel=canonical_appmodel_member(root / 'canonical/native', path, args.native_family))
        app_targets = sorted((root / 'apps/apps').glob('*/*.msi'))
        staged_path = root / 'apps/chain.json'
        staged = json.loads(staged_path.read_bytes()) if staged_path.exists() else {'version': None, 'apps': []}
        if not isinstance(staged, dict) or set(staged) != {'version', 'apps'}:
            raise ValueError('staged app chain requires exactly version and apps')
        context = producer_context()
        producer_hosts(staged, delivery_root=root, **context)
        expected = context['expected_producers'] or {}
        by_path = {member(root, 'apps/apps/' + app['id'] + '/' + Path(app['file']).name): app['id']
                   for app in staged['apps'] if 'embedded_integration' not in app}
        if set(app_targets) != set(by_path):
            raise ValueError('selected app MSI signing targets differ from producer chain')
        app_payloads = {path: expected[by_path[path]]['expected_payload'] for path in app_targets}
        if args.scope != 'core':targets.extend(app_targets)
    elif args.operation == 'smoke-sign':
        targets = [member(root, 'hello.exe'), member(root, 'hello.msi')]
    else:
        raise ValueError('unknown Windows signature phase')
    # Serialize targets already selected above as relative wire member names.
    proofs = []
    if args.scope in ('runtime','core'):
        if args.retained_signatures is None:raise ValueError('split signing requires retained exact prior signatures')
        expected = (set(native_member_names(args.native_family)) if args.scope == 'runtime' else
                    {'apps/apps/' + app['id'] + '/' + Path(app['file']).name
                     for app in staged['apps'] if 'embedded_integration' not in app})
        policy_sha=hashlib.sha256(args.policy.read_bytes()).hexdigest()
        retained=json.loads(args.retained_signatures.read_bytes())
        # A native catalog delivery can have no MSI container. Its separately
        # checked host/external signatures remain in the normal sealing owner.
        empty=dict(schema=1,result='pass',policy_sha256=policy_sha,files=[])
        if expected or retained != empty:
            retained=verify_receipt(retained,policy,root,policy_sha256=policy_sha)
        if {row['name'] for row in retained['files']} != expected:
            raise ValueError('retained signature roster differs from earlier phase')
        for row in retained['files']:
            actual=verify(member(root,row['name']),policy,args.signtool)
            if any(actual[key]!=row[key] for key in ('bytes','sha256')):
                raise ValueError('retained signed bytes changed before phase join')
            proofs.append(row)
    for path in targets:
        if args.operation == 'sign-msi' and path in app_payloads:
            proof = sign_app_msi(path, policy, args.signtool, app_payloads[path])
        else:
            proof = operation(path, policy, args.signtool)
            if args.operation == 'sign-msi':
                # This readback occurs after the final container signature.
                proof = verify_msi_payload(path, policy, args.signtool,
                    root / 'canonical/native/abstraction_ipc.dll', signed_container=False, container_proof=proof,
                    canonical_appmodel=canonical_appmodel_member(root / 'canonical/native', path, args.native_family))
        proofs.append(dict(proof, name=Path(os.path.relpath(path, root)).as_posix()))
    receipt = {'schema': 1, 'policy_sha256': hashlib.sha256(args.policy.read_bytes()).hexdigest(), 'result': 'pass', 'files': proofs}
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    if args.native_roster:
        native_family_environment(args.github_env, args.native_family)
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
    if argv and argv[0] == 'diagnostic-host':
        return diagnostic_main(argv[1:])
    if argv and argv[0] == 'consume':
        return consume_main(argv[1:])
    if argv and argv[0] not in ('sign', 'verify', '--help', '-h'):
        return phase_main(argv)
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        'Hosted owner phases: prepare-tools, check-native-source, sign-pe, verify-pe, '
        'sign-msi, verify-msis, verify-language, prepare-chain, copy-chain, sign-bundle, verify-bundle, '
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
