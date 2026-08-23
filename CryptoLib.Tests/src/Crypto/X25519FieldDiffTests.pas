{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit X25519FieldDiffTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpCurveFieldSimd,
  ClpX25519,
  ClpConverters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// Differential safety net for the radix-2^64 ADX X25519 scalar-mult tier: on an
  /// ADX host TX25519.ScalarMult routes through the fused fe64 ladder, so its output
  /// must be byte-identical to the fe51 path (forced via TCurveFieldGate.ForceDisabled)
  /// and match the RFC 7748 vectors. Swept over the RFC vectors, random (scalar,
  /// u-point) pairs, and edge u-coordinates (all-zero, small-order, near-p). Under a
  /// FORCE_SCALAR build (asm off) both paths are the Pascal tier, so the same
  /// assertions cover the Pascal tier's agreement with the vectors too.
  /// </summary>
  TTestX25519FieldDiff = class(TCryptoLibAlgorithmTestCase)
  strict private
    // TX25519.ScalarMult with the fe64 tier gate set to AForceDisabled, restored on
    // return (including on exceptions).
    function ScalarMult(AForceDisabled: Boolean; const AK, AU: TBytes): TBytes;
    // TX25519.ScalarMult with the i386 ADX sub-tier gate set (restored on return).
    function ScalarMultAdx(AAdx32Disabled: Boolean; const AK, AU: TBytes): TBytes;
    // Default tier vs forced-fe51 tier must be byte-identical, and (when given) both
    // must match the reference vector.
    procedure CheckBothTiers(const AK, AU: TBytes; const AExpectedHex, AText: String);
    // i386 ADX kernel vs the plain-mul fe51 kernel must be byte-identical (and match
    // the reference vector when given). A no-op where the ADX kernel does not apply.
    procedure CheckAdx32Tiers(const AK, AU: TBytes; const AExpectedHex, AText: String);
  published
    // Guard: proves the gate is wired - default enables fe64 on an ADX box, forcing
    // disables it, clearing restores the baseline. Makes the parity tests below
    // fe64-vs-fe51 rather than fe51-vs-fe51 where ADX is present.
    procedure TestGateWiring;
    procedure TestRfcVectorsBothTiers;
    procedure TestRandomBothTiers;
    procedure TestEdgePointsBothTiers;
    // i386 radix-2^32 ADX kernel vs plain-mul fe51 (dual path). Skips where the ADX
    // kernel does not apply (non-i386, or no BMI2+ADX).
    procedure TestAdx32VsPlainMulRfc;
    procedure TestAdx32VsPlainMulRandom;
    procedure TestAdx32VsPlainMulEdge;
  end;

implementation

const
  // Edge u-coordinates (little-endian, 32 bytes): all-zero, one, all-FF, p, p-1,
  // 2^255-1, 2^255 (bit 255 masked at decode), and an RFC 7748 small-order point.
  CEdgeU: array [0 .. 7] of String = (
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '0000000000000000000000000000000000000000000000000000000000000080',
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800');

{ TTestX25519FieldDiff }

function TTestX25519FieldDiff.ScalarMult(AForceDisabled: Boolean;
  const AK, AU: TBytes): TBytes;
var
  LSaved: Boolean;
begin
  LSaved := TCurveFieldGate.ForceDisabled;
  TCurveFieldGate.ForceDisabled := AForceDisabled;
  try
    System.SetLength(Result, TX25519.PointSize);
    TX25519.ScalarMult(AK, 0, AU, 0, Result, 0);
  finally
    TCurveFieldGate.ForceDisabled := LSaved;
  end;
end;

procedure TTestX25519FieldDiff.CheckBothTiers(const AK, AU: TBytes;
  const AExpectedHex, AText: String);
var
  LDefault, LForced, LExpected: TBytes;
begin
  LDefault := ScalarMult(False, AK, AU); // fe64 on an ADX box, else fe51 / Pascal
  LForced := ScalarMult(True, AK, AU);   // fe51 / Pascal
  if not AreEqual(LDefault, LForced) then
    Fail(Format('%s: default vs forced-scalar tier outputs differ', [AText]));
  if AExpectedHex <> '' then
  begin
    LExpected := DecodeHex(AExpectedHex);
    CheckTrue(AreEqual(LExpected, LDefault),
      Format('%s: default tier vs reference vector', [AText]));
    CheckTrue(AreEqual(LExpected, LForced),
      Format('%s: forced tier vs reference vector', [AText]));
  end;
end;

function TTestX25519FieldDiff.ScalarMultAdx(AAdx32Disabled: Boolean;
  const AK, AU: TBytes): TBytes;
var
  LSaved: Boolean;
begin
  // Force the fe64 tier off so the per-op fe51 path (where the ADX sub-tier lives)
  // is exercised, and set the ADX sub-tier gate.
  LSaved := TCurveFieldGate.ForceAdx32Disabled;
  TCurveFieldGate.ForceDisabled := True;
  TCurveFieldGate.ForceAdx32Disabled := AAdx32Disabled;
  try
    System.SetLength(Result, TX25519.PointSize);
    TX25519.ScalarMult(AK, 0, AU, 0, Result, 0);
  finally
    TCurveFieldGate.ForceAdx32Disabled := LSaved;
    TCurveFieldGate.ForceDisabled := False;
  end;
end;

procedure TTestX25519FieldDiff.CheckAdx32Tiers(const AK, AU: TBytes;
  const AExpectedHex, AText: String);
var
  LAdx, LPlain, LExpected: TBytes;
begin
  if not TCurveFieldSimd.Adx32Supported then
    Exit; // ADX kernel does not apply on this build/CPU - nothing to cross-check
  LAdx := ScalarMultAdx(False, AK, AU);  // radix-2^32 ADX kernel
  LPlain := ScalarMultAdx(True, AK, AU); // plain-mul fe51 kernel
  if not AreEqual(LAdx, LPlain) then
    Fail(Format('%s: i386 ADX vs plain-mul outputs differ', [AText]));
  if AExpectedHex <> '' then
  begin
    LExpected := DecodeHex(AExpectedHex);
    CheckTrue(AreEqual(LExpected, LAdx),
      Format('%s: ADX kernel vs reference vector', [AText]));
    CheckTrue(AreEqual(LExpected, LPlain),
      Format('%s: plain-mul kernel vs reference vector', [AText]));
  end;
end;

procedure TTestX25519FieldDiff.TestGateWiring;
var
  LSaved, LBaseline: Boolean;
begin
  LSaved := TCurveFieldGate.ForceDisabled;
  try
    TCurveFieldGate.ForceDisabled := False;
    LBaseline := TCurveFieldSimd.Fe64Supported; // True on an ADX x86-64 host
    TCurveFieldGate.ForceDisabled := True;
    CheckTrue(not TCurveFieldSimd.Fe64Supported,
      'gate: ForceDisabled must disable the fe64 tier');
    TCurveFieldGate.ForceDisabled := False;
    CheckTrue(LBaseline = TCurveFieldSimd.Fe64Supported,
      'gate: cleared -> baseline capability restored');
  finally
    TCurveFieldGate.ForceDisabled := LSaved;
  end;
end;

procedure TTestX25519FieldDiff.TestRfcVectorsBothTiers;
begin
  CheckBothTiers(
    DecodeHex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
    DecodeHex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'),
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    'RFC 7748 Vector #1');
  CheckBothTiers(
    DecodeHex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'),
    DecodeHex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'),
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    'RFC 7748 Vector #2');
end;

procedure TTestX25519FieldDiff.TestRandomBothTiers;
var
  LRnd: ISecureRandom;
  LK, LU: TBytes;
  LI: Int32;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes('X25519FieldDiff-Random',
    TEncoding.ASCII));
  System.SetLength(LK, TX25519.ScalarSize);
  System.SetLength(LU, TX25519.PointSize);
  for LI := 1 to 512 do
  begin
    LRnd.NextBytes(LK);
    LRnd.NextBytes(LU);
    CheckBothTiers(LK, LU, '', Format('Random #%d', [LI]));
  end;
end;

procedure TTestX25519FieldDiff.TestEdgePointsBothTiers;
var
  LRnd: ISecureRandom;
  LK, LU: TBytes;
  LEi, LKi: Int32;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes('X25519FieldDiff-Edge',
    TEncoding.ASCII));
  System.SetLength(LK, TX25519.ScalarSize);
  for LEi := 0 to System.Length(CEdgeU) - 1 do
  begin
    LU := DecodeHex(CEdgeU[LEi]);
    for LKi := 1 to 8 do
    begin
      LRnd.NextBytes(LK);
      CheckBothTiers(LK, LU, '', Format('Edge u#%d k#%d', [LEi, LKi]));
    end;
  end;
end;

procedure TTestX25519FieldDiff.TestAdx32VsPlainMulRfc;
begin
  CheckAdx32Tiers(
    DecodeHex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
    DecodeHex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'),
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    'RFC 7748 Vector #1 (ADX)');
  CheckAdx32Tiers(
    DecodeHex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'),
    DecodeHex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'),
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    'RFC 7748 Vector #2 (ADX)');
end;

procedure TTestX25519FieldDiff.TestAdx32VsPlainMulRandom;
var
  LRnd: ISecureRandom;
  LK, LU: TBytes;
  LI: Int32;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes('X25519FieldDiff-Adx32Random',
    TEncoding.ASCII));
  System.SetLength(LK, TX25519.ScalarSize);
  System.SetLength(LU, TX25519.PointSize);
  for LI := 1 to 512 do
  begin
    LRnd.NextBytes(LK);
    LRnd.NextBytes(LU);
    CheckAdx32Tiers(LK, LU, '', Format('ADX Random #%d', [LI]));
  end;
end;

procedure TTestX25519FieldDiff.TestAdx32VsPlainMulEdge;
var
  LRnd: ISecureRandom;
  LK, LU: TBytes;
  LEi, LKi: Int32;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes('X25519FieldDiff-Adx32Edge',
    TEncoding.ASCII));
  System.SetLength(LK, TX25519.ScalarSize);
  for LEi := 0 to System.Length(CEdgeU) - 1 do
  begin
    LU := DecodeHex(CEdgeU[LEi]);
    for LKi := 1 to 8 do
    begin
      LRnd.NextBytes(LK);
      CheckAdx32Tiers(LK, LU, '', Format('ADX Edge u#%d k#%d', [LEi, LKi]));
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX25519FieldDiff);
{$ELSE}
  RegisterTest(TTestX25519FieldDiff.Suite);
{$ENDIF FPC}

end.
