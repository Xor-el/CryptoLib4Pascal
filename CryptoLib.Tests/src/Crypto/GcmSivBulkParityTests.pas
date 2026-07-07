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

unit GcmSivBulkParityTests;

{$I ..\..\..\CryptoLib\src\Include\CryptoLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpGcmSivBlockCipher,
  ClpIGcmSivBlockCipher,
  ClpAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpFusedKernelRegistry,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// AES-GCM-SIV POLYVAL parity: the fused POLYVAL kernel (used for hashed spans
  /// &gt;= 128 bytes) must produce byte-identical ciphertext+tag to the scalar
  /// fallback across AAD/plaintext lengths around the 8-block boundary.
  /// Cross-comparing fused vs scalar output catches a symmetric POLYVAL bug that
  /// a round-trip (matching wrong tag on both sides) cannot.
  /// </summary>
  TTestGcmSivBulkParity = class(TCryptoLibAlgorithmTestCase)
  strict private
    function GcmSivEncrypt(const AKey, ANonce, AAad, APlain: TBytes;
      AUseFused: Boolean): TBytes;
    function GcmSivDecrypt(const AKey, ANonce, AAad, ACipher: TBytes;
      AUseFused: Boolean): TBytes;
    procedure RunParity(AKeyBytes: Int32; const ALabel: String);
  published
    procedure TestGcmSiv128FusedVsScalarParity;
    procedure TestGcmSiv256FusedVsScalarParity;
  end;

implementation

{ TTestGcmSivBulkParity }

function TTestGcmSivBulkParity.GcmSivEncrypt(const AKey, ANonce, AAad,
  APlain: TBytes; AUseFused: Boolean): TBytes;
var
  LCipher: IGcmSivBlockCipher;
  LSaved: Boolean;
  LLen: Int32;
begin
  LSaved := TFusedKernelGate.ForceDisabled;
  // The fused POLYVAL kernel is resolved during Init (DeriveKeys); the gate must
  // therefore be set BEFORE Init to select the fused or scalar path.
  TFusedKernelGate.ForceDisabled := not AUseFused;
  try
    LCipher := TGcmSivBlockCipher.Create() as IGcmSivBlockCipher;
    LCipher.Init(True, TAeadParameters.Create(TKeyParameter.Create(AKey)
      as IKeyParameter, 128, ANonce, AAad) as ICipherParameters);
    System.SetLength(Result, LCipher.GetOutputSize(System.Length(APlain)));
    LLen := LCipher.ProcessBytes(APlain, 0, System.Length(APlain), nil, 0);
    LLen := LLen + LCipher.DoFinal(Result, 0);
    if LLen <> System.Length(Result) then
      System.SetLength(Result, LLen);
  finally
    TFusedKernelGate.ForceDisabled := LSaved;
  end;
end;

function TTestGcmSivBulkParity.GcmSivDecrypt(const AKey, ANonce, AAad,
  ACipher: TBytes; AUseFused: Boolean): TBytes;
var
  LCipher: IGcmSivBlockCipher;
  LSaved: Boolean;
  LLen: Int32;
begin
  LSaved := TFusedKernelGate.ForceDisabled;
  TFusedKernelGate.ForceDisabled := not AUseFused;
  try
    LCipher := TGcmSivBlockCipher.Create() as IGcmSivBlockCipher;
    LCipher.Init(False, TAeadParameters.Create(TKeyParameter.Create(AKey)
      as IKeyParameter, 128, ANonce, AAad) as ICipherParameters);
    System.SetLength(Result, LCipher.GetOutputSize(System.Length(ACipher)));
    LLen := LCipher.ProcessBytes(ACipher, 0, System.Length(ACipher), nil, 0);
    LLen := LLen + LCipher.DoFinal(Result, 0);
    if LLen <> System.Length(Result) then
      System.SetLength(Result, LLen);
  finally
    TFusedKernelGate.ForceDisabled := LSaved;
  end;
end;

procedure TTestGcmSivBulkParity.RunParity(AKeyBytes: Int32; const ALabel: String);
const
  // Lengths straddling the 8-block (128-byte) fused batch boundary, the 16-byte
  // tail, and multi-batch spans.
  Lengths: array [0 .. 20] of Int32 = (0, 1, 15, 16, 17, 31, 96, 112, 127, 128,
    129, 143, 144, 240, 255, 256, 257, 383, 384, 512, 1000);
var
  LRnd: ISecureRandom;
  LKey, LNonce, LAad, LPlain, LEncFused, LEncScalar, LDec: TBytes;
  LAi, LPi, LIter: Int32;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes(
    'GcmSivBulkParitySeed-' + ALabel, TEncoding.ASCII));

  System.SetLength(LKey, AKeyBytes);
  System.SetLength(LNonce, 12);

  for LAi := 0 to System.Length(Lengths) - 1 do
    for LPi := 0 to System.Length(Lengths) - 1 do
      for LIter := 0 to 1 do
      begin
        LRnd.NextBytes(LKey);
        LRnd.NextBytes(LNonce);

        System.SetLength(LAad, Lengths[LAi]);
        if System.Length(LAad) > 0 then
          LRnd.NextBytes(LAad);
        System.SetLength(LPlain, Lengths[LPi]);
        if System.Length(LPlain) > 0 then
          LRnd.NextBytes(LPlain);

        LEncFused := GcmSivEncrypt(LKey, LNonce, LAad, LPlain, True);
        LEncScalar := GcmSivEncrypt(LKey, LNonce, LAad, LPlain, False);

        // The whole point: fused and scalar POLYVAL must agree byte-for-byte.
        if not AreEqual(LEncFused, LEncScalar) then
          Fail(Format('%s: fused vs scalar ciphertext+tag mismatch ' +
            '(aad=%d plain=%d iter=%d)',
            [ALabel, Lengths[LAi], Lengths[LPi], LIter]));

        // Cross-mode round-trip: the fused encryption must decrypt (and verify)
        // under the scalar path back to the original plaintext.
        LDec := GcmSivDecrypt(LKey, LNonce, LAad, LEncFused, False);
        if not AreEqual(LPlain, LDec) then
          Fail(Format('%s: scalar decrypt of fused ciphertext mismatch ' +
            '(aad=%d plain=%d iter=%d)',
            [ALabel, Lengths[LAi], Lengths[LPi], LIter]));
      end;
end;

procedure TTestGcmSivBulkParity.TestGcmSiv128FusedVsScalarParity;
begin
  RunParity(16, 'AES-128-GCM-SIV');
end;

procedure TTestGcmSivBulkParity.TestGcmSiv256FusedVsScalarParity;
begin
  RunParity(32, 'AES-256-GCM-SIV');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGcmSivBulkParity);
{$ELSE}
  RegisterTest(TTestGcmSivBulkParity.Suite);
{$ENDIF FPC}

end.
