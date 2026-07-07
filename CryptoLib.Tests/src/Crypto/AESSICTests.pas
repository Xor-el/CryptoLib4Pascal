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

unit AESSICTests;

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
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  SymmetricBlockVectors;

type

  /// <summary>
  /// Test vectors based on NIST Special Publication 800-38A, <br />
  /// "Recommendation for Block Cipher Modes of Operation"
  /// </summary>
  TTestAESSIC = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FKeys, FPlain: TCryptoLibMatrixByteArray;
    FCipher: TCryptoLibGenericArray<TCryptoLibMatrixByteArray>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestAESSIC;
    /// <summary>
    /// Exercises the AES-NI 8-wide CTR fast path (ICtrBlockCipher) on buffers
    /// large enough to hit it, cross-checked against an independent
    /// ECB-of-counter-blocks keystream reference, plus a decrypt round-trip.
    /// Covers all three key sizes and block counts that span below-batch,
    /// exact-batch, batch+tail and multi-batch, with an IV that forces
    /// big-endian counter carries across byte boundaries.
    /// </summary>
    procedure TestAESCTRLargeBufferMatchesEcbReference;

  end;

implementation

{ TTestAESSIC }

procedure TTestAESSIC.SetUp;
var
  LBaseBand: TCryptoLibGenericArray<TNistAesVectorRow>;
  LBand128, LBand192, LBand256: TCryptoLibGenericArray<TNistAesVectorRow>;
begin
  inherited;

  LBaseBand := TNistSp80038aAesVectors.GetRows('Ctr', 128);
  LBand128 := LBaseBand;
  LBand192 := TNistSp80038aAesVectors.GetRows('Ctr', 192);
  LBand256 := TNistSp80038aAesVectors.GetRows('Ctr', 256);

  FKeys := TCryptoLibMatrixByteArray.Create(
    DecodeHex(LBand128[0].Key),
    DecodeHex(LBand192[0].Key),
    DecodeHex(LBand256[0].Key));

  FPlain := TCryptoLibMatrixByteArray.Create(
    DecodeHex(LBaseBand[0].Input),
    DecodeHex(LBaseBand[1].Input),
    DecodeHex(LBaseBand[2].Input),
    DecodeHex(LBaseBand[3].Input));

  FCipher := TCryptoLibGenericArray<TCryptoLibMatrixByteArray>.Create(
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(LBand128[0].Output),
      DecodeHex(LBand128[1].Output),
      DecodeHex(LBand128[2].Output),
      DecodeHex(LBand128[3].Output)),
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(LBand192[0].Output),
      DecodeHex(LBand192[1].Output),
      DecodeHex(LBand192[2].Output),
      DecodeHex(LBand192[3].Output)),
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(LBand256[0].Output),
      DecodeHex(LBand256[1].Output),
      DecodeHex(LBand256[2].Output),
      DecodeHex(LBand256[3].Output)));
end;

procedure TTestAESSIC.TearDown;
begin
  inherited;
end;

procedure TTestAESSIC.TestAESSIC;
var
  LC: IBufferedCipher;
  LI, LJ: Int32;
  LSKey, LSk: IKeyParameter;
  LEnc, LCrypt: TBytes;
  LKeySizes: array [0 .. 2] of Int32;
  LBand: TCryptoLibGenericArray<TNistAesVectorRow>;
begin
  LKeySizes[0] := 128;
  LKeySizes[1] := 192;
  LKeySizes[2] := 256;

  LC := TCipherUtilities.GetCipher('AES/SIC/NoPadding');

  LI := 0;
  while LI <> System.Length(FKeys) do
  begin
    LBand := TNistSp80038aAesVectors.GetRows('Ctr', LKeySizes[LI]);
    LSKey := TParameterUtilities.CreateKeyParameter('AES', FKeys[LI]);
    LC.Init(True, TParametersWithIV.Create(LSKey,
      DecodeHex(LBand[0].IV)) as IParametersWithIV);

    LJ := 0;
    while LJ <> System.Length(FPlain) do
    begin
      LEnc := LC.ProcessBytes(FPlain[LJ]);
      if (not AreEqual(LEnc, FCipher[LI, LJ])) then
      begin
        Fail('AESSIC encrypt failed: key ' + IntToStr(LI) + ' block ' +
          IntToStr(LJ));
      end;
      System.Inc(LJ);
    end;

    LC.Init(False, TParametersWithIV.Create(LSKey,
      DecodeHex(LBand[0].IV)) as IParametersWithIV);

    LJ := 0;
    while LJ <> System.Length(FPlain) do
    begin
      LEnc := LC.ProcessBytes(FCipher[LI, LJ]);
      if (not AreEqual(LEnc, FPlain[LJ])) then
      begin
        Fail('AESSIC decrypt failed: key ' + IntToStr(LI) + ' block ' +
          IntToStr(LJ));
      end;
      System.Inc(LJ);
    end;
    System.Inc(LI);
  end;

  LC := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  LSk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex(TNistSp80038aAesVectors.GetRows('Ctr', 128)[0].Key));

  LC.Init(True, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(DecodeHex('00000000000000000000000000000000'));

  if (not AreEqual(LCrypt, DecodeHex('D23513162B02D0F72A43A2FE4A5F97AB'))) then
  begin
    Fail('AESSIC failed test 2');
  end;

  LC := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  LSk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex(TNistSp80038aAesVectors.GetRows('Ctr', 128)[0].Key));

  LC.Init(True, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(DecodeHex('12345678'));

  LC.Init(False, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(LCrypt);

  if (not AreEqual(LCrypt, DecodeHex('12345678'))) then
  begin
    Fail('AESSIC failed partial test');
  end;

end;

// Big-endian whole-counter increment, identical to TSicBlockCipher's.
procedure IncCounterBE(const ACounter: TBytes);
var
  Lk: Int32;
begin
  Lk := System.Length(ACounter) - 1;
  while Lk >= 0 do
  begin
    ACounter[Lk] := Byte(ACounter[Lk] + 1);
    if ACounter[Lk] <> 0 then
      Break;
    System.Dec(Lk);
  end;
end;

procedure TTestAESSIC.TestAESCTRLargeBufferMatchesEcbReference;
const
  BLOCK = 16;
  // Below one 8-block batch, exactly one batch, batch + tail, multi-batch exact.
  CBlockCounts: array [0 .. 3] of Int32 = (7, 8, 61, 64);
var
  LKeyBytes: array [0 .. 2] of Int32;
  LKi, LNi, LN, Li, Lj, LLen: Int32;
  LKey, LIV, LPlain, LCounters, LKeystream, LRef, LCtr, LBack, LCtrBlk: TBytes;
  LKeyParam: IKeyParameter;
  LEcb, LCtrCipher: IBufferedCipher;
begin
  LKeyBytes[0] := 16;
  LKeyBytes[1] := 24;
  LKeyBytes[2] := 32;

  for LKi := 0 to 2 do
  begin
    System.SetLength(LKey, LKeyBytes[LKi]);
    for Li := 0 to System.High(LKey) do
      LKey[Li] := Byte((Li * 11) + (LKi * 7) + 1);
    LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LKey);

    // Full 16-byte IV whose low bytes force per-block carries across byte
    // boundaries (and through the low-32 region) as the counter advances.
    LIV := DecodeHex('000102030405060708090A0B0CFFFFFE');

    for LNi := 0 to System.High(CBlockCounts) do
    begin
      LN := CBlockCounts[LNi];
      LLen := LN * BLOCK;

      System.SetLength(LPlain, LLen);
      for Li := 0 to LLen - 1 do
        LPlain[Li] := Byte((Li * 13) xor (Li shr 3) xor (LN * 5));

      // Independent reference: keystream = ECB(counter_i), ct = pt xor keystream.
      System.SetLength(LCounters, LLen);
      LCtrBlk := System.Copy(LIV, 0, BLOCK);
      for Li := 0 to LN - 1 do
      begin
        System.Move(LCtrBlk[0], LCounters[Li * BLOCK], BLOCK);
        IncCounterBE(LCtrBlk);
      end;
      LEcb := TCipherUtilities.GetCipher('AES/ECB/NoPadding');
      LEcb.Init(True, LKeyParam);
      LKeystream := LEcb.DoFinal(LCounters);
      System.SetLength(LRef, LLen);
      for Lj := 0 to LLen - 1 do
        LRef[Lj] := Byte(LPlain[Lj] xor LKeystream[Lj]);

      // CTR fast path over the whole buffer (hits the 8-wide kernel for LN >= 8).
      LCtrCipher := TCipherUtilities.GetCipher('AES/CTR/NoPadding');
      LCtrCipher.Init(True, TParametersWithIV.Create(LKeyParam, LIV)
        as IParametersWithIV);
      LCtr := LCtrCipher.DoFinal(LPlain);
      if not AreEqual(LCtr, LRef) then
        Fail(Format('CTR fast path != ECB reference (key %d bytes, %d blocks)',
          [LKeyBytes[LKi], LN]));

      // Decrypt round-trip must recover the plaintext.
      LCtrCipher.Init(False, TParametersWithIV.Create(LKeyParam, LIV)
        as IParametersWithIV);
      LBack := LCtrCipher.DoFinal(LCtr);
      if not AreEqual(LBack, LPlain) then
        Fail(Format('CTR round-trip failed (key %d bytes, %d blocks)',
          [LKeyBytes[LKi], LN]));
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAESSIC);
{$ELSE}
  RegisterTest(TTestAESSIC.Suite);
{$ENDIF FPC}

end.
