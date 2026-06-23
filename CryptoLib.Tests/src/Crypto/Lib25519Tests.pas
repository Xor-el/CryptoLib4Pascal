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

unit Lib25519Tests;

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
  ClpArrayUtilities,
  ClpISecureRandom,
  ClpLib25519,
  ClpSecureRandom,
  CryptoLibTestBase;

type

  TLib25519Test = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRandom: ISecureRandom;

    function NextBitIndex(ANumBits: Int32): Int32;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDHCompatibility;
    procedure TestDHConsistency;
    procedure TestSignCompatibility;
    procedure TestSignConsistency;
  end;

implementation

{ TLib25519Test }

function TLib25519Test.NextBitIndex(ANumBits: Int32): Int32;
begin
  if ANumBits <= 0 then
    raise EArgumentOutOfRangeException.Create('ANumBits');
  Result := Abs(FRandom.NextInt32()) mod ANumBits;
end;

procedure TLib25519Test.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TLib25519Test.TearDown;
begin
  FRandom := nil;
  inherited;
end;

procedure TLib25519Test.TestDHCompatibility;
var
  LPkA, LPkB, LSkA, LSkB, LK, LKA, LKB: TBytes;
begin
  LPkA := DecodeHex('A7903A3BB3A1F13C8762233FFCD00161F5E02F15A8B481D92AA4C4377CF9751C');
  LPkB := DecodeHex('FE0A4B000F033F5D9B1D87C6035E9197AB603F7F453F3723E61BA8C6FF6F8435');
  LSkA := DecodeHex('B02B0874F3DB3E679200393A95E28B682DFF726CBBFBDADE042ACA2203A477C0');
  LSkB := DecodeHex('A3B650EB7EB3D39486CCCEE16347FEA8951C3E6FE69A162F3029BEF946DA0EC1');
  LK := DecodeHex('B666ECF65932E33E44C962E2007929E081D21BA6EE335A28358835307F935B4D');

  CheckEquals(TLib25519.DHPublicKeyBytes, System.Length(LPkA));
  CheckEquals(TLib25519.DHPublicKeyBytes, System.Length(LPkB));
  CheckEquals(TLib25519.DHSecretKeyBytes, System.Length(LSkA));
  CheckEquals(TLib25519.DHSecretKeyBytes, System.Length(LSkB));
  CheckEquals(TLib25519.DHBytes, System.Length(LK));

  System.SetLength(LKA, TLib25519.DHBytes);
  System.SetLength(LKB, TLib25519.DHBytes);

  TLib25519.DH(LKA, 0, LPkB, 0, LSkA, 0);
  CheckTrue(AreEqual(LK, LKA));

  TLib25519.DH(LKB, 0, LPkA, 0, LSkB, 0);
  CheckTrue(AreEqual(LK, LKB));
end;

procedure TLib25519Test.TestDHConsistency;
var
  LI: Int32;
  LPkA, LPkB, LSkA, LSkB, LKA, LKB: TBytes;
begin
  System.SetLength(LPkA, TLib25519.DHPublicKeyBytes);
  System.SetLength(LPkB, TLib25519.DHPublicKeyBytes);
  System.SetLength(LSkA, TLib25519.DHSecretKeyBytes);
  System.SetLength(LSkB, TLib25519.DHSecretKeyBytes);
  System.SetLength(LKA, TLib25519.DHBytes);
  System.SetLength(LKB, TLib25519.DHBytes);

  for LI := 0 to 9 do
  begin
    TLib25519.DHKeyPair(LPkA, 0, LSkA, 0);
    TLib25519.DHKeyPair(LPkB, 0, LSkB, 0);

    TLib25519.DH(LKA, 0, LPkB, 0, LSkA, 0);
    TLib25519.DH(LKB, 0, LPkA, 0, LSkB, 0);

    CheckTrue(AreEqual(LKA, LKB));
  end;
end;

procedure TLib25519Test.TestSignCompatibility;
var
  LI, LBit, LM1Len, LSm2Len, LM2Len, LM3Len: Int32;
  LPk, LSk, LM, LSm, LM1, LSm2, LM2, LM3, LSm3: TBytes;
begin
  LPk := DecodeHex('B395CDA6065928050FA680D91652A393E70902D7448226B60661277114AA9251');
  LSk := DecodeHex(
    '6BBA3FA19FA4D27B326E44F80570626C67E5419763C6092EBF5DB23D56F0C430' +
    'B395CDA6065928050FA680D91652A393E70902D7448226B60661277114AA9251');
  LM := DecodeHex(
    '60CC404FA136D1CC0894A7C63DAC9DABD5C330B4BDB01154D70B573C492103D3' +
    'CCA003D13CDCE62C4E9D95C07C1E7A71FADE4C11C44737589E9A5CE9EBBD0CFB' +
    'EC4843E31B111DDA21050E829334F5EF41CE54545AFC49C4544B84AE89A4E37A' +
    '2029582C6A62CB064479BC4BAC26E309B47BCC332F798CDC58F8FC1067900F3D' +
    '7C71CD7C3F9517582D716984294B357C6C8F788C966F53E5D741DF4A536CC8D7' +
    '3A9675FA24D506CA54290CC7C1C5A208E66FE4BE1BC8D12918AAD2958784FB15' +
    'ED811A4CC87F16C411D7ED5B2666724C54C91B08745FD792E61C1BB789821A3D' +
    'B7D5DFAA1390D4F91AC0F55263FD8A95CF393696BEBA9AB6F4AC2835490A4010');
  LSm := DecodeHex(
    'CEF1E171064E34EBC6C1DDE98B0A97874E6E1C88EEC62C420CDF2129D0695D07' +
    '6D5D1F773F0E7196927239C5CA371414D62ABC8314BC72D22EF061D5F65DB004' +
    '60CC404FA136D1CC0894A7C63DAC9DABD5C330B4BDB01154D70B573C492103D3' +
    'CCA003D13CDCE62C4E9D95C07C1E7A71FADE4C11C44737589E9A5CE9EBBD0CFB' +
    'EC4843E31B111DDA21050E829334F5EF41CE54545AFC49C4544B84AE89A4E37A' +
    '2029582C6A62CB064479BC4BAC26E309B47BCC332F798CDC58F8FC1067900F3D' +
    '7C71CD7C3F9517582D716984294B357C6C8F788C966F53E5D741DF4A536CC8D7' +
    '3A9675FA24D506CA54290CC7C1C5A208E66FE4BE1BC8D12918AAD2958784FB15' +
    'ED811A4CC87F16C411D7ED5B2666724C54C91B08745FD792E61C1BB789821A3D' +
    'B7D5DFAA1390D4F91AC0F55263FD8A95CF393696BEBA9AB6F4AC2835490A4010');

  CheckEquals(TLib25519.SignPublicKeyBytes, System.Length(LPk));
  CheckEquals(TLib25519.SignSecretKeyBytes, System.Length(LSk));
  CheckEquals(TLib25519.SignBytes + System.Length(LM), System.Length(LSm));

  System.SetLength(LM1, System.Length(LSm));
  CheckTrue(TLib25519.SignOpen(LM1, 0, LM1Len, LSm, 0, System.Length(LSm), LPk, 0));
  CheckEquals(System.Length(LM), LM1Len);
  CheckTrue(AreEqual(LM, CopyOfRange(LM1, 0, LM1Len)));

  System.SetLength(LSm2, System.Length(LSm));
  TLib25519.Sign(LSm2, 0, LSm2Len, LM, 0, System.Length(LM), LSk, 0);
  CheckEquals(System.Length(LSm), LSm2Len);

  System.SetLength(LM2, System.Length(LSm));
  CheckTrue(TLib25519.SignOpen(LM2, 0, LM2Len, LSm2, 0, LSm2Len, LPk, 0));
  CheckEquals(System.Length(LM), LM2Len);
  CheckTrue(AreEqual(LM, CopyOfRange(LM2, 0, LM2Len)));

  LSm3 := Copy(LSm);
  System.SetLength(LM3, System.Length(LSm));
  for LI := 0 to 9 do
  begin
    LBit := NextBitIndex(System.Length(LSm) * 8);
    LSm3[LBit shr 3] := LSm3[LBit shr 3] xor Byte(1 shl (LBit and 7));

    TArrayUtilities.Fill<Byte>(LM3, 0, System.Length(LM3), $FF);
    CheckFalse(TLib25519.SignOpen(LM3, 0, LM3Len, LSm3, 0, System.Length(LSm3), LPk, 0));
    CheckEquals(-1, LM3Len);
    CheckTrue(TArrayUtilities.AreAllZeroes(LM3, 0, System.Length(LSm3)));

    LSm3[LBit shr 3] := LSm3[LBit shr 3] xor Byte(1 shl (LBit and 7));
  end;
end;

procedure TLib25519Test.TestSignConsistency;
var
  LI, LSigBit, LMsgBit, LSmLen, LMlen, LMlen2, LMlen3: Int32;
  LPk, LSk, LMin, LSm, LMout: TBytes;
  LMLength, LSmLength: Int32;
begin
  System.SetLength(LPk, TLib25519.SignPublicKeyBytes);
  System.SetLength(LSk, TLib25519.SignSecretKeyBytes);

  LMLength := 1000;
  LSmLength := LMLength + TLib25519.SignBytes;

  System.SetLength(LMin, LMLength);
  System.SetLength(LSm, LSmLength);
  System.SetLength(LMout, LSmLength);

  for LI := 0 to 9 do
  begin
    FRandom.NextBytes(LMin, 0, LMLength);

    TLib25519.SignKeyPair(LPk, 0, LSk, 0);
    TLib25519.Sign(LSm, 0, LSmLen, LMin, 0, LMLength, LSk, 0);
    CheckEquals(LSmLength, LSmLen);

    CheckTrue(TLib25519.SignOpen(LMout, 0, LMlen, LSm, 0, LSmLen, LPk, 0));
    CheckEquals(LMLength, LMlen);
    CheckTrue(AreEqual(LMin, CopyOfRange(LMout, 0, LMlen)));

    LSigBit := NextBitIndex(TLib25519.SignBytes * 8);
    LSm[LSigBit shr 3] := LSm[LSigBit shr 3] xor Byte(1 shl (LSigBit and 7));

    TArrayUtilities.Fill<Byte>(LMout, 0, System.Length(LMout), $FF);
    CheckFalse(TLib25519.SignOpen(LMout, 0, LMlen2, LSm, 0, LSmLen, LPk, 0));
    CheckEquals(-1, LMlen2);
    CheckTrue(TArrayUtilities.AreAllZeroes(LMout, 0, LSmLen));

    LSm[LSigBit shr 3] := LSm[LSigBit shr 3] xor Byte(1 shl (LSigBit and 7));

    LMsgBit := NextBitIndex(LMLength * 8);
    LSm[TLib25519.SignBytes + (LMsgBit shr 3)] :=
      LSm[TLib25519.SignBytes + (LMsgBit shr 3)] xor Byte(1 shl (LMsgBit and 7));

    TArrayUtilities.Fill<Byte>(LMout, 0, System.Length(LMout), $FF);
    CheckFalse(TLib25519.SignOpen(LMout, 0, LMlen3, LSm, 0, LSmLen, LPk, 0));
    CheckEquals(-1, LMlen3);
    CheckTrue(TArrayUtilities.AreAllZeroes(LMout, 0, LSmLen));

    LSm[TLib25519.SignBytes + (LMsgBit shr 3)] :=
      LSm[TLib25519.SignBytes + (LMsgBit shr 3)] xor Byte(1 shl (LMsgBit and 7));
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TLib25519Test);
{$ELSE}
RegisterTest(TLib25519Test.Suite);
{$ENDIF FPC}

end.
