{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit BitStringTests;

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
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TBitStringTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure EncodingCheck(const ADerData, ADlData: TCryptoLibByteArray);

  published
    procedure TestBitString;
    procedure TestZeroLengthStrings;
    procedure TestRandomPadBits;

  end;

implementation

{ TBitStringTest }

procedure TBitStringTest.TestRandomPadBits;
var
  LTest, LTest1, LTest2, LTest3, LTest4: TCryptoLibByteArray;
begin
  LTest := DecodeHex('030206c0');
  LTest1 := DecodeHex('030206f0');
  LTest2 := DecodeHex('030206c1');
  LTest3 := DecodeHex('030206c7');
  LTest4 := DecodeHex('030206d1');

  EncodingCheck(LTest, LTest1);
  EncodingCheck(LTest, LTest2);
  EncodingCheck(LTest, LTest3);
  EncodingCheck(LTest, LTest4);
end;

procedure TBitStringTest.TestZeroLengthStrings;
var
  LS1, LS2: IDerBitString;
  LDerBit: IDerBitString;
  LEmptyBytes: TCryptoLibByteArray;
begin
  LS1 := TDerBitString.CreateEmpty();

  LS1.GetBytes();

  LDerBit := TDerBitString.GetInstance
    (TAsn1Object.FromByteArray(LS1.GetEncoded()));

  if not AreEqual(LS1.GetEncoded(), DecodeHex('030100')) then
  begin
    Fail('zero encoding wrong');
  end;

  try
    TDerBitString.Create(nil, 1);
    Fail('exception not thrown');
  except
    on E: EArgumentNilCryptoLibException do
    begin
      // Expected
    end;
  end;

  try
    System.SetLength(LEmptyBytes, 1);
    TDerBitString.Create(LEmptyBytes, 8);
    Fail('exception not thrown');
  except
    on E: EArgumentCryptoLibException do
    begin
      // Expected
    end;
  end;

  LS2 := TDerBitString.Create(0);
  if not AreEqual(LS1.GetEncoded(), LS2.GetEncoded()) then
  begin
    Fail('zero encoding wrong');
  end;
end;

procedure TBitStringTest.EncodingCheck(const ADerData, ADlData: TCryptoLibByteArray);
var
  LDl: IDerBitString;
  LDer: IDerBitString;
begin
  if AreEqual(ADerData, TAsn1Object.FromByteArray(ADlData).GetEncoded()) then
  begin
    Fail('failed DL check');
  end;
  LDl := TDLBitString.GetInstance(ADlData);

  CheckTrue(Supports(LDl, IDLBitString), 'DL test failed');
  if not AreEqual(ADerData, TAsn1Object.FromByteArray(ADlData).GetDerEncoded())
  then
  begin
    Fail('failed DER check');
  end;
  try
    TDerBitString.GetInstance(ADlData);
  except
    on E: EArgumentCryptoLibException do
    begin
      Fail('failed DL encoding conversion');
    end;
  end;
  LDer := TDerBitString.GetInstance(ADerData);
  CheckTrue(Supports(LDer, IDerBitString), 'DER test failed');
end;


procedure TBitStringTest.TestBitString;
var
  LK: IKeyUsage;
begin
  LK := TKeyUsage.Create(TKeyUsage.DigitalSignature);
  if (LK.GetBytes()[0] <> Byte(TKeyUsage.DigitalSignature)) or
    ((LK as IDerBitString).PadBits <> 7) then
  begin
    Fail('failed digitalSignature');
  end;

  LK := TKeyUsage.Create(TKeyUsage.NonRepudiation);
  if (LK.GetBytes()[0] <> Byte(TKeyUsage.NonRepudiation)) or
    ((LK as IDerBitString).PadBits <> 6) then
  begin
    Fail('failed nonRepudiation');
  end;

  LK := TKeyUsage.Create(TKeyUsage.KeyEncipherment);
  if (LK.GetBytes()[0] <> Byte(TKeyUsage.KeyEncipherment)) or
    ((LK as IDerBitString).PadBits <> 5) then
  begin
    Fail('failed keyEncipherment');
  end;

  LK := TKeyUsage.Create(TKeyUsage.CrlSign);
  if (LK.GetBytes()[0] <> Byte(TKeyUsage.CrlSign)) or
    ((LK as IDerBitString).PadBits <> 1) then
  begin
    Fail('failed cRLSign');
  end;

  LK := TKeyUsage.Create(TKeyUsage.DecipherOnly);
  if (LK.GetBytes()[1] <> Byte(TKeyUsage.DecipherOnly shr 8)) or
    ((LK as IDerBitString).PadBits <> 7) then
  begin
    Fail('failed decipherOnly');
  end;

  try
    TAsn1Object.FromByteArray((TDerBitString.CreateEmpty as IDerBitString).GetEncoded());
  except
    on E: Exception do
    begin
      Fail(E.ToString());
    end;
  end;

end;

initialization

{$IFDEF FPC}
RegisterTest(TBitStringTest);
{$ELSE}
RegisterTest(TBitStringTest.Suite);
{$ENDIF FPC}

end.
