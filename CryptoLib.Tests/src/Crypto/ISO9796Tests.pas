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

unit ISO9796Tests;

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
  ClpBigInteger,
  ClpEncoders,
  ClpRsaEngine,
  ClpIRsaEngine,
  ClpISO9796d1Encoding,
  ClpIISO9796d1Encoding,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpIAsymmetricBlockCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  AsymmetricTestVectors;

type

  TTestISO9796 = class(TCryptoLibAlgorithmTestCase)
  private
    function IsSameAs(const a: TCryptoLibByteArray; off: Int32;
      const b: TCryptoLibByteArray): Boolean;
    procedure RunVectorTest(const ATestId: string);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestISO9796d1_Test1;
    procedure TestISO9796d1_Test2;
    procedure TestISO9796d1_Test3;

  end;

implementation

{ TTestISO9796 }

procedure TTestISO9796.SetUp;
begin
  inherited;
end;

procedure TTestISO9796.TearDown;
begin
  inherited;
end;

function TTestISO9796.IsSameAs(const a: TCryptoLibByteArray; off: Int32;
  const b: TCryptoLibByteArray): Boolean;
var
  i: Int32;
begin
  if (System.Length(a) - off) <> System.Length(b) then
  begin
    Result := False;
    Exit;
  end;

  for i := 0 to System.Length(b) - 1 do
  begin
    if a[i + off] <> b[i] then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

procedure TTestISO9796.RunVectorTest(const ATestId: string);
var
  LRow: TIso9796VectorRow;
  LMod, LPub, LPri: TBigInteger;
  LMsg, LExpectedSig, LData: TCryptoLibByteArray;
  LPubParameters, LPrivParameters: IRsaKeyParameters;
  LRsa: IRsaEngine;
  LEng: IISO9796d1Encoding;
begin
  LRow := TIso9796Vectors.GetRow(ATestId);
  LMod := TBigInteger.Create(LRow.ModulusHex, 16);
  LPub := TBigInteger.Create(LRow.PubExpHex, 16);
  LPri := TBigInteger.Create(LRow.PriExpHex, 16);
  LMsg := THexEncoder.Decode(LRow.MessageHex);
  LExpectedSig := TIso9796Vectors.ComputeExpectedSignature(LRow);

  LPubParameters := TRsaKeyParameters.Create(False, LMod, LPub);
  LPrivParameters := TRsaKeyParameters.Create(True, LMod, LPri);
  LRsa := TRsaEngine.Create();
  LEng := TISO9796d1Encoding.Create(LRsa as IAsymmetricBlockCipher);

  LEng.Init(True, LPrivParameters);
  if LRow.PadBits > 0 then
    LEng.SetPadBits(LRow.PadBits);

  LData := LEng.ProcessBlock(LMsg, 0, System.Length(LMsg));

  LEng.Init(False, LPubParameters);

  if SameText(LRow.GenerationCompare, 'dataOffset') then
    CheckTrue(IsSameAs(LData, LRow.SigCompareOffset, LExpectedSig),
      'failed ISO9796-1 generation ' + ATestId)
  else if SameText(LRow.GenerationCompare, 'sigOffset') then
    CheckTrue(IsSameAs(LExpectedSig, LRow.SigCompareOffset, LData),
      'failed ISO9796-1 generation ' + ATestId)
  else
    CheckTrue(AreEqual(LExpectedSig, LData),
      'failed ISO9796-1 generation ' + ATestId);

  LData := LEng.ProcessBlock(LData, 0, System.Length(LData));

  if LRow.MsgCompareOffset > 0 then
    CheckTrue(IsSameAs(LMsg, LRow.MsgCompareOffset, LData),
      'failed ISO9796-1 retrieve ' + ATestId)
  else
    CheckTrue(AreEqual(LMsg, LData),
      'failed ISO9796-1 retrieve ' + ATestId);
end;

procedure TTestISO9796.TestISO9796d1_Test1;
begin
  RunVectorTest('Test1');
end;

procedure TTestISO9796.TestISO9796d1_Test2;
begin
  RunVectorTest('Test2');
end;

procedure TTestISO9796.TestISO9796d1_Test3;
begin
  RunVectorTest('Test3');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestISO9796);
{$ELSE}
  RegisterTest(TTestISO9796.Suite);
{$ENDIF FPC}

end.
