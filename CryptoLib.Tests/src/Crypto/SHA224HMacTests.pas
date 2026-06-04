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

unit SHA224HMacTests;

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
  ClpKeyParameter,
  ClpHMac,
  ClpIMac,
  ClpDigestUtilities,
  ClpStringUtilities,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  HmacVectors;

type

  /// <summary>
  /// SHA224 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestSHA224HMac = class(TCryptoLibAlgorithmTestCase)
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSHA224HMac;

  end;

implementation

{ TTestSHA224HMac }

procedure TTestSHA224HMac.SetUp;
begin
  inherited;
end;

procedure TTestSHA224HMac.TearDown;
begin
  inherited;
end;

procedure TTestSHA224HMac.TestSHA224HMac;
var
  LRows: TCryptoLibGenericArray<THmacRfc2202Row>;
  LRow: THmacRfc2202Row;
  LHmac: IMac;
  LResBuf, LM, LM2: TBytes;
  LI, LVector: Int32;
begin
  LRows := THmacVectors.GetRfc2202Rows('SHA224');
  LHmac := THMac.Create(TDigestUtilities.GetDigest('SHA-224'));
  SetLength(LResBuf, LHmac.GetMacSize());

  for LI := 0 to High(LRows) do
  begin
    LRow := LRows[LI];
    LM := TConverters.ConvertStringToBytes(LRow.Message, TEncoding.ASCII);
    if TStringUtilities.StartsWith(LRow.Message, '0x', True) then
      LM := DecodeHex(Copy(LRow.Message, 3, Length(LRow.Message) - 2));

    LHmac.Init(TKeyParameter.Create(DecodeHex(LRow.Key)));
    LHmac.BlockUpdate(LM, 0, Length(LM));
    LHmac.DoFinal(LResBuf, 0);

    if not AreEqual(LResBuf, DecodeHex(LRow.ExpectedHex)) then
      Fail('Vector ' + IntToStr(LRow.CaseIndex) + ' failed');
  end;

  LVector := 0;
  LRow := LRows[LVector];
  LM2 := TConverters.ConvertStringToBytes(LRow.Message, TEncoding.ASCII);
  if TStringUtilities.StartsWith(LRow.Message, '0x', True) then
    LM2 := DecodeHex(Copy(LRow.Message, 3, Length(LRow.Message) - 2));

  LHmac.Init(TKeyParameter.Create(DecodeHex(LRow.Key)));
  LHmac.BlockUpdate(LM2, 0, Length(LM2));
  LHmac.DoFinal(LResBuf, 0);
  LHmac.Reset();
  LHmac.BlockUpdate(LM2, 0, Length(LM2));
  LHmac.DoFinal(LResBuf, 0);

  if not AreEqual(LResBuf, DecodeHex(LRow.ExpectedHex)) then
    Fail('Reset with vector ' + IntToStr(LVector) + ' failed');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSHA224HMac);
{$ELSE}
  RegisterTest(TTestSHA224HMac.Suite);
{$ENDIF FPC}

end.
