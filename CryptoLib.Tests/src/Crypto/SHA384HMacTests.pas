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

unit SHA384HMacTests;

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
  /// SHA384 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestSHA384HMac = class(TCryptoLibAlgorithmTestCase)
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSHA384HMac;

  end;

implementation

{ TTestSHA384HMac }

procedure TTestSHA384HMac.SetUp;
begin
  inherited;
end;

procedure TTestSHA384HMac.TearDown;
begin
  inherited;
end;

procedure TTestSHA384HMac.TestSHA384HMac;
var
  LRows: TCryptoLibGenericArray<THmacRfc2202Row>;
  LRow: THmacRfc2202Row;
  LHmac: IMac;
  LResBuf, LM, LM2: TBytes;
  LI, LVector: Int32;
begin
  LRows := THmacVectors.GetRfc2202Rows('SHA384');
  LHmac := THMac.Create(TDigestUtilities.GetDigest('SHA-384'));
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
  RegisterTest(TTestSHA384HMac);
{$ELSE}
  RegisterTest(TTestSHA384HMac.Suite);
{$ENDIF FPC}

end.
