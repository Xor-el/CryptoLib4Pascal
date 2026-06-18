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

unit RspTxtVectorParserTests;

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
  RspTxtVectorParser,
  PqcTestVectors,
  CryptoLibTestBase;

type
  TTestRspTxtVectorParser = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestParserSmoke;
  end;

implementation

type
  TSmokeRspTxtCallback = class(TRspTxtVectorCallback)
  strict private
  var
    FCount: Int32;
    FTestCase: TTestRspTxtVectorParser;
  public
    constructor Create(ATestCase: TTestRspTxtVectorParser);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
    property Count: Int32 read FCount;
  end;

{ TSmokeRspTxtCallback }

constructor TSmokeRspTxtCallback.Create(ATestCase: TTestRspTxtVectorParser);
begin
  inherited Create;
  FTestCase := ATestCase;
  FCount := 0;
end;

procedure TSmokeRspTxtCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTestCase.CheckTrue(AData.ContainsKey('parameterSet'),
    'parameterSet field expected');
  Inc(FCount);
end;

{ TTestRspTxtVectorParser }

procedure TTestRspTxtVectorParser.TestParserSmoke;
var
  LCallback: TSmokeRspTxtCallback;
begin
  LCallback := TSmokeRspTxtCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlKem/ML-KEM-keyGen.txt', LCallback);
    CheckTrue(LCallback.Count > 0, 'expected at least one vector record');
  finally
    LCallback.Free;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TTestRspTxtVectorParser);
{$ELSE}
RegisterTest(TTestRspTxtVectorParser.Suite);
{$ENDIF FPC}

end.
