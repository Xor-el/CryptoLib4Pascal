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

unit ParseTests;

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
  ClpAsn1Parsers,
  ClpIAsn1Parsers,
  ClpAsn1Objects,
  ClpIAsn1Core,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TParseTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FLongTagged: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestLongTag;
    procedure TestEmptyInputRejectedCleanly;
    procedure TestTruncatedOctetStringParserRejectedCleanly;
  end;

implementation

{ TParseTest }

procedure TParseTest.SetUp;
begin
  inherited;
  FLongTagged := THexEncoder.Decode('9f1f023330');
end;

procedure TParseTest.TearDown;
begin
  FLongTagged := nil;
  inherited;
end;

procedure TParseTest.TestEmptyInputRejectedCleanly;
begin
  // Nil/empty input must not leak an undeclared exception from nil type naming
  // in CheckedCast — callers must get a predictable outcome, not an access violation.
  CheckTrue(TAsn1Sequence.GetInstance(nil) = nil);
end;

procedure TParseTest.TestLongTag;
var
  LAIn: IAsn1StreamParser;
  LTagged: IAsn1TaggedObjectParser;
begin
  LAIn := TAsn1StreamParser.Create(FLongTagged);
  LTagged := LAIn.ReadObject() as IAsn1TaggedObjectParser;

  CheckTrue(LTagged.HasContextTag(31), 'Expected context tag 31');
end;

procedure TParseTest.TestTruncatedOctetStringParserRejectedCleanly;
var
  LTruncated: TCryptoLibByteArray;
  LParser: IAsn1StreamParser;
  LObj: IAsn1Convertible;
begin
  // A definite-length OCTET STRING whose declared length exceeds available bytes
  // is parsed lazily; forcing ToAsn1Object must surface EAsn1ParsingCryptoLibException like
  // sibling parsers — not EInvalidOperationCryptoLibException that callers would miss.
  // 04 20 = OCTET STRING length 32, only 4 content bytes follow.
  LTruncated := THexEncoder.Decode('042001020304');
  LParser := TAsn1StreamParser.Create(LTruncated);
  LObj := LParser.ReadObject();
  try
    LObj.ToAsn1Object();
    Fail('expected EAsn1ParsingCryptoLibException');
  except
    on E: EAsn1ParsingCryptoLibException do
      ;
  else
    raise;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TParseTest);
{$ELSE}
  RegisterTest(TParseTest.Suite);
{$ENDIF FPC}

end.
