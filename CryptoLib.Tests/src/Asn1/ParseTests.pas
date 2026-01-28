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
  end;

implementation

{ TParseTest }

procedure TParseTest.SetUp;
begin
  inherited;
  FLongTagged := THex.Decode('9f1f023330');
end;

procedure TParseTest.TearDown;
begin
  FLongTagged := nil;
  inherited;
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

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TParseTest);
{$ELSE}
  RegisterTest(TParseTest.Suite);
{$ENDIF FPC}

end.
