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
  ClpAsn1Objects,
  ClpIAsn1Objects,
  CryptoLibTestBase;

type
  TTestParse = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FlongTagged: TBytes;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestParse;

  end;

implementation

{ TTestParse }

procedure TTestParse.SetUp;
begin
  inherited;
  FlongTagged := DecodeHex('9f1f023330');
end;

procedure TTestParse.TearDown;
begin
  inherited;

end;

procedure TTestParse.TestParse;
var
  aIn: IAsn1StreamParser;
  tagged: IAsn1TaggedObjectParser;
begin
  aIn := TAsn1StreamParser.Create(FlongTagged);
  tagged := aIn.ReadObject() as IAsn1TaggedObjectParser;

  CheckEquals(31, tagged.TagNo);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestParse);
{$ELSE}
  RegisterTest(TTestParse.Suite);
{$ENDIF FPC}

end.
