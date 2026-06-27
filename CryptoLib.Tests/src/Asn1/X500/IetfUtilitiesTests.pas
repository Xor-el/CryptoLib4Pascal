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

unit IetfUtilitiesTests;

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
  ClpIetfUtilities,
  CryptoLibTestBase;

type
  TIetfUtilitiesTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestValueToString;
  end;

implementation

{ TIetfUtilitiesTest }

procedure TIetfUtilitiesTest.TestValueToString;
var
  LCommas: TStringBuilder;
  LEscaped: String;
  LI, LN: Int32;
begin
  TIetfUtilities.ValueToString(TDerUtf8String.Create(' ') as IDerUtf8String);

  CheckEquals('abc', TIetfUtilities.ValueToString(TDerUtf8String.Create('abc') as IDerUtf8String),
    'plain');
  CheckEquals('a\,b', TIetfUtilities.ValueToString(TDerUtf8String.Create('a,b') as IDerUtf8String),
    'comma');
  CheckEquals('\,\"\\\+\=\<\>\;',
    TIetfUtilities.ValueToString(TDerUtf8String.Create(',"\+=<>;') as IDerUtf8String),
    'all specials');
  CheckEquals('\ ab', TIetfUtilities.ValueToString(TDerUtf8String.Create(' ab') as IDerUtf8String),
    'leading space');
  CheckEquals('ab\ ', TIetfUtilities.ValueToString(TDerUtf8String.Create('ab ') as IDerUtf8String),
    'trailing space');
  CheckEquals('\ ab\ ', TIetfUtilities.ValueToString(TDerUtf8String.Create(' ab ') as IDerUtf8String),
    'leading+trailing space');
  CheckEquals('\ \ \ ', TIetfUtilities.ValueToString(TDerUtf8String.Create('   ') as IDerUtf8String),
    'all spaces');
  CheckEquals('a b', TIetfUtilities.ValueToString(TDerUtf8String.Create('a b') as IDerUtf8String),
    'interior space kept');
  CheckEquals('\#abc', TIetfUtilities.ValueToString(TDerUtf8String.Create('#abc') as IDerUtf8String),
    'leading hash');
  CheckEquals('a#b', TIetfUtilities.ValueToString(TDerUtf8String.Create('a#b') as IDerUtf8String),
    'non-leading hash kept');

  LN := 100000;
  LCommas := TStringBuilder.Create(LN);
  try
    for LI := 0 to LN - 1 do
      LCommas.Append(',');
    LEscaped := TIetfUtilities.ValueToString(TDerUtf8String.Create(LCommas.ToString()) as IDerUtf8String);
    CheckEquals(2 * LN, System.Length(LEscaped), 'large all-comma value fully escaped');
  finally
    LCommas.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TIetfUtilitiesTest);
{$ELSE}
  RegisterTest(TIetfUtilitiesTest.Suite);
{$ENDIF FPC}

end.
