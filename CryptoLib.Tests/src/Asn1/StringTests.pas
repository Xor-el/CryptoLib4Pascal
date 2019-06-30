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

unit StringTests;

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
  ClpConverters,
  CryptoLibTestBase;

type

  /// <summary>
  /// X.690 test example
  /// </summary>
  TTestString = class(TCryptoLibAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestString;

  end;

implementation

{ TTestString }

procedure TTestString.SetUp;
begin
  inherited;

end;

procedure TTestString.TearDown;
begin
  inherited;

end;

procedure TTestString.TestString;
var
  bs: IDerBitString;
  us: IDerUniversalString;
  t61: IDerT61String;
  t61Bytes: TBytes;
  t61String: string;
  LEncoding: TEncoding;
begin
  bs := TDerBitString.Create(TBytes.Create($01, $23, $45, $67, $89, $AB,
    $CD, $EF));

  if (not(bs.GetString() = ('#0309000123456789ABCDEF'))) then
  begin
    Fail('DerBitString.GetString() result incorrect');
  end;

  if (not(bs.ToString() = ('#0309000123456789ABCDEF'))) then
  begin
    Fail('DerBitString.ToString() result incorrect');
  end;

  bs := TDerBitString.Create(TBytes.Create($FE, $DC, $BA, $98, $76, $54,
    $32, $10));

  if (not(bs.GetString() = ('#030900FEDCBA9876543210'))) then
  begin
    Fail('DerBitString.GetString() result incorrect');
  end;

  if (not(bs.ToString() = ('#030900FEDCBA9876543210'))) then
  begin
    Fail('DerBitString.ToString() result incorrect');
  end;

  us := TDerUniversalString.Create(TBytes.Create($01, $23, $45, $67, $89, $AB,
    $CD, $EF));

  if (not(us.GetString() = ('#1C080123456789ABCDEF'))) then
  begin
    Fail('DerUniversalString.GetString() result incorrect');
  end;

  if (not(us.ToString() = ('#1C080123456789ABCDEF'))) then
  begin
    Fail('DerUniversalString.ToString() result incorrect');
  end;

  us := TDerUniversalString.Create(TBytes.Create($FE, $DC, $BA, $98, $76, $54,
    $32, $10));

  if (not(us.GetString() = ('#1C08FEDCBA9876543210'))) then
  begin
    Fail('DerUniversalString.GetString() result incorrect');
  end;

  if (not(us.ToString() = ('#1C08FEDCBA9876543210'))) then
  begin
    Fail('DerUniversalString.ToString() result incorrect');
  end;

  t61Bytes := TBytes.Create($FF, $FE, $FD, $FC, $FB, $FA, $F9, $F8);
  LEncoding := TEncoding.GetEncoding('iso-8859-1');
  try
    t61String := TConverters.ConvertBytesToString(t61Bytes, LEncoding);
  finally
    LEncoding.Free;
  end;

  t61 := TDerT61String.Create(t61Bytes);

  if (not(t61.GetString() = (t61String))) then
  begin
    Fail('DerT61String.GetString() result incorrect');
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestString);
{$ELSE}
  RegisterTest(TTestString.Suite);
{$ENDIF FPC}

end.
