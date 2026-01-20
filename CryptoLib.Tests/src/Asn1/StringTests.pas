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
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// X.690 test example
  /// </summary>
  TStringTest = class(TCryptoLibAlgorithmTestCase)

  published
    procedure TestString;

  end;

implementation

{ TStringTest }

procedure TStringTest.TestString;
var
  LDerBit: IDerBitString;
  LUniversal: IDerUniversalString;
  LT61: IDerT61String;
  LT61Bytes: TCryptoLibByteArray;
  LT61String: String;
  LEncoding: TEncoding;
begin
  LDerBit := TDerBitString.Create(TCryptoLibByteArray.Create($01, $23, $45, $67, $89, $AB, $CD, $EF));

  if not(LDerBit.GetString() = '#0309000123456789ABCDEF') then
  begin
    Fail('DerBitString.GetString() result incorrect');
  end;

  if not(LDerBit.ToString() = '#0309000123456789ABCDEF') then
  begin
    Fail('DerBitString.ToString() result incorrect');
  end;

  LDerBit := TDerBitString.Create(TCryptoLibByteArray.Create($FE, $DC, $BA, $98, $76, $54, $32, $10));

  if not(LDerBit.GetString() = '#030900FEDCBA9876543210') then
  begin
    Fail('DerBitString.GetString() result incorrect');
  end;

  if not(LDerBit.ToString() = '#030900FEDCBA9876543210') then
  begin
    Fail('DerBitString.ToString() result incorrect');
  end;

  LUniversal := TDerUniversalString.Create(TCryptoLibByteArray.Create($01, $23, $45, $67, $89, $AB, $CD, $EF));

  if not(LUniversal.GetString() = '#1C080123456789ABCDEF') then
  begin
    Fail('DerUniversalString.GetString() result incorrect');
  end;

  if not(LUniversal.ToString() = '#1C080123456789ABCDEF') then
  begin
    Fail('DerUniversalString.ToString() result incorrect');
  end;

  LUniversal := TDerUniversalString.Create(TCryptoLibByteArray.Create($FE, $DC, $BA, $98, $76, $54, $32, $10));

  if not(LUniversal.GetString() = '#1C08FEDCBA9876543210') then
  begin
    Fail('DerUniversalString.GetString() result incorrect');
  end;

  if not(LUniversal.ToString() = '#1C08FEDCBA9876543210') then
  begin
    Fail('DerUniversalString.ToString() result incorrect');
  end;

  LT61Bytes := TCryptoLibByteArray.Create($FF, $FE, $FD, $FC, $FB, $FA, $F9, $F8);
  LEncoding := TEncoding.GetEncoding('iso-8859-1');
  try
    LT61String := TConverters.ConvertBytesToString(LT61Bytes, LEncoding);
  finally
    LEncoding.Free;
  end;

  LT61 := TDerT61String.Create(LT61Bytes);

  if not(LT61.GetString() = LT61String) then
  begin
    Fail('DerT61String.GetString() result incorrect');
  end;

  if not(LT61.ToString() = LT61String) then
  begin
    Fail('DerT61String.ToString() result incorrect');
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TStringTest);
{$ELSE}
RegisterTest(TStringTest.Suite);
{$ENDIF FPC}

end.
