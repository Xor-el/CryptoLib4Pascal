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

unit IPAddressUtilitiesTests;

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
  ClpIPAddressUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TIPAddressUtilitiesTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FValidIPv4: TCryptoLibStringArray;
      FInvalidIPv4: TCryptoLibStringArray;
      FValidIPv6: TCryptoLibStringArray;
      FInvalidIPv6: TCryptoLibStringArray;

    procedure SetUpTestData;
    procedure DoTestIP(const AValid, AInvalid: TCryptoLibStringArray);

  protected
    procedure SetUp; override;

  published
    procedure TestIPv4;
    procedure TestIPv6;

  end;

implementation

{ TIPAddressUtilitiesTest }

procedure TIPAddressUtilitiesTest.SetUpTestData;
begin
  System.SetLength(FValidIPv4, 3);
  FValidIPv4[0] := '0.0.0.0';
  FValidIPv4[1] := '255.255.255.255';
  FValidIPv4[2] := '192.168.0.0';

  System.SetLength(FInvalidIPv4, 5);
  FInvalidIPv4[0] := '0.0.0.0.1';
  FInvalidIPv4[1] := '256.255.255.255';
  FInvalidIPv4[2] := '1';
  FInvalidIPv4[3] := 'A.B.C';
  FInvalidIPv4[4] := '1:.4.6.5';

  System.SetLength(FValidIPv6, 3);
  FValidIPv6[0] := '0:0:0:0:0:0:0:0';
  FValidIPv6[1] := 'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF';
  FValidIPv6[2] := '0:1:2:3:FFFF:5:FFFF:1';

  System.SetLength(FInvalidIPv6, 2);
  FInvalidIPv6[0] := '0.0.0.0:1';
  FInvalidIPv6[1] := 'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFFF';
end;

procedure TIPAddressUtilitiesTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TIPAddressUtilitiesTest.DoTestIP(const AValid, AInvalid: TCryptoLibStringArray);
var
  I: Int32;
begin
  for I := 0 to System.Length(AValid) - 1 do
  begin
    if not TIPAddressUtilities.IsValid(AValid[I]) then
    begin
      Fail(Format('Valid input string not accepted: %s.', [AValid[I]]));
    end;
  end;

  for I := 0 to System.Length(AInvalid) - 1 do
  begin
    if TIPAddressUtilities.IsValid(AInvalid[I]) then
    begin
      Fail(Format('Invalid input string accepted: %s.', [AInvalid[I]]));
    end;
  end;
end;

procedure TIPAddressUtilitiesTest.TestIPv4;
begin
  DoTestIP(FValidIPv4, FInvalidIPv4);
end;

procedure TIPAddressUtilitiesTest.TestIPv6;
begin
  DoTestIP(FValidIPv6, FInvalidIPv6);
end;

initialization

{$IFDEF FPC}
RegisterTest(TIPAddressUtilitiesTest);
{$ELSE}
RegisterTest(TIPAddressUtilitiesTest.Suite);
{$ENDIF FPC}

end.
