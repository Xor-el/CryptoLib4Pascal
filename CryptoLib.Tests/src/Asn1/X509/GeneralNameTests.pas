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

unit GeneralNameTests;

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
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TGeneralNameTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FIpv4: TCryptoLibByteArray;
      FIpv4WithMask24: TCryptoLibByteArray;
      FIpv4WithMask14: TCryptoLibByteArray;
      FIpv6a: TCryptoLibByteArray;
      FIpv6b: TCryptoLibByteArray;
      FIpv6c: TCryptoLibByteArray;
      FIpv6d: TCryptoLibByteArray;
      FIpv6e: TCryptoLibByteArray;
      FIpv6f: TCryptoLibByteArray;
      FIpv6g: TCryptoLibByteArray;
      FIpv6h: TCryptoLibByteArray;

    procedure SetUpTestData;
    procedure CheckIPAddressEncoding(const AInputIP: String;
      const AExpectedEncoding: TCryptoLibByteArray; const AMessage: String);

  protected
    procedure SetUp; override;

  published
    procedure TestIPv4;
    procedure TestIPv6;

  end;

implementation

{ TGeneralNameTest }

procedure TGeneralNameTest.SetUpTestData;
begin
  FIpv4 := DecodeHex('87040a090800');
  FIpv4WithMask24 := DecodeHex('87080a090800ffffff00');
  FIpv4WithMask14 := DecodeHex('87080a090800fffc0000');

  FIpv6a := DecodeHex('871020010db885a308d313198a2e03707334');
  FIpv6b := DecodeHex('871020010db885a3000013198a2e03707334');
  FIpv6c := DecodeHex('871000000000000000000000000000000001');
  FIpv6d := DecodeHex('871020010db885a3000000008a2e03707334');
  FIpv6e := DecodeHex('871020010db885a3000000008a2e0a090800');
  FIpv6f := DecodeHex('872020010db885a3000000008a2e0a090800ffffffffffff00000000000000000000');
  FIpv6g := DecodeHex('872020010db885a3000000008a2e0a090800ffffffffffffffffffffffffffffffff');
  FIpv6h := DecodeHex('872020010db885a300000000000000000000ffffffffffff00000000000000000000');
end;

procedure TGeneralNameTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TGeneralNameTest.CheckIPAddressEncoding(const AInputIP: String;
  const AExpectedEncoding: TCryptoLibByteArray; const AMessage: String);
var
  LGeneralName: IGeneralName;
  LEncoded: TCryptoLibByteArray;
begin
  LGeneralName := TGeneralName.Create(TGeneralName.IPAddress, AInputIP);
  LEncoded := LGeneralName.GetEncoded();
  CheckTrue(AreEqual(AExpectedEncoding, LEncoded), AMessage);
end;

procedure TGeneralNameTest.TestIPv4;
begin
  CheckIPAddressEncoding('10.9.8.0', FIpv4, 'ipv4 encoding failed');
  CheckIPAddressEncoding('10.9.8.0/255.255.255.0', FIpv4WithMask24, 'ipv4 with netmask 1 encoding (24bit) failed');
  CheckIPAddressEncoding('10.9.8.0/24', FIpv4WithMask24, 'ipv4 with netmask 2 encoding (24bit) failed');
  CheckIPAddressEncoding('10.9.8.0/255.252.0.0', FIpv4WithMask14, 'ipv4 with netmask 1 encoding (14bit) failed');
  CheckIPAddressEncoding('10.9.8.0/14', FIpv4WithMask14, 'ipv4 with netmask 2 encoding (14bit) failed');
end;

procedure TGeneralNameTest.TestIPv6;
begin
  CheckIPAddressEncoding('2001:0db8:85a3:08d3:1319:8a2e:0370:7334', FIpv6a, 'ipv6a failed');
  CheckIPAddressEncoding('2001:0db8:85a3::1319:8a2e:0370:7334', FIpv6b, 'ipv6b failed');
  CheckIPAddressEncoding('::1', FIpv6c, 'ipv6c failed');
  CheckIPAddressEncoding('2001:0db8:85a3::8a2e:0370:7334', FIpv6d, 'ipv6d failed');
  CheckIPAddressEncoding('2001:0db8:85a3::8a2e:10.9.8.0', FIpv6e, 'ipv6e failed');
  CheckIPAddressEncoding('2001:0db8:85a3::8a2e:10.9.8.0/ffff:ffff:ffff::0000', FIpv6f, 'ipv6f failed');
  CheckIPAddressEncoding('2001:0db8:85a3::8a2e:10.9.8.0/128', FIpv6g, 'ipv6g failed');
  CheckIPAddressEncoding('2001:0db8:85a3::/48', FIpv6h, 'ipv6h failed');
end;

initialization

{$IFDEF FPC}
RegisterTest(TGeneralNameTest);
{$ELSE}
RegisterTest(TGeneralNameTest.Suite);
{$ENDIF FPC}

end.
