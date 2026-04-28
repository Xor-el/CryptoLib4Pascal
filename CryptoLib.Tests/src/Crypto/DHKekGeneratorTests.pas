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

unit DHKekGeneratorTests;

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
  ClpDigestUtilities,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpDHKekGenerator,
  ClpDHKdfParameters,
  ClpIDHKdfParameters,
  ClpNistObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// DH KEK generator tests (RFC 2631-style OtherInfo).
  /// </summary>
  TTestDHKekGenerator = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FSeed, FPartyAInfo, FExpected192, FExpected128: TBytes;

    procedure CheckMask(const AName: String; const AKdf: IDerivationFunction;
      const AParams: IDerivationParameters; const AExpected: TBytes);
    procedure DoTestDHKekGenerator;

  protected
    procedure SetUp; override;

  published
    procedure TestDHKekGenerator;
  end;

implementation

{ TTestDHKekGenerator }

procedure TTestDHKekGenerator.CheckMask(const AName: String;
  const AKdf: IDerivationFunction; const AParams: IDerivationParameters;
  const AExpected: TBytes);
var
  LData: TBytes;
begin
  System.SetLength(LData, System.Length(AExpected));
  AKdf.Init(AParams);
  AKdf.GenerateBytes(LData, 0, System.Length(LData));
  if not AreEqual(AExpected, LData) then
    Fail(Format('DHKekGenerator failed test %s', [AName]));
end;

procedure TTestDHKekGenerator.DoTestDHKekGenerator;
var
  LKdf: IDerivationFunction;
  LDhParams: IDHKdfParameters;
begin
  LKdf := TDHKekGenerator.Create(TDigestUtilities.GetDigest('SHA-1'));

  LDhParams := TDHKdfParameters.Create(TNistObjectIdentifiers.IdAes192Wrap, 192,
    FSeed);
  CheckMask('Aes192Wrap', LKdf, LDhParams, FExpected192);

  LDhParams := TDHKdfParameters.Create(TNistObjectIdentifiers.IdAes128Wrap, 128,
    FSeed, FPartyAInfo);
  CheckMask('Aes128Wrap+partyA', LKdf, LDhParams, FExpected128);
end;

procedure TTestDHKekGenerator.SetUp;
begin
  inherited;
  FSeed := DecodeHex('000102030405060708090a0b0c0d0e0f10111213');
  FPartyAInfo := DecodeHex(
    '0123456789abcdeffedcba9876543201' +
    '0123456789abcdeffedcba9876543201' +
    '0123456789abcdeffedcba9876543201' +
    '0123456789abcdeffedcba9876543201');

  FExpected192 := DecodeHex(
    '0c8ca67a805d533be783ba24009b572b72c474599ae71f7e');
  FExpected128 := DecodeHex('82c44ae9b7e7db3681e8ab328192a5ee');
end;

procedure TTestDHKekGenerator.TestDHKekGenerator;
begin
  DoTestDHKekGenerator;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDHKekGenerator);
{$ELSE}
  RegisterTest(TTestDHKekGenerator.Suite);
{$ENDIF FPC}

end.
