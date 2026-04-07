{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ECDHKekGeneratorTests;

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
  ClpECDHKekGenerator,
  ClpDHKdfParameters,
  ClpIDHKdfParameters,
  ClpNistObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// ECDH CMS KEK tests (ECC-CMS-SharedInfo).
  /// </summary>
  TTestECDHKekGenerator = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FSeed1, FExpected1, FSeed2, FExpected2, FSeed3, FExpected3: TBytes;

    procedure CheckMask(const AName: String; const AKdf: IDerivationFunction;
      const AParams: IDerivationParameters; const AExpected: TBytes);
    procedure DoTestECDHKekGenerator;

  protected
    procedure SetUp; override;

  published
    procedure TestECDHKekGenerator;
  end;

implementation

{ TTestECDHKekGenerator }

procedure TTestECDHKekGenerator.CheckMask(const AName: String;
  const AKdf: IDerivationFunction; const AParams: IDerivationParameters;
  const AExpected: TBytes);
var
  LData: TBytes;
begin
  System.SetLength(LData, System.Length(AExpected));
  AKdf.Init(AParams);
  AKdf.GenerateBytes(LData, 0, System.Length(LData));
  if not AreEqual(AExpected, LData) then
    Fail(Format('ECDHKekGenerator failed test %s', [AName]));
end;

procedure TTestECDHKekGenerator.DoTestECDHKekGenerator;
var
  LKdf: IDerivationFunction;
  LDhParams: IDHKdfParameters;
begin
  LKdf := TECDHKekGenerator.Create(TDigestUtilities.GetDigest('SHA-1'));

  LDhParams := TDHKdfParameters.Create(TNistObjectIdentifiers.IdAes256Wrap, 256,
    FSeed1) as IDHKdfParameters;
  CheckMask('Aes256Wrap', LKdf, LDhParams, FExpected1);

  LDhParams := TDHKdfParameters.Create(TNistObjectIdentifiers.IdAes128Wrap, 128,
    FSeed2) as IDHKdfParameters;
  CheckMask('Aes128Wrap', LKdf, LDhParams, FExpected2);

  LDhParams := TDHKdfParameters.Create(TNistObjectIdentifiers.IdAes192Wrap, 192,
    FSeed3) as IDHKdfParameters;
  CheckMask('Aes192Wrap', LKdf, LDhParams, FExpected3);
end;

procedure TTestECDHKekGenerator.SetUp;
begin
  inherited;
  FSeed1 := DecodeHex(
    'db4a8daba1f98791d54e940175dd1a5f3a0826a1066aa9b668d4dc1e1e0790158dcad1533c03b44214d1b61fefa8b579');
  FExpected1 := DecodeHex(
    '8ecc6d85caf25eaba823a7d620d4ab0d33e4c645f2');

  FSeed2 := DecodeHex(
    '75d7487b5d3d2bfb3c69ce0365fe64e3bfab5d0d63731628a9f47eb8fddfa28c65decaf228a0b38f0c51c6a3356d7c56');
  FExpected2 := DecodeHex('042be1faca3a4a8fc859241bfb87ba35');

  FSeed3 := DecodeHex(
    'fdeb6d809f997e8ac174d638734dc36d37aaf7e876e39967cd82b1cada3de772449788461ee7f856bad9305627f8e48b');

  FExpected3 := DecodeHex(
    'eb02216a64badae35675fd2f7cc35c13f8c20631f7f4240b');
end;

procedure TTestECDHKekGenerator.TestECDHKekGenerator;
begin
  DoTestECDHKekGenerator;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestECDHKekGenerator);
{$ELSE}
  RegisterTest(TTestECDHKekGenerator.Suite);
{$ENDIF FPC}

end.
