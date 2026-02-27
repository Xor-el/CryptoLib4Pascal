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

unit Pkcs12Tests;

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
  ClpPkcs12ParametersGenerator,
  ClpIPkcs12ParametersGenerator,
  ClpPbeParametersGenerator,
  ClpDigestUtilities,
  ClpIKeyParameter,
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// Test for Pkcs12 key generation - vectors from
  /// http://www.drh-consultancy.demon.co.uk/test.txt
  /// </summary>
  TTestPkcs12 = class(TCryptoLibAlgorithmTestCase)
  private
    procedure Run1(AId: Int32; const APassword: TCryptoLibCharArray;
      const ASalt: TBytes; AICount: Int32; const AResult: TBytes);
    procedure Run2(AId: Int32; const APassword: TCryptoLibCharArray;
      const ASalt: TBytes; AICount: Int32; const AResult: TBytes);
    procedure Run3(AId: Int32; const APassword: TCryptoLibCharArray;
      const ASalt: TBytes; AICount: Int32; const AResult: TBytes);

  published
    procedure TestPkcs12KeyDerivation;
  end;

implementation

procedure TTestPkcs12.Run1(AId: Int32; const APassword: TCryptoLibCharArray;
  const ASalt: TBytes; AICount: Int32; const AResult: TBytes);
var
  LGenerator: IPkcs12ParametersGenerator;
  LKeyParams: ICipherParameters;
  LKeyParam: IKeyParameter;
  LPasswordBytes: TBytes;
begin
  LGenerator := TPkcs12ParametersGenerator.Create(TDigestUtilities.GetDigest('SHA1'));
  LPasswordBytes := TPbeParametersGenerator.Pkcs12PasswordToBytes(APassword);
  LGenerator.Init(LPasswordBytes, ASalt, AICount);
  LKeyParams := LGenerator.GenerateDerivedParameters('AES192', 24 * 8);
  if not Supports(LKeyParams, IKeyParameter, LKeyParam) then
    Fail(Format('id %d: expected IKeyParameter', [AId]));
  if not AreEqual(AResult, LKeyParam.GetKey()) then
    Fail(Format('id %d Failed', [AId]));
end;

procedure TTestPkcs12.Run2(AId: Int32; const APassword: TCryptoLibCharArray;
  const ASalt: TBytes; AICount: Int32; const AResult: TBytes);
var
  LGenerator: IPkcs12ParametersGenerator;
  LParams: ICipherParameters;
  LParamsWithIV: IParametersWithIV;
  LPasswordBytes: TBytes;
begin
  LGenerator := TPkcs12ParametersGenerator.Create(TDigestUtilities.GetDigest('SHA1'));
  LPasswordBytes := TPbeParametersGenerator.Pkcs12PasswordToBytes(APassword);
  LGenerator.Init(LPasswordBytes, ASalt, AICount);
  LParams := LGenerator.GenerateDerivedParameters('AES256', 256, 128);
  if not Supports(LParams, IParametersWithIV, LParamsWithIV) then
    Fail(Format('id %d: expected IParametersWithIV', [AId]));
  if not AreEqual(AResult, LParamsWithIV.GetIV()) then
    Fail(Format('id %d Failed', [AId]));
end;

procedure TTestPkcs12.Run3(AId: Int32; const APassword: TCryptoLibCharArray;
  const ASalt: TBytes; AICount: Int32; const AResult: TBytes);
var
  LGenerator: IPkcs12ParametersGenerator;
  LKeyParams: ICipherParameters;
  LKeyParam: IKeyParameter;
  LPasswordBytes: TBytes;
begin
  LGenerator := TPkcs12ParametersGenerator.Create(TDigestUtilities.GetDigest('SHA1'));
  LPasswordBytes := TPbeParametersGenerator.Pkcs12PasswordToBytes(APassword);
  LGenerator.Init(LPasswordBytes, ASalt, AICount);
  LKeyParams := LGenerator.GenerateDerivedMacParameters(160);
  if not Supports(LKeyParams, IKeyParameter, LKeyParam) then
    Fail(Format('id %d: expected IKeyParameter', [AId]));
  if not AreEqual(AResult, LKeyParam.GetKey()) then
    Fail(Format('id %d Failed', [AId]));
end;

procedure TTestPkcs12.TestPkcs12KeyDerivation;
var
  LPassword1, LPassword2: TCryptoLibCharArray;
begin
  LPassword1 := StringToCharArray('smeg');
  LPassword2 := StringToCharArray('queeg');

  Run1(1, LPassword1, THexEncoder.Decode('0A58CF64530D823F'), 1, THexEncoder.Decode('8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3'));
  Run2(2, LPassword1, THexEncoder.Decode('0A58CF64530D823F'), 1, THexEncoder.Decode('79993DFE048D3B76BA33EDF670C54CA0'));
  Run1(3, LPassword1, THexEncoder.Decode('642B99AB44FB4B1F'), 1, THexEncoder.Decode('F3A95FEC48D7711E985CFE67908C5AB79FA3D7C5CAA5D966'));
  Run2(4, LPassword1, THexEncoder.Decode('642B99AB44FB4B1F'), 1, THexEncoder.Decode('C0A38D64A79BEA1D3AA691A2C9F4E1ED'));
  Run3(5, LPassword1, THexEncoder.Decode('3D83C0E4546AC140'), 1, THexEncoder.Decode('8D967D88F6CAA9D714800AB3D48051D63F73A312'));
  Run1(6, LPassword2, THexEncoder.Decode('05DEC959ACFF72F7'), 1000, THexEncoder.Decode('ED2034E36328830FF09DF1E1A07DD357185DAC0D4F9EB3D4'));
  Run2(7, LPassword2, THexEncoder.Decode('05DEC959ACFF72F7'), 1000, THexEncoder.Decode('11DEDAD7758D4860844084F02D9C8E0D'));
  Run1(8, LPassword2, THexEncoder.Decode('1682C0FC5B3F7EC5'), 1000, THexEncoder.Decode('483DD6E919D7DE2E8E648BA8F862F3FBFBDC2BCB2C02957F'));
  Run2(9, LPassword2, THexEncoder.Decode('1682C0FC5B3F7EC5'), 1000, THexEncoder.Decode('9D461D1B00355C50C06F086E706E2202'));
  Run3(10, LPassword2, THexEncoder.Decode('263216FCC2FAB31C'), 1000, THexEncoder.Decode('5EC4C7A80DF652294C3925B6489A7AB857C83476'));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcs12);
{$ELSE}
  RegisterTest(TTestPkcs12.Suite);
{$ENDIF FPC}

end.
