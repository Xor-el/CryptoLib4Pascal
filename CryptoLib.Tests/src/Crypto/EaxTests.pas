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

unit EaxTests;

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
  ClpIBlockCipher,
  ClpIAeadBlockCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpEaxBlockCipher,
  ClpIEaxBlockCipher,
  ClpAesEngine,
  ClpIAesEngine,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpConverters,
  CryptoLibTestBase;

type

  TTestEax = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FK1, FN1, FA1, FP1, FC1, FT1: TBytes;
      FK2, FN2, FA2, FP2, FC2, FT2: TBytes;
      FK3, FN3, FA3, FP3, FC3, FT3: TBytes;
      FK4, FN4, FA4, FP4, FC4, FT4: TBytes;
      FK5, FN5, FA5, FP5, FC5, FT5: TBytes;
      FK6, FN6, FA6, FP6, FC6, FT6: TBytes;
      FK7, FN7, FA7, FP7, FC7, FT7: TBytes;
      FK8, FN8, FA8, FP8, FC8, FT8: TBytes;
      FK9, FN9, FA9, FP9, FC9, FT9: TBytes;
      FK10, FN10, FA10, FP10, FC10, FT10: TBytes;
      FK11, FN11, FA11, FP11, FC11, FT11: TBytes;

  private
    procedure CheckVectors(ACount: Int32; const AK: TBytes; AMacSize: Int32;
      const AN, AA, AP, AT, AC: TBytes); overload;

    procedure CheckVectors(ACount: Int32; const AAdditionalDataType: string;
      const AK: TBytes; AMacSize: Int32; const AN, AA, ASA, AP, AT, AC: TBytes); overload;

    procedure RunCheckVectors(ACount: Int32; const AEncEax, ADecEax: IEaxBlockCipher;
      const AAdditionalDataType: string; const ASA, AP, AT, AC: TBytes);

    procedure IvParamTest(ACount: Int32; const AEax: IAeadBlockCipher;
      const AK, AN: TBytes);

    procedure RandomTest(const ARandom: ISecureRandom);
    procedure RandomTests;

    function CreateEngine: IBlockCipher;
    function CreateEaxCipher: IEaxBlockCipher;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestVectors;
    procedure TestIvParameters;
    procedure TestExceptionsAndRandomised;

  end;

implementation

{ TTestEax }

procedure TTestEax.SetUp;
begin
  inherited;

  FK1 := DecodeHex('233952DEE4D5ED5F9B9C6D6FF80FF478');
  FN1 := DecodeHex('62EC67F9C3A4A407FCB2A8C49031A8B3');
  FA1 := DecodeHex('6BFB914FD07EAE6B');
  FP1 := DecodeHex('');
  FC1 := DecodeHex('E037830E8389F27B025A2D6527E79D01');
  FT1 := DecodeHex('E037830E8389F27B025A2D6527E79D01');

  FK2 := DecodeHex('91945D3F4DCBEE0BF45EF52255F095A4');
  FN2 := DecodeHex('BECAF043B0A23D843194BA972C66DEBD');
  FA2 := DecodeHex('FA3BFD4806EB53FA');
  FP2 := DecodeHex('F7FB');
  FC2 := DecodeHex('19DD5C4C9331049D0BDAB0277408F67967E5');
  FT2 := DecodeHex('5C4C9331049D0BDAB0277408F67967E5');

  FK3 := DecodeHex('01F74AD64077F2E704C0F60ADA3DD523');
  FN3 := DecodeHex('70C3DB4F0D26368400A10ED05D2BFF5E');
  FA3 := DecodeHex('234A3463C1264AC6');
  FP3 := DecodeHex('1A47CB4933');
  FC3 := DecodeHex('D851D5BAE03A59F238A23E39199DC9266626C40F80');
  FT3 := DecodeHex('3A59F238A23E39199DC9266626C40F80');

  FK4 := DecodeHex('D07CF6CBB7F313BDDE66B727AFD3C5E8');
  FN4 := DecodeHex('8408DFFF3C1A2B1292DC199E46B7D617');
  FA4 := DecodeHex('33CCE2EABFF5A79D');
  FP4 := DecodeHex('481C9E39B1');
  FC4 := DecodeHex('632A9D131AD4C168A4225D8E1FF755939974A7BEDE');
  FT4 := DecodeHex('D4C168A4225D8E1FF755939974A7BEDE');

  FK5 := DecodeHex('35B6D0580005BBC12B0587124557D2C2');
  FN5 := DecodeHex('FDB6B06676EEDC5C61D74276E1F8E816');
  FA5 := DecodeHex('AEB96EAEBE2970E9');
  FP5 := DecodeHex('40D0C07DA5E4');
  FC5 := DecodeHex('071DFE16C675CB0677E536F73AFE6A14B74EE49844DD');
  FT5 := DecodeHex('CB0677E536F73AFE6A14B74EE49844DD');

  FK6 := DecodeHex('BD8E6E11475E60B268784C38C62FEB22');
  FN6 := DecodeHex('6EAC5C93072D8E8513F750935E46DA1B');
  FA6 := DecodeHex('D4482D1CA78DCE0F');
  FP6 := DecodeHex('4DE3B35C3FC039245BD1FB7D');
  FC6 := DecodeHex('835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F');
  FT6 := DecodeHex('ABB8644FD6CCB86947C5E10590210A4F');

  FK7 := DecodeHex('7C77D6E813BED5AC98BAA417477A2E7D');
  FN7 := DecodeHex('1A8C98DCD73D38393B2BF1569DEEFC19');
  FA7 := DecodeHex('65D2017990D62528');
  FP7 := DecodeHex('8B0A79306C9CE7ED99DAE4F87F8DD61636');
  FC7 := DecodeHex('02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2');
  FT7 := DecodeHex('137327D10649B0AA6E1C181DB617D7F2');

  FK8 := DecodeHex('5FFF20CAFAB119CA2FC73549E20F5B0D');
  FN8 := DecodeHex('DDE59B97D722156D4D9AFF2BC7559826');
  FA8 := DecodeHex('54B9F04E6A09189A');
  FP8 := DecodeHex('1BDA122BCE8A8DBAF1877D962B8592DD2D56');
  FC8 := DecodeHex('2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A');
  FT8 := DecodeHex('3B60450599BD02C96382902AEF7F832A');

  FK9 := DecodeHex('A4A4782BCFFD3EC5E7EF6D8C34A56123');
  FN9 := DecodeHex('B781FCF2F75FA5A8DE97A9CA48E522EC');
  FA9 := DecodeHex('899A175897561D7E');
  FP9 := DecodeHex('6CF36720872B8513F6EAB1A8A44438D5EF11');
  FC9 := DecodeHex('0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700');
  FT9 := DecodeHex('E7F6D2231618102FDB7FE55FF1991700');

  FK10 := DecodeHex('8395FCF1E95BEBD697BD010BC766AAC3');
  FN10 := DecodeHex('22E7ADD93CFC6393C57EC0B3C17D6B44');
  FA10 := DecodeHex('126735FCC320D25A');
  FP10 := DecodeHex('CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7');
  FC10 := DecodeHex('CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E');
  FT10 := DecodeHex('CFC46AFC253B4652B1AF3795B124AB6E');

  FK11 := DecodeHex('8395FCF1E95BEBD697BD010BC766AAC3');
  FN11 := DecodeHex('22E7ADD93CFC6393C57EC0B3C17D6B44');
  FA11 := DecodeHex('126735FCC320D25A');
  FP11 := DecodeHex('CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7');
  FC11 := DecodeHex('CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC');
  FT11 := DecodeHex('CFC46AFC');
end;

procedure TTestEax.TearDown;
begin
  inherited;
end;

function TTestEax.CreateEngine: IBlockCipher;
begin
  Result := TAesEngine.Create() as IAesEngine;
end;

function TTestEax.CreateEaxCipher: IEaxBlockCipher;
begin
  Result := TEaxBlockCipher.Create(CreateEngine) as IEaxBlockCipher;
end;

procedure TTestEax.CheckVectors(ACount: Int32; const AK: TBytes;
  AMacSize: Int32; const AN, AA, AP, AT, AC: TBytes);
var
  LFirstA, LLastA: TBytes;
begin
  SetLength(LFirstA, Length(AA) div 2);
  SetLength(LLastA, Length(AA) - Length(LFirstA));
  if Length(LFirstA) > 0 then
  begin
    System.Move(AA[0], LFirstA[0], Length(LFirstA));
  end;
  if Length(LLastA) > 0 then
  begin
    System.Move(AA[Length(LFirstA)], LLastA[0], Length(LLastA));
  end;

  CheckVectors(ACount, 'all initial associated data', AK, AMacSize,
    AN, AA, nil, AP, AT, AC);
  CheckVectors(ACount, 'subsequent associated data', AK, AMacSize,
    AN, nil, AA, AP, AT, AC);
  CheckVectors(ACount, 'split associated data', AK, AMacSize,
    AN, LFirstA, LLastA, AP, AT, AC);
end;

procedure TTestEax.CheckVectors(ACount: Int32; const AAdditionalDataType: string;
  const AK: TBytes; AMacSize: Int32; const AN, AA, ASA, AP, AT, AC: TBytes);
var
  LEncEax, LDecEax: IEaxBlockCipher;
  LParams: IAeadParameters;
begin
  LEncEax := CreateEaxCipher;
  LDecEax := CreateEaxCipher;

  LParams := TAeadParameters.Create(TKeyParameter.Create(AK) as IKeyParameter,
    AMacSize, AN, AA);
  LEncEax.Init(True, LParams as ICipherParameters);
  LDecEax.Init(False, LParams as ICipherParameters);

  RunCheckVectors(ACount, LEncEax, LDecEax, AAdditionalDataType, ASA, AP, AT, AC);
  RunCheckVectors(ACount, LEncEax, LDecEax, AAdditionalDataType, ASA, AP, AT, AC);

  // key reuse test (reuse key via null-key parameters)
  LParams := TAeadParameters.Create(nil, AMacSize, AN, AA);
  LEncEax.Init(True, LParams as ICipherParameters);
  LDecEax.Init(False, LParams as ICipherParameters);

  RunCheckVectors(ACount, LEncEax, LDecEax, AAdditionalDataType, ASA, AP, AT, AC);
  RunCheckVectors(ACount, LEncEax, LDecEax, AAdditionalDataType, ASA, AP, AT, AC);
end;

procedure TTestEax.RunCheckVectors(ACount: Int32; const AEncEax, ADecEax: IEaxBlockCipher;
  const AAdditionalDataType: string; const ASA, AP, AT, AC: TBytes);
var
  LEnc, LTmp, LDec: TBytes;
  LLen: Int32;
begin
  SetLength(LEnc, Length(AC));

  if ASA <> nil then
  begin
    AEncEax.ProcessAadBytes(ASA, 0, Length(ASA));
  end;

  LLen := AEncEax.ProcessBytes(AP, 0, Length(AP), LEnc, 0);
  AEncEax.DoFinal(LEnc, LLen);

  if not AreEqual(AC, LEnc) then
  begin
    Fail(Format('encrypted stream fails to match in test %d with %s',
      [ACount, AAdditionalDataType]));
  end;

  SetLength(LTmp, Length(LEnc));
  if ASA <> nil then
  begin
    ADecEax.ProcessAadBytes(ASA, 0, Length(ASA));
  end;

  LLen := ADecEax.ProcessBytes(LEnc, 0, Length(LEnc), LTmp, 0);
  LLen := LLen + ADecEax.DoFinal(LTmp, LLen);

  SetLength(LDec, LLen);
  if LLen > 0 then
  begin
    System.Move(LTmp[0], LDec[0], LLen);
  end;

  if not AreEqual(AP, LDec) then
  begin
    Fail(Format('decrypted stream fails to match in test %d with %s',
      [ACount, AAdditionalDataType]));
  end;

  if not AreEqual(AT, ADecEax.GetMac) then
  begin
    Fail(Format('MAC fails to match in test %d with %s',
      [ACount, AAdditionalDataType]));
  end;
end;

procedure TTestEax.IvParamTest(ACount: Int32; const AEax: IAeadBlockCipher;
  const AK, AN: TBytes);
var
  LPlain, LEnc, LTmp, LDec: TBytes;
  LParams: IParametersWithIV;
  LLen: Int32;
begin
  LPlain := TConverters.ConvertStringToBytes('hello world!!', TEncoding.ASCII);

  LParams := TParametersWithIV.Create(TKeyParameter.Create(AK) as IKeyParameter,
    AN);

  AEax.Init(True, LParams as ICipherParameters);
  SetLength(LEnc, Length(LPlain) + 8);

  LLen := AEax.ProcessBytes(LPlain, 0, Length(LPlain), LEnc, 0);
  AEax.DoFinal(LEnc, LLen);

  AEax.Init(False, LParams as ICipherParameters);
  SetLength(LTmp, Length(LEnc));

  LLen := AEax.ProcessBytes(LEnc, 0, Length(LEnc), LTmp, 0);
  LLen := LLen + AEax.DoFinal(LTmp, LLen);

  SetLength(LDec, LLen);
  if LLen > 0 then
  begin
    System.Move(LTmp[0], LDec[0], LLen);
  end;

  if not AreEqual(LPlain, LDec) then
  begin
    Fail(Format('decrypted stream fails to match in IV param test %d', [ACount]));
  end;
end;

procedure TTestEax.RandomTest(const ARandom: ISecureRandom);
const
  NonceLen = 8;
  MacLen = 8;
  AuthLen = 20;
var
  LDatLen, LOutOff, LResultLen: Int32;
  LNonce, LAuth, LDatIn, LKey, LIntr, LDatOut: TBytes;
  LEngine: IBlockCipher;
  LKeyParam: IKeyParameter;
  LEax: IEaxBlockCipher;
  LParams: IAeadParameters;
begin
  LDatLen := ARandom.Next(1024);

  SetLength(LNonce, NonceLen);
  SetLength(LAuth, AuthLen);
  SetLength(LDatIn, LDatLen);
  SetLength(LKey, 16);

  ARandom.NextBytes(LNonce);
  ARandom.NextBytes(LAuth);
  ARandom.NextBytes(LDatIn);
  ARandom.NextBytes(LKey);

  LEngine := CreateEngine;
  LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
  LEax := TEaxBlockCipher.Create(LEngine) as IEaxBlockCipher;

  LParams := TAeadParameters.Create(LKeyParam, MacLen * 8, LNonce, LAuth);
  LEax.Init(True, LParams as ICipherParameters);

  SetLength(LIntr, LEax.GetOutputSize(Length(LDatIn)));
  LOutOff := LEax.ProcessBytes(LDatIn, 0, LDatLen, LIntr, 0);
  LOutOff := LOutOff + LEax.DoFinal(LIntr, LOutOff);

  LEax.Init(False, LParams as ICipherParameters);
  SetLength(LDatOut, LEax.GetOutputSize(LOutOff));
  LResultLen := LEax.ProcessBytes(LIntr, 0, LOutOff, LDatOut, 0);
  LEax.DoFinal(LDatOut, LResultLen);

  if not AreEqual(LDatIn, LDatOut) then
  begin
    Fail('EAX roundtrip failed to match');
  end;
end;

procedure TTestEax.RandomTests;
var
  LRandom: ISecureRandom;
  LI: Int32;
begin
  LRandom := TSecureRandom.Create();
  for LI := 0 to 9 do
  begin
    RandomTest(LRandom);
  end;
end;

procedure TTestEax.TestVectors;
begin
  CheckVectors(1, FK1, 128, FN1, FA1, FP1, FT1, FC1);
  CheckVectors(2, FK2, 128, FN2, FA2, FP2, FT2, FC2);
  CheckVectors(3, FK3, 128, FN3, FA3, FP3, FT3, FC3);
  CheckVectors(4, FK4, 128, FN4, FA4, FP4, FT4, FC4);
  CheckVectors(5, FK5, 128, FN5, FA5, FP5, FT5, FC5);
  CheckVectors(6, FK6, 128, FN6, FA6, FP6, FT6, FC6);
  CheckVectors(7, FK7, 128, FN7, FA7, FP7, FT7, FC7);
  CheckVectors(8, FK8, 128, FN8, FA8, FP8, FT8, FC8);
  CheckVectors(9, FK9, 128, FN9, FA9, FP9, FT9, FC9);
  CheckVectors(10, FK10, 128, FN10, FA10, FP10, FT10, FC10);
  CheckVectors(11, FK11, 32, FN11, FA11, FP11, FT11, FC11);
end;

procedure TTestEax.TestIvParameters;
var
  LEax: IAeadBlockCipher;
begin
  LEax := CreateEaxCipher as IAeadBlockCipher;
  IvParamTest(1, LEax, FK1, FN1);
end;

procedure TTestEax.TestExceptionsAndRandomised;
var
  LEax: IEaxBlockCipher;
  LEnc, LBadKey: TBytes;
  LLen: Int32;
begin
  LEax := CreateEaxCipher;

  // Wrong MAC size / invalid ciphertext: decryption should fail
  LEax.Init(False,
    TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
    32, FN2, FA2) as ICipherParameters);
  SetLength(LEnc, Length(FC2));
  try
    LLen := LEax.ProcessBytes(FC2, 0, Length(FC2), LEnc, 0);
    LEax.DoFinal(LEnc, LLen);
    Fail('invalid cipher text not picked up');
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      // expected
    end;
  end;

  // Wrong parameter type: bare KeyParameter instead of AEAD parameters
  SetLength(LBadKey, Length(FK1));
  if Length(FK1) > 0 then
  begin
    System.Move(FK1[0], LBadKey[0], Length(FK1));
  end;
  try
    LEax.Init(False, TKeyParameter.Create(LBadKey) as IKeyParameter);
    Fail('illegal argument not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  // Randomised round-trip tests
  RandomTests;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEax);
{$ELSE}
  RegisterTest(TTestEax.Suite);
{$ENDIF FPC}

end.

