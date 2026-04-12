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

unit AESSICTests;

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
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  NistSp80038aAesTestData;

type

  /// <summary>
  /// Test vectors based on NIST Special Publication 800-38A, <br />
  /// "Recommendation for Block Cipher Modes of Operation"
  /// </summary>
  TTestAESSIC = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FKeys, FPlain: TCryptoLibMatrixByteArray;
    FCipher: TCryptoLibGenericArray<TCryptoLibMatrixByteArray>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestAESSIC;

  end;

implementation

{ TTestAESSIC }

procedure TTestAESSIC.SetUp;
begin
  inherited;

  FKeys := TCryptoLibMatrixByteArray.Create(
    DecodeHex(TNistSp80038aAesTestData.OfficialKeys[0]),
    DecodeHex(TNistSp80038aAesTestData.OfficialKeys[4]),
    DecodeHex(TNistSp80038aAesTestData.OfficialKeys[8]));

  FPlain := TCryptoLibMatrixByteArray.Create(
    DecodeHex(TNistSp80038aAesTestData.OfficialPlaintext[0]),
    DecodeHex(TNistSp80038aAesTestData.OfficialPlaintext[1]),
    DecodeHex(TNistSp80038aAesTestData.OfficialPlaintext[2]),
    DecodeHex(TNistSp80038aAesTestData.OfficialPlaintext[3]));

  FCipher := TCryptoLibGenericArray<TCryptoLibMatrixByteArray>.Create(
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[0]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[1]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[2]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[3])),
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[4]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[5]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[6]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[7])),
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[8]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[9]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[10]),
      DecodeHex(TNistSp80038aAesTestData.OfficialCT_CTR[11])));
end;

procedure TTestAESSIC.TearDown;
begin
  inherited;
end;

procedure TTestAESSIC.TestAESSIC;
var
  LC: IBufferedCipher;
  LI, LJ: Int32;
  LSKey, LSk: IKeyParameter;
  LEnc, LCrypt: TBytes;
begin

  LC := TCipherUtilities.GetCipher('AES/SIC/NoPadding');

  LI := 0;
  while LI <> System.Length(FKeys) do
  begin
    LSKey := TParameterUtilities.CreateKeyParameter('AES', FKeys[LI]);
    LC.Init(True, TParametersWithIV.Create(LSKey,
      DecodeHex(TNistSp80038aAesTestData.OfficialIV_CTR[LI * 4]))
      as IParametersWithIV);

    LJ := 0;
    while LJ <> System.Length(FPlain) do
    begin
      LEnc := LC.ProcessBytes(FPlain[LJ]);
      if (not AreEqual(LEnc, FCipher[LI, LJ])) then
      begin
        Fail('AESSIC encrypt failed: key ' + IntToStr(LI) + ' block ' +
          IntToStr(LJ));
      end;
      System.Inc(LJ);
    end;

    LC.Init(False, TParametersWithIV.Create(LSKey,
      DecodeHex(TNistSp80038aAesTestData.OfficialIV_CTR[LI * 4]))
      as IParametersWithIV);

    LJ := 0;
    while LJ <> System.Length(FPlain) do
    begin
      LEnc := LC.ProcessBytes(FCipher[LI, LJ]);
      if (not AreEqual(LEnc, FPlain[LJ])) then
      begin
        Fail('AESSIC decrypt failed: key ' + IntToStr(LI) + ' block ' +
          IntToStr(LJ));
      end;
      System.Inc(LJ);
    end;
    System.Inc(LI);
  end;

  LC := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  LSk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex(TNistSp80038aAesTestData.OfficialKeys[0]));

  LC.Init(True, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(DecodeHex('00000000000000000000000000000000'));

  if (not AreEqual(LCrypt, DecodeHex('D23513162B02D0F72A43A2FE4A5F97AB'))) then
  begin
    Fail('AESSIC failed test 2');
  end;

  LC := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  LSk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex(TNistSp80038aAesTestData.OfficialKeys[0]));

  LC.Init(True, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(DecodeHex('12345678'));

  LC.Init(False, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(LCrypt);

  if (not AreEqual(LCrypt, DecodeHex('12345678'))) then
  begin
    Fail('AESSIC failed partial test');
  end;

end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAESSIC);
{$ELSE}
  RegisterTest(TTestAESSIC.Suite);
{$ENDIF FPC}

end.
