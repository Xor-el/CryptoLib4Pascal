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
  SymmetricBlockVectors;

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
var
  LBaseBand: TCryptoLibGenericArray<TNistAesVectorRow>;
  LBand128, LBand192, LBand256: TCryptoLibGenericArray<TNistAesVectorRow>;
begin
  inherited;

  LBaseBand := TNistSp80038aAesVectors.GetRows('Ctr', 128);
  LBand128 := LBaseBand;
  LBand192 := TNistSp80038aAesVectors.GetRows('Ctr', 192);
  LBand256 := TNistSp80038aAesVectors.GetRows('Ctr', 256);

  FKeys := TCryptoLibMatrixByteArray.Create(
    DecodeHex(LBand128[0].Key),
    DecodeHex(LBand192[0].Key),
    DecodeHex(LBand256[0].Key));

  FPlain := TCryptoLibMatrixByteArray.Create(
    DecodeHex(LBaseBand[0].Input),
    DecodeHex(LBaseBand[1].Input),
    DecodeHex(LBaseBand[2].Input),
    DecodeHex(LBaseBand[3].Input));

  FCipher := TCryptoLibGenericArray<TCryptoLibMatrixByteArray>.Create(
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(LBand128[0].Output),
      DecodeHex(LBand128[1].Output),
      DecodeHex(LBand128[2].Output),
      DecodeHex(LBand128[3].Output)),
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(LBand192[0].Output),
      DecodeHex(LBand192[1].Output),
      DecodeHex(LBand192[2].Output),
      DecodeHex(LBand192[3].Output)),
    TCryptoLibMatrixByteArray.Create(
      DecodeHex(LBand256[0].Output),
      DecodeHex(LBand256[1].Output),
      DecodeHex(LBand256[2].Output),
      DecodeHex(LBand256[3].Output)));
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
  LKeySizes: array [0 .. 2] of Int32;
  LBand: TCryptoLibGenericArray<TNistAesVectorRow>;
begin
  LKeySizes[0] := 128;
  LKeySizes[1] := 192;
  LKeySizes[2] := 256;

  LC := TCipherUtilities.GetCipher('AES/SIC/NoPadding');

  LI := 0;
  while LI <> System.Length(FKeys) do
  begin
    LBand := TNistSp80038aAesVectors.GetRows('Ctr', LKeySizes[LI]);
    LSKey := TParameterUtilities.CreateKeyParameter('AES', FKeys[LI]);
    LC.Init(True, TParametersWithIV.Create(LSKey,
      DecodeHex(LBand[0].IV)) as IParametersWithIV);

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
      DecodeHex(LBand[0].IV)) as IParametersWithIV);

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
    DecodeHex(TNistSp80038aAesVectors.GetRows('Ctr', 128)[0].Key));

  LC.Init(True, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(DecodeHex('00000000000000000000000000000000'));

  if (not AreEqual(LCrypt, DecodeHex('D23513162B02D0F72A43A2FE4A5F97AB'))) then
  begin
    Fail('AESSIC failed test 2');
  end;

  LC := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  LSk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex(TNistSp80038aAesVectors.GetRows('Ctr', 128)[0].Key));

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
