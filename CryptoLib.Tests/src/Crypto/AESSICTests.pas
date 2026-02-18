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
  CryptoLibTestBase;

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

  FKeys := TCryptoLibMatrixByteArray.Create
    (DecodeHex('2B7E151628AED2A6ABF7158809CF4F3C'),
    DecodeHex('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'),
    DecodeHex(
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'));

  FPlain := TCryptoLibMatrixByteArray.Create
    (DecodeHex('6BC1BEE22E409F96E93D7E117393172A'),
    DecodeHex('AE2D8A571E03AC9C9EB76FAC45AF8E51'),
    DecodeHex('30C81C46A35CE411E5FBC1191A0A52EF'),
    DecodeHex('F69F2445DF4F9B17AD2B417BE66C3710'));

  FCipher := TCryptoLibGenericArray<TCryptoLibMatrixByteArray>.Create
    (TCryptoLibMatrixByteArray.Create
    (DecodeHex('874D6191B620E3261BEF6864990DB6CE'),
    DecodeHex('9806F66B7970FDFF8617187BB9FFFDFF'),
    DecodeHex('5AE4DF3EDBD5D35E5B4F09020DB03EAB'),
    DecodeHex('1E031DDA2FBE03D1792170A0F3009CEE')),
    TCryptoLibMatrixByteArray.Create
    (DecodeHex('1ABC932417521CA24F2B0459FE7E6E0B'),
    DecodeHex('090339EC0AA6FAEFD5CCC2C6F4CE8E94'),
    DecodeHex('1E36B26BD1EBC670D1BD1D665620ABF7'),
    DecodeHex('4F78A7F6D29809585A97DAEC58C6B050')),
    TCryptoLibMatrixByteArray.Create
    (DecodeHex('601EC313775789A5B7A7F504BBF3D228'),
    DecodeHex('F443E3CA4D62B59ACA84E990CACAF5C5'),
    DecodeHex('2B0930DAA23DE94CE87017BA2D84988D'),
    DecodeHex('DFC9C58DB67AADA613C2DD08457941A6')));
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
      DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')) as IParametersWithIV);

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
      DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')) as IParametersWithIV);

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
    DecodeHex('2B7E151628AED2A6ABF7158809CF4F3C'));

  LC.Init(True, TParametersWithIV.Create(LSk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  LCrypt := LC.DoFinal(DecodeHex('00000000000000000000000000000000'));

  if (not AreEqual(LCrypt, DecodeHex('D23513162B02D0F72A43A2FE4A5F97AB'))) then
  begin
    Fail('AESSIC failed test 2');
  end;

  LC := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  LSk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex('2B7E151628AED2A6ABF7158809CF4F3C'));

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
