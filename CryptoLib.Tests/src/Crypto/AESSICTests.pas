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
  ClpGeneratorUtilities,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpHex,
  ClpArrayUtils,
  ClpCryptoLibTypes;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  /// <summary>
  /// Test vectors based on NIST Special Publication 800-38A, <br />
  /// "Recommendation for Block Cipher Modes of Operation"
  /// </summary>
  TTestAESSIC = class(TCryptoLibTestCase)
  private

  var
    Fkeys, Fplain: TCryptoLibMatrixByteArray;
    Fcipher: TCryptoLibGenericArray<TCryptoLibMatrixByteArray>;

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

  Fkeys := TCryptoLibMatrixByteArray.Create
    (THex.Decode('2b7e151628aed2a6abf7158809cf4f3c'),
    THex.Decode('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
    THex.Decode
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'));

  Fplain := TCryptoLibMatrixByteArray.Create
    (THex.Decode('6bc1bee22e409f96e93d7e117393172a'),
    THex.Decode('ae2d8a571e03ac9c9eb76fac45af8e51'),
    THex.Decode('30c81c46a35ce411e5fbc1191a0a52ef'),
    THex.Decode('f69f2445df4f9b17ad2b417be66c3710'));

  Fcipher := TCryptoLibGenericArray<TCryptoLibMatrixByteArray>.Create
    (TCryptoLibMatrixByteArray.Create
    (THex.Decode('874d6191b620e3261bef6864990db6ce'),
    THex.Decode('9806f66b7970fdff8617187bb9fffdff'),
    THex.Decode('5ae4df3edbd5d35e5b4f09020db03eab'),
    THex.Decode('1e031dda2fbe03d1792170a0f3009cee')),
    TCryptoLibMatrixByteArray.Create
    (THex.Decode('1abc932417521ca24f2b0459fe7e6e0b'),
    THex.Decode('090339ec0aa6faefd5ccc2c6f4ce8e94'),
    THex.Decode('1e36b26bd1ebc670d1bd1d665620abf7'),
    THex.Decode('4f78a7f6d29809585a97daec58c6b050')),
    TCryptoLibMatrixByteArray.Create
    (THex.Decode('601ec313775789a5b7a7f504bbf3d228'),
    THex.Decode('f443e3ca4d62b59aca84e990cacaf5c5'),
    THex.Decode('2b0930daa23de94ce87017ba2d84988d'),
    THex.Decode('dfc9c58db67aada613c2dd08457941a6')));
end;

procedure TTestAESSIC.TearDown;
begin
  inherited;

end;

procedure TTestAESSIC.TestAESSIC;
var
  c: IBufferedCipher;
  i, j: Int32;
  skey, sk: IKeyParameter;
  enc, crypt: TBytes;
begin

  c := TCipherUtilities.GetCipher('AES/SIC/NoPadding');

  //
  // NIST vectors
  //

  i := 0;
  while i <> System.Length(Fkeys) do
  begin
    skey := TParameterUtilities.CreateKeyParameter('AES', Fkeys[i]);
    c.Init(true, TParametersWithIV.Create(skey,
      THex.Decode('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')) as IParametersWithIV);

    j := 0;
    while j <> System.Length(Fplain) do
    begin
      enc := c.ProcessBytes(Fplain[j]);
      if (not TArrayUtils.AreEqual(enc, Fcipher[i, j])) then
      begin
        Fail('AESSIC encrypt failed: key ' + IntToStr(i) + ' block ' +
          IntToStr(j));
      end;
      System.Inc(j);
    end;

    c.Init(false, TParametersWithIV.Create(skey,
      THex.Decode('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')) as IParametersWithIV);

    j := 0;
    while j <> System.Length(Fplain) do
    begin
      enc := c.ProcessBytes(Fcipher[i, j]);
      if (not TArrayUtils.AreEqual(enc, Fplain[j])) then
      begin
        Fail('AESSIC decrypt failed: key ' + IntToStr(i) + ' block ' +
          IntToStr(j));
      end;
      System.Inc(j);
    end;
    System.Inc(i);
  end;

  //
  // check CTR also recognised.
  //

  c := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  sk := TParameterUtilities.CreateKeyParameter('AES',
    THex.Decode('2B7E151628AED2A6ABF7158809CF4F3C'));

  c.Init(true, TParametersWithIV.Create(sk,
    THex.Decode('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  crypt := c.DoFinal(THex.Decode('00000000000000000000000000000000'));

  if (not TArrayUtils.AreEqual(crypt,
    THex.Decode('D23513162B02D0F72A43A2FE4A5F97AB'))) then
  begin
    Fail('AESSIC failed test 2');
  end;

  //
  // check partial block processing
  //
  c := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  sk := TParameterUtilities.CreateKeyParameter('AES',
    THex.Decode('2B7E151628AED2A6ABF7158809CF4F3C'));

  c.Init(true, TParametersWithIV.Create(sk,
    THex.Decode('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  crypt := c.DoFinal(THex.Decode('12345678'));

  c.Init(false, TParametersWithIV.Create(sk,
    THex.Decode('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  crypt := c.DoFinal(crypt);

  if (not TArrayUtils.AreEqual(crypt, THex.Decode('12345678'))) then
  begin
    Fail('AESSIC failed partial test');
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAESSIC);
{$ELSE}
  RegisterTest(TTestAESSIC.Suite);
{$ENDIF FPC}

end.
