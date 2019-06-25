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
    (DecodeHex('2B7E151628AED2A6ABF7158809CF4F3C'),
    DecodeHex('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B'),
    DecodeHex(
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4'));

  Fplain := TCryptoLibMatrixByteArray.Create
    (DecodeHex('6BC1BEE22E409F96E93D7E117393172A'),
    DecodeHex('AE2D8A571E03AC9C9EB76FAC45AF8E51'),
    DecodeHex('30C81C46A35CE411E5FBC1191A0A52EF'),
    DecodeHex('F69F2445DF4F9B17AD2B417BE66C3710'));

  Fcipher := TCryptoLibGenericArray<TCryptoLibMatrixByteArray>.Create
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
      DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')) as IParametersWithIV);

    j := 0;
    while j <> System.Length(Fplain) do
    begin
      enc := c.ProcessBytes(Fplain[j]);
      if (not AreEqual(enc, Fcipher[i, j])) then
      begin
        Fail('AESSIC encrypt failed: key ' + IntToStr(i) + ' block ' +
          IntToStr(j));
      end;
      System.Inc(j);
    end;

    c.Init(false, TParametersWithIV.Create(skey,
      DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')) as IParametersWithIV);

    j := 0;
    while j <> System.Length(Fplain) do
    begin
      enc := c.ProcessBytes(Fcipher[i, j]);
      if (not AreEqual(enc, Fplain[j])) then
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
    DecodeHex('2B7E151628AED2A6ABF7158809CF4F3C'));

  c.Init(true, TParametersWithIV.Create(sk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  crypt := c.DoFinal(DecodeHex('00000000000000000000000000000000'));

  if (not AreEqual(crypt, DecodeHex('D23513162B02D0F72A43A2FE4A5F97AB'))) then
  begin
    Fail('AESSIC failed test 2');
  end;

  //
  // check partial block processing
  //
  c := TCipherUtilities.GetCipher('AES/CTR/NoPadding');

  sk := TParameterUtilities.CreateKeyParameter('AES',
    DecodeHex('2B7E151628AED2A6ABF7158809CF4F3C'));

  c.Init(true, TParametersWithIV.Create(sk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  crypt := c.DoFinal(DecodeHex('12345678'));

  c.Init(false, TParametersWithIV.Create(sk,
    DecodeHex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001')) as IParametersWithIV);

  crypt := c.DoFinal(crypt);

  if (not AreEqual(crypt, DecodeHex('12345678'))) then
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
