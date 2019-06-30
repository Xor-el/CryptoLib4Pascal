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

unit Kdf2GeneratorTests;

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
  ClpShortenedDigest,
  ClpIShortenedDigest,
  ClpIDerivationFunction,
  ClpKdfParameters,
  ClpIKdfParameters,
  ClpKdf2BytesGenerator,
  ClpIKdf2BytesGenerator,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// KDF2 tests - vectors from ISO 18033.
  /// </summary>
  TTestKdf2Generator = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fseed1, Fmask1, Fseed2, Fmask2, Fseed3, Fmask3, Fseed4, Fmask4,
      FadjustedMask2, Fsha1Mask: TBytes;

    procedure CheckMask(count: Int32; const kdf: IDerivationFunction;
      const seed, result: TBytes);
    procedure DoTestKdf2Generator();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestKdf2Generator;

  end;

implementation

{ TTestKdf2Generator }

procedure TTestKdf2Generator.CheckMask(count: Int32;
  const kdf: IDerivationFunction; const seed, result: TBytes);
var
  data: TBytes;
begin
  System.SetLength(data, System.Length(result));

  kdf.Init(TKdfParameters.Create(seed, Nil) as IKdfParameters);

  kdf.GenerateBytes(data, 0, System.Length(data));

  if (not AreEqual(result, data)) then
  begin
    Fail(Format('KDF2 failed generator test %d', [count]));
  end;
end;

procedure TTestKdf2Generator.DoTestKdf2Generator;
var
  temp: TBytes;
begin

  CheckMask(1, TKdf2BytesGenerator.Create(TShortenedDigest.Create
    (TDigestUtilities.GetDigest('SHA-256'), 20) as IShortenedDigest)
    as IKdf2BytesGenerator, Fseed1, Fmask1);

  CheckMask(2, TKdf2BytesGenerator.Create(TShortenedDigest.Create
    (TDigestUtilities.GetDigest('SHA-256'), 20) as IShortenedDigest)
    as IKdf2BytesGenerator, Fseed2, Fmask2);

  CheckMask(3, TKdf2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-256'))
    as IKdf2BytesGenerator, Fseed2, FadjustedMask2);

  CheckMask(4, TKdf2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKdf2BytesGenerator, Fseed2, Fsha1Mask);

  CheckMask(5, TKdf2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKdf2BytesGenerator, Fseed3, Fmask3);

  CheckMask(6, TKdf2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKdf2BytesGenerator, Fseed4, Fmask4);

  try
    System.SetLength(temp, 10);
    (TKdf2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
      as IKdf2BytesGenerator).GenerateBytes(temp, 0, 20);
    Fail('short input array not caught');
  except
    on e: EDataLengthCryptoLibException do
    begin
      // expected
    end;

  end;
end;

procedure TTestKdf2Generator.SetUp;
begin
  inherited;
  Fseed1 := DecodeHex('d6e168c5f256a2dcff7ef12facd390f393c7a88d');
  Fmask1 := DecodeHex('df79665bc31dc5a62f70535e52c53015b9d37d412ff3c119343959' +
    '9e1b628774c50d9ccb78d82c425e4521ee47b8c36a4bcffe8b8112a8' +
    '9312fc04420a39de99223890e74ce10378bc515a212b97b8a6447ba6' +
    'a8870278f0262727ca041fa1aa9f7b5d1cf7f308232fe861');

  Fseed2 := DecodeHex
    ('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741' +
    '52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');
  Fmask2 := DecodeHex
    ('10a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb456' +
    '68f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb13' +
    '19fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbac' +
    'a19f6410ee1fcb260892670e0814c348664f6a7248aaf998a3acc6');
  FadjustedMask2 :=
    DecodeHex(
    '10a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac1' +
    '79f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2' +
    'a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24875a60b4aacb131' +
    '9fa11c3365a8b79a44669f26fba933d012db213d7e3b16349');

  Fsha1Mask := DecodeHex
    ('0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32' +
    '052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a2519' +
    '2985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837ee' +
    'a4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807');

  Fseed3 := DecodeHex('CA7C0F8C3FFA87A96E1B74AC8E6AF594347BB40A');
  Fmask3 := DecodeHex('744AB703F5BC082E59185F6D049D2D367DB245C2');

  Fseed4 := DecodeHex('0499B502FC8B5BAFB0F4047E731D1F9FD8CD0D8881');
  Fmask4 := DecodeHex
    ('03C62280C894E103C680B13CD4B4AE740A5EF0C72547292F82DC6B1777F47D63BA9D1EA732DBF386');
end;

procedure TTestKdf2Generator.TearDown;
begin
  inherited;

end;

procedure TTestKdf2Generator.TestKdf2Generator;
begin
  DoTestKdf2Generator();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestKdf2Generator);
{$ELSE}
  RegisterTest(TTestKdf2Generator.Suite);
{$ENDIF FPC}

end.
