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

unit Kdf1GeneratorTests;

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
  ClpIIso18033KdfParameters,
  ClpIso18033KdfParameters,
  ClpKdf1BytesGenerator,
  ClpIKdf1BytesGenerator,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// KDF1 tests - vectors from ISO 18033.
  /// </summary>
  TTestKdf1Generator = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fseed1, Fmask1, Fseed2, Fmask2, Fseed3, Fmask3: TBytes;

    procedure CheckMask(count: Int32; const kdf: IDerivationFunction;
      const seed, result: TBytes);
    procedure DoTestKdf1Generator();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestKdf1Generator;

  end;

implementation

{ TTestKdf1Generator }

procedure TTestKdf1Generator.CheckMask(count: Int32;
  const kdf: IDerivationFunction; const seed, result: TBytes);
var
  data: TBytes;
begin
  System.SetLength(data, System.Length(result));

  kdf.Init(TIso18033KdfParameters.Create(seed) as IIso18033KdfParameters);

  kdf.GenerateBytes(data, 0, System.Length(data));

  if (not AreEqual(result, data)) then
  begin
    Fail(Format('KDF1 failed generator test %d', [count]));
  end;
end;

procedure TTestKdf1Generator.DoTestKdf1Generator;
var
  temp: TBytes;
begin

  CheckMask(1, TKdf1BytesGenerator.Create(TShortenedDigest.Create
    (TDigestUtilities.GetDigest('SHA-256'), 20) as IShortenedDigest)
    as IKdf1BytesGenerator, Fseed1, Fmask1);

  CheckMask(2, TKdf1BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKdf1BytesGenerator, Fseed2, Fmask2);

  CheckMask(3, TKdf1BytesGenerator.Create(TShortenedDigest.Create
    (TDigestUtilities.GetDigest('SHA-256'), 20) as IShortenedDigest)
    as IKdf1BytesGenerator, Fseed3, Fmask3);

  try
    System.SetLength(temp, 10);
    (TKdf1BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
      as IKdf1BytesGenerator).GenerateBytes(temp, 0, 20);
    Fail('short input array not caught');
  except
    on e: EDataLengthCryptoLibException do
    begin
      // expected
    end;

  end;
end;

procedure TTestKdf1Generator.SetUp;
begin
  inherited;
  Fseed1 := DecodeHex('d6e168c5f256a2dcff7ef12facd390f393c7a88d');
  Fmask1 := DecodeHex('0742ba966813af75536bb6149cc44fc256fd6406df79665bc31dc5' +
    'a62f70535e52c53015b9d37d412ff3c1193439599e1b628774c50d9c' +
    'cb78d82c425e4521ee47b8c36a4bcffe8b8112a89312fc04420a39de' +
    '99223890e74ce10378bc515a212b97b8a6447ba6a8870278');

  Fseed2 := DecodeHex
    ('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741' +
    '52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');
  Fmask2 := DecodeHex
    ('5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca9' +
    '75bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263c' +
    'fccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e' +
    '7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04');

  Fseed3 := Fseed2;

  Fmask3 := DecodeHex
    ('09e2decf2a6e1666c2f6071ff4298305e2643fd510a2403db42a8743cb989de86e' +
    '668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa' +
    '70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb5' +
    '55c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb');
end;

procedure TTestKdf1Generator.TearDown;
begin
  inherited;

end;

procedure TTestKdf1Generator.TestKdf1Generator;
begin
  DoTestKdf1Generator();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestKdf1Generator);
{$ELSE}
  RegisterTest(TTestKdf1Generator.Suite);
{$ENDIF FPC}

end.
