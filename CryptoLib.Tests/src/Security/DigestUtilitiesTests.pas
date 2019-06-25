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

unit DigestUtilitiesTests;

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
  HlpIHashInfo,
  HlpHashFactory,
  ClpIDigest,
  ClpDigest,
  ClpDigestUtilities,
  CryptoLibTestBase;

type

  TTestDigestUtilities = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FTestBytes: TBytes;

    function MakeTestPlainDigest(const digest: IDigest): TBytes;
    procedure CheckPlainDigestAlgorithm(const name: String;
      const digest: IDigest);

    function MakeTestXofDigest(const digest: IDigest; count: Int32): TBytes;
    procedure CheckXofDigestAlgorithm(const name: String;
      const digest: IDigest);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestAlgorithms();

  end;

implementation

{ TTestDigestUtilities }

procedure TTestDigestUtilities.SetUp;
begin
  inherited;
  System.SetLength(FTestBytes, 100);
end;

procedure TTestDigestUtilities.TearDown;
begin
  FTestBytes := Nil;
  inherited;
end;

function TTestDigestUtilities.MakeTestXofDigest(const digest: IDigest;
  count: Int32): TBytes;
begin
  System.SetLength(Result, count);
  digest.BlockUpdate(FTestBytes, 0, System.Length(FTestBytes));
  digest.DoFinal(Result, 0);
end;

function TTestDigestUtilities.MakeTestPlainDigest(const digest
  : IDigest): TBytes;
var
  i: Int32;
begin
  for i := 0 to System.Pred(digest.GetDigestSize()) do
  begin
    digest.Update(Byte(i));
  end;

  digest.BlockUpdate(FTestBytes, 0, System.Length(FTestBytes));

  Result := TDigestUtilities.DoFinal(digest);
end;

procedure TTestDigestUtilities.CheckXofDigestAlgorithm(const name: String;
  const digest: IDigest);
var
  hash1, hash2: TBytes;
  i: Int32;
begin
  for i := 1 to 100 do
  begin
    hash1 := MakeTestXofDigest(digest, i);
    hash2 := MakeTestXofDigest(TDigestUtilities.GetDigest(name), i);

    if not AreEqual(hash1, hash2) then
    begin
      Fail(Format
        ('%s (%d) at Index %d CheckXofDigestAlgorithm Operation Failed',
        [name, (digest as IXOF).XOFSizeInBits, i]));
    end;
  end;
end;

procedure TTestDigestUtilities.CheckPlainDigestAlgorithm(const name: String;
  const digest: IDigest);
var
  hash1, hash2: TBytes;
begin
  hash1 := MakeTestPlainDigest(digest);
  hash2 := MakeTestPlainDigest(TDigestUtilities.GetDigest(name));

  if not AreEqual(hash1, hash2) then
  begin
    Fail(Format('%s CheckPlainDigestAlgorithm Operation Failed', [name]));
  end;
end;

procedure TTestDigestUtilities.TestAlgorithms;
begin
  // plain digest test
  CheckPlainDigestAlgorithm('MD2',
    TDigest.Create(THashFactory.TCrypto.CreateMD2()) as IDigest);

  CheckPlainDigestAlgorithm('MD4',
    TDigest.Create(THashFactory.TCrypto.CreateMD4()) as IDigest);

  CheckPlainDigestAlgorithm('MD5',
    TDigest.Create(THashFactory.TCrypto.CreateMD5()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-1',
    TDigest.Create(THashFactory.TCrypto.CreateSHA1()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-224',
    TDigest.Create(THashFactory.TCrypto.CreateSHA2_224()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-256',
    TDigest.Create(THashFactory.TCrypto.CreateSHA2_256()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-384',
    TDigest.Create(THashFactory.TCrypto.CreateSHA2_384()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-512',
    TDigest.Create(THashFactory.TCrypto.CreateSHA2_512()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-512/224',
    TDigest.Create(THashFactory.TCrypto.CreateSHA2_512_224()) as IDigest);

  CheckPlainDigestAlgorithm('SHA-512/256',
    TDigest.Create(THashFactory.TCrypto.CreateSHA2_512_256()) as IDigest);

  CheckPlainDigestAlgorithm('KECCAK224',
    TDigest.Create(THashFactory.TCrypto.CreateKeccak_224()) as IDigest);

  CheckPlainDigestAlgorithm('KECCAK256',
    TDigest.Create(THashFactory.TCrypto.CreateKeccak_256()) as IDigest);

  CheckPlainDigestAlgorithm('KECCAK288',
    TDigest.Create(THashFactory.TCrypto.CreateKeccak_288()) as IDigest);

  CheckPlainDigestAlgorithm('KECCAK384',
    TDigest.Create(THashFactory.TCrypto.CreateKeccak_384()) as IDigest);

  CheckPlainDigestAlgorithm('KECCAK512',
    TDigest.Create(THashFactory.TCrypto.CreateKeccak_512()) as IDigest);

  CheckPlainDigestAlgorithm('SHA3-224',
    TDigest.Create(THashFactory.TCrypto.CreateSHA3_224()) as IDigest);

  CheckPlainDigestAlgorithm('SHA3-256',
    TDigest.Create(THashFactory.TCrypto.CreateSHA3_256()) as IDigest);

  CheckPlainDigestAlgorithm('SHA3-384',
    TDigest.Create(THashFactory.TCrypto.CreateSHA3_384()) as IDigest);

  CheckPlainDigestAlgorithm('SHA3-512',
    TDigest.Create(THashFactory.TCrypto.CreateSHA3_512()) as IDigest);

  CheckXofDigestAlgorithm('SHAKE128',
    TDigest.Create(THashFactory.TXOF.CreateShake_128(128)) as IDigest);

  CheckXofDigestAlgorithm('SHAKE256',
    TDigest.Create(THashFactory.TXOF.CreateShake_256(256)) as IDigest);

  CheckPlainDigestAlgorithm('RIPEMD128',
    TDigest.Create(THashFactory.TCrypto.CreateRIPEMD128()) as IDigest);

  CheckPlainDigestAlgorithm('RIPEMD160',
    TDigest.Create(THashFactory.TCrypto.CreateRIPEMD160()) as IDigest);

  CheckPlainDigestAlgorithm('RIPEMD256',
    TDigest.Create(THashFactory.TCrypto.CreateRIPEMD256()) as IDigest);

  CheckPlainDigestAlgorithm('RIPEMD320',
    TDigest.Create(THashFactory.TCrypto.CreateRIPEMD320()) as IDigest);

  CheckPlainDigestAlgorithm('GOST3411',
    TDigest.Create(THashFactory.TCrypto.CreateGost()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2B-160',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2B_160()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2B-256',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2B_256()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2B-384',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2B_384()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2B-512',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2B_512()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2S-128',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2S_128()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2S-160',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2S_160()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2S-224',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2S_224()) as IDigest);

  CheckPlainDigestAlgorithm('BLAKE2S-256',
    TDigest.Create(THashFactory.TCrypto.CreateBlake2S_256()) as IDigest);

  CheckPlainDigestAlgorithm('GOST3411-2012-256',
    TDigest.Create(THashFactory.TCrypto.CreateGOST3411_2012_256()) as IDigest);

  CheckPlainDigestAlgorithm('GOST3411-2012-512',
    TDigest.Create(THashFactory.TCrypto.CreateGOST3411_2012_512()) as IDigest);

  CheckPlainDigestAlgorithm('Tiger',
    TDigest.Create(THashFactory.TCrypto.CreateTiger_3_192()) as IDigest);

  CheckPlainDigestAlgorithm('Whirlpool',
    TDigest.Create(THashFactory.TCrypto.CreateWhirlPool()) as IDigest);

  // Xof test
  CheckXofDigestAlgorithm('SHAKE128',
    TDigest.Create(THashFactory.TXOF.CreateShake_128(128)) as IDigest);

  CheckXofDigestAlgorithm('SHAKE256',
    TDigest.Create(THashFactory.TXOF.CreateShake_256(256)) as IDigest);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestDigestUtilities);
{$ELSE}
  RegisterTest(TTestDigestUtilities.Suite);
{$ENDIF FPC}

end.
