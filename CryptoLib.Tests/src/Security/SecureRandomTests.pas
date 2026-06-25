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

unit SecureRandomTests;

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
  ClpOSRandomProvider,
  ClpAesRandomProvider,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpRandomNumberGenerator,
  ClpIRandomNumberGenerator,
  ClpCryptoApiRandomGenerator,
  ClpICryptoApiRandomGenerator,
  ClpIRandomGenerator,
  ClpCryptoLibTypes,
  ClpDigestUtilities,
  ClpIDigest,
  ClpHMac,
  ClpIMac,
  ClpIBlockCipher,
  ClpAesUtilities,
  ClpISP800SecureRandomBuilder,
  ClpSP800SecureRandomBuilder,
  CryptoLibTestBase;

type

  TTestSecureRandom = class(TCryptoLibAlgorithmTestCase)
  private

    procedure CheckSecureRandom(const random: ISecureRandom);
    function RunChiSquaredTests(const random: ISecureRandom): Boolean;
    function MeasureChiSquared(const random: ISecureRandom;
      rounds: Int32): Double;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCryptoApi();
    procedure TestOSRandom();
    procedure TestAESPRNG();
    procedure TestAESPRNGRandom();
    procedure TestDefault();
    procedure TestNextDouble();
    procedure TestSha1Prng();
    procedure TestSha1PrngReplicable();
    procedure TestSha256Prng();
    /// <summary>Smoke test for AES CTR_DRBG via <see cref="TSP800SecureRandomBuilder"/>.</summary>
    procedure TestSP800Ctr();
    /// <summary>Smoke test for Hash_DRBG via <see cref="TSP800SecureRandomBuilder"/>.</summary>
    procedure TestSP800Hash();
    /// <summary>Smoke test for HMAC_DRBG via <see cref="TSP800SecureRandomBuilder"/>.</summary>
    procedure TestSP800HMac();

  end;

implementation

type
  TTestRandomGenerator = class abstract(TInterfacedObject, IRandomGenerator)
  public
    procedure AddSeedMaterial(const ASeed: TCryptoLibByteArray); overload; virtual;
    procedure AddSeedMaterial(ASeed: Int64); overload; virtual;
    procedure NextBytes(const ABytes: TCryptoLibByteArray); overload; virtual;
    procedure NextBytes(const ABytes: TCryptoLibByteArray; AStart, ALen: Int32);
      overload; virtual; abstract;
  end;

  TFixedRandomGenerator = class sealed(TTestRandomGenerator)
  strict private
    FB: Byte;
  public
    constructor Create(AB: Byte);
    procedure NextBytes(const ABytes: TCryptoLibByteArray; AStart, ALen: Int32);
      overload; override;
  end;

{ TFixedRandomGenerator }

constructor TFixedRandomGenerator.Create(AB: Byte);
begin
  inherited Create;
  FB := AB;
end;

procedure TFixedRandomGenerator.NextBytes(const ABytes: TCryptoLibByteArray;
  AStart, ALen: Int32);
var
  LI: Int32;
begin
  for LI := AStart to AStart + ALen - 1 do
  begin
    ABytes[LI] := FB;
  end;
end;

{ TTestRandomGenerator }

procedure TTestRandomGenerator.AddSeedMaterial(const ASeed: TCryptoLibByteArray);
begin
end;

procedure TTestRandomGenerator.AddSeedMaterial(ASeed: Int64);
begin
end;

procedure TTestRandomGenerator.NextBytes(const ABytes: TCryptoLibByteArray);
begin
  NextBytes(ABytes, 0, System.Length(ABytes));
end;

{ TTestSecureRandom }

procedure TTestSecureRandom.CheckSecureRandom(const random: ISecureRandom);
begin
  // Note: This will periodically (< 1e-6 probability) give a false alarm.
  // That's randomness for you!
  CheckEquals(true, RunChiSquaredTests(random),
    'Chi2 test detected possible non-randomness');
end;

function TTestSecureRandom.MeasureChiSquared(const random: ISecureRandom;
  rounds: Int32): Double;
var
  opts, bs: TBytes;
  counts: TCryptoLibInt32Array;
  I, b, total, k, mask, shift: Int32;
  chi2, diff, diff2, temp: Double;
begin
  opts := random.GenerateSeed(2);
  System.SetLength(counts, 256);
  System.SetLength(bs, 256);

  I := 0;
  while I < rounds do
  begin
    random.NextBytes(bs);

    for b := 0 to System.Pred(256) do
    begin

      counts[bs[b]] := counts[bs[b]] + 1;

    end;

    System.Inc(I);
  end;

  mask := opts[0];

  I := 0;
  while I < rounds do
  begin
    random.NextBytes(bs);

    for b := 0 to System.Pred(256) do
    begin

      counts[bs[b] xor Byte(mask)] := counts[bs[b] xor Byte(mask)] + 1;

    end;
    System.Inc(mask);
    System.Inc(I);
  end;

  shift := opts[1];

  I := 0;
  while I < rounds do
  begin
    random.NextBytes(bs);

    for b := 0 to System.Pred(256) do
    begin

      counts[Byte(bs[b] + Byte(shift))] :=
        counts[Byte(bs[b] + Byte(shift))] + 1;

    end;
    System.Inc(shift);
    System.Inc(I);
  end;

  total := 3 * rounds;

  chi2 := 0;

  for k := 0 to System.Pred(System.Length(counts)) do
  begin
    temp := counts[k];
    diff := temp - total;
    diff2 := diff * diff;

    chi2 := chi2 + diff2;
  end;

  chi2 := chi2 / total;

  result := chi2;
end;

function TTestSecureRandom.RunChiSquaredTests(const random
  : ISecureRandom): Boolean;
var
  passes, tries: Int32;
  chi2: Double;
begin
  passes := 0;

  tries := 0;
  while tries < 100 do
  begin
    chi2 := MeasureChiSquared(random, 1000);

    // 255 degrees of freedom in test => Q ~ 10.0% for 285
    if (chi2 < 285.0) then
    begin
      System.Inc(passes);
    end;

    System.Inc(tries);
  end;

  result := passes > 75;
end;

procedure TTestSecureRandom.SetUp;
begin
  inherited;

end;

procedure TTestSecureRandom.TearDown;
begin
  inherited;

end;

procedure TTestSecureRandom.TestOSRandom;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create(TCryptoApiRandomGenerator.Create
    (TRandomNumberGenerator.CreateRng(TOSRandomProvider.Instance))
    as ICryptoApiRandomGenerator);

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestAESPRNG;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create(TCryptoApiRandomGenerator.Create
    (TRandomNumberGenerator.CreateRng(TAesRandomProvider.Instance))
    as ICryptoApiRandomGenerator);

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestAESPRNGRandom;
const
  // For very small buffers two independent random draws can legitimately be
  // equal (e.g. a single byte collides with probability 1/256). Retrying a
  // few times distinguishes ordinary randomness (which diverges on retry)
  // from a genuinely stuck RNG (which keeps returning identical output).
  MaxCollisionRetries = Int32(8);
var
  b1, b2: TBytes;
  a1, a2: IRandomNumberGenerator;
  Idx, Retry: Int32;
begin
  // it is hard to validate randomness - we just test the feature set
  b1 := nil;
  b2 := nil;
  System.SetLength(b1, 16);
  System.SetLength(b2, 16);
  TAesRandomProvider.Instance.GetBytes(b1);
  TAesRandomProvider.Instance.GetBytes(b2);

  CheckTrue(not AreEqual(b1, b2));

  a1 := TRandomNumberGenerator.CreateRng(TAesRandomProvider.Instance);
  a2 := TRandomNumberGenerator.CreateRng(TAesRandomProvider.Instance);

  a1.GetBytes(b1);
  a2.GetBytes(b2);
  CheckTrue(not AreEqual(b1, b2));

  for Idx := 1 to 10000 do
  begin
    b1 := nil;
    b2 := nil;
    System.SetLength(b1, Idx);
    System.SetLength(b2, Idx);
    a1.GetBytes(b1);
    a2.GetBytes(b2);

    Retry := 0;
    while AreEqual(b1, b2) and (Retry < MaxCollisionRetries) do
    begin
      a1.GetBytes(b1);
      a2.GetBytes(b2);
      System.Inc(Retry);
    end;

    CheckTrue(not AreEqual(b1, b2));
  end;

end;

procedure TTestSecureRandom.TestCryptoApi;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create(TCryptoApiRandomGenerator.Create()
    as ICryptoApiRandomGenerator);

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestDefault;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create();

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestNextDouble;
var
  LRandom: ISecureRandom;
  LValue: Double;
begin
  LRandom := TSecureRandom.Create(TFixedRandomGenerator.Create($00) as IRandomGenerator);
  LValue := LRandom.NextDouble();
  CheckTrue(LValue >= 0.0);
  CheckTrue(LValue < 1.0);

  LRandom := TSecureRandom.Create(TFixedRandomGenerator.Create($FF) as IRandomGenerator);
  LValue := LRandom.NextDouble();
  CheckTrue(LValue >= 0.0);
  CheckTrue(LValue < 1.0);
end;

procedure TTestSecureRandom.TestSha1PrngReplicable;
var
  LRandom, LSx, LSy: ISecureRandom;
  LSeed, LBx, LBy: TBytes;
begin
  LRandom := TSecureRandom.Create();
  LSeed := TSecureRandom.GetNextBytes(LRandom, 16);
  LSx := TSecureRandom.GetInstance('SHA1PRNG', False);
  LSy := TSecureRandom.GetInstance('SHA1PRNG', False);
  LSx.SetSeed(LSeed);
  LSy.SetSeed(LSeed);
  System.SetLength(LBx, 128);
  System.SetLength(LBy, 128);
  LSx.NextBytes(LBx);
  LSy.NextBytes(LBy);
  CheckTrue(AreEqual(LBx, LBy));
end;

procedure TTestSecureRandom.TestSha1Prng;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.GetInstance('SHA1PRNG');

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestSha256Prng;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.GetInstance('SHA256PRNG');

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestSP800Ctr;
var
  LNonce: TCryptoLibByteArray;
  LBuilder: ISP800SecureRandomBuilder;
  LEngine: IBlockCipher;
  LRandom: ISecureRandom;
begin
  System.SetLength(LNonce, 32);
  LBuilder := TSP800SecureRandomBuilder.Create();
  LEngine := TAesUtilities.CreateEngine();
  LRandom := LBuilder.BuildCtr(LEngine, 256, LNonce, False);

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestSP800Hash;
var
  LNonce: TCryptoLibByteArray;
  LBuilder: ISP800SecureRandomBuilder;
  LDigest: IDigest;
  LRandom: ISecureRandom;
begin
  System.SetLength(LNonce, 32);
  LBuilder := TSP800SecureRandomBuilder.Create();
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LRandom := LBuilder.BuildHash(LDigest, LNonce, False);

  CheckSecureRandom(LRandom);
end;

procedure TTestSecureRandom.TestSP800HMac;
var
  LNonce: TCryptoLibByteArray;
  LBuilder: ISP800SecureRandomBuilder;
  LDigest: IDigest;
  LHMac: IMac;
  LRandom: ISecureRandom;
begin
  System.SetLength(LNonce, 32);
  LBuilder := TSP800SecureRandomBuilder.Create();
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LHMac := THMac.Create(LDigest);
  LRandom := LBuilder.BuildHMac(LHMac, LNonce, False);

  CheckSecureRandom(LRandom);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSecureRandom);
{$ELSE}
  RegisterTest(TTestSecureRandom.Suite);
{$ENDIF FPC}

end.
