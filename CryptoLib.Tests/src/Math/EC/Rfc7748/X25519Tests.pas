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

unit X25519Tests;

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
  ClpX25519,
  ClpSecureRandom,
  ClpISecureRandom,
  CryptoLibTestBase;

type

  TTestX25519 = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

    procedure CheckECDHVector(const sA, sAPub, sB, sBPub, sK, text: String);
    procedure CheckIterated(count: Int32);
    procedure CheckValue(const n: TBytes; const text, se: String);
    procedure CheckX25519Vector(const sK, su, se, text: String);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestConsistency();
    procedure TestECDH();
    procedure TestECDHVector1();
    procedure TestX25519Iterated();
    // disabled because it takes a lot of time
    // procedure TestX25519IteratedFull();
    procedure TestX25519Vector1();
    procedure TestX25519Vector2();

  end;

implementation

{ TTestX25519 }

procedure TTestX25519.CheckECDHVector(const sA, sAPub, sB, sBPub, sK,
  text: String);
var
  a, b, aPub, bPub, aK, bK: TBytes;
begin
  a := DecodeHex(sA);
  CheckEquals(TX25519.ScalarSize, System.Length(a));

  b := DecodeHex(sB);
  CheckEquals(TX25519.ScalarSize, System.Length(b));

  System.SetLength(aPub, TX25519.PointSize);

  TX25519.ScalarMultBase(a, 0, aPub, 0);
  CheckValue(aPub, text, sAPub);

  System.SetLength(bPub, TX25519.PointSize);
  TX25519.ScalarMultBase(b, 0, bPub, 0);
  CheckValue(bPub, text, sBPub);

  System.SetLength(aK, TX25519.PointSize);

  TX25519.ScalarMult(a, 0, bPub, 0, aK, 0);
  CheckValue(aK, text, sK);

  System.SetLength(bK, TX25519.PointSize);

  TX25519.ScalarMult(b, 0, aPub, 0, bK, 0);
  CheckValue(bK, text, sK);
end;

procedure TTestX25519.CheckIterated(count: Int32);
var
  k, u, r: TBytes;
  iterations: Int32;
begin
  CheckEquals(TX25519.PointSize, TX25519.ScalarSize);

  System.SetLength(k, TX25519.PointSize);
  k[0] := 9;
  System.SetLength(u, TX25519.PointSize);
  u[0] := 9;
  System.SetLength(r, TX25519.PointSize);

  iterations := 0;

  while (iterations < count) do
  begin

    TX25519.ScalarMult(k, 0, u, 0, r, 0);

    System.Move(k[0], u[0], TX25519.PointSize * System.SizeOf(Byte));
    System.Move(r[0], k[0], TX25519.PointSize * System.SizeOf(Byte));

    System.Inc(iterations);
    case iterations of
      1:
        CheckValue(k, 'Iterated @1',
          '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079');
      1000:
        CheckValue(k, 'Iterated @1000',
          '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51');
      1000000:
        CheckValue(k, 'Iterated @1000000',
          '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424');
    end;

  end;
end;

procedure TTestX25519.CheckValue(const n: TBytes; const text, se: String);
var
  e: TBytes;
begin
  e := DecodeHex(se);
  CheckTrue(AreEqual(e, n), text);
end;

procedure TTestX25519.CheckX25519Vector(const sK, su, se, text: String);
var
  k, u, r: TBytes;
begin
  k := DecodeHex(sK);
  CheckEquals(TX25519.ScalarSize, System.Length(k));

  u := DecodeHex(su);
  CheckEquals(TX25519.PointSize, System.Length(u));

  System.SetLength(r, TX25519.PointSize);
  TX25519.ScalarMult(k, 0, u, 0, r, 0);
  CheckValue(r, text, se);
end;

procedure TTestX25519.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
  TX25519.Precompute();
end;

procedure TTestX25519.TearDown;
begin
  inherited;
end;

procedure TTestX25519.TestConsistency;
var
  u, k, rF, rV: TBytes;
  i: Int32;
begin
  System.SetLength(u, TX25519.PointSize);
  u[0] := 9;
  System.SetLength(k, TX25519.ScalarSize);
  System.SetLength(rF, TX25519.PointSize);
  System.SetLength(rV, TX25519.PointSize);

  for i := 1 to 100 do
  begin
    FRandom.NextBytes(k);
    TX25519.ScalarMultBase(k, 0, rF, 0);
    TX25519.ScalarMult(k, 0, u, 0, rV, 0);
    CheckTrue(AreEqual(rF, rV), Format('Consistency #%d', [i]));
  end;
end;

procedure TTestX25519.TestECDH;
var
  kA, Kb, qA, qB, sA, sB: TBytes;
  i: Int32;
begin
  System.SetLength(kA, TX25519.ScalarSize);
  System.SetLength(Kb, TX25519.ScalarSize);
  System.SetLength(qA, TX25519.PointSize);
  System.SetLength(qB, TX25519.PointSize);
  System.SetLength(sA, TX25519.PointSize);
  System.SetLength(sB, TX25519.PointSize);

  for i := 1 to 100 do
  begin
    // Each party generates an ephemeral private key, ...
    FRandom.NextBytes(kA);
    FRandom.NextBytes(Kb);

    // ... publishes their public key, ...
    TX25519.ScalarMultBase(kA, 0, qA, 0);
    TX25519.ScalarMultBase(Kb, 0, qB, 0);

    // ... computes the shared secret, ...
    TX25519.ScalarMult(kA, 0, qB, 0, sA, 0);
    TX25519.ScalarMult(Kb, 0, qA, 0, sB, 0);

    // ... which is the same for both parties.
    if (not AreEqual(sA, sB)) then
    begin
      Fail(Format(' %d', [i]));
    end;
  end;
end;

procedure TTestX25519.TestECDHVector1;
begin
  CheckECDHVector
    ('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    'ECDH Vector #1');
end;

procedure TTestX25519.TestX25519Iterated;
begin
  CheckIterated(1000);
end;

// procedure TTestX25519.TestX25519IteratedFull;
// begin
// CheckIterated(1000000);
// end;

procedure TTestX25519.TestX25519Vector1;
begin
  CheckX25519Vector
    ('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    'Vector #1');
end;

procedure TTestX25519.TestX25519Vector2;
begin
  CheckX25519Vector
    ('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    'Vector #2');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestX25519);
{$ELSE}
  RegisterTest(TTestX25519.Suite);
{$ENDIF FPC}

end.
