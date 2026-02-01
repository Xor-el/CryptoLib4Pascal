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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpX25519,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestX25519 = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

    procedure CheckValue(const AN: TBytes; const AText, ASe: String);
    procedure CheckECDHVector(const ASa, ASaPub, ASb, ASbPub, ASk, AText: String);
    procedure CheckIterated(ACount: Int32);
    procedure CheckX25519Vector(const ASk, ASu, ASe, AText: String);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestConsistency();
    procedure TestECDH();
    procedure TestECDHVector1();
    procedure TestX25519Iterated();
    //procedure TestX25519IteratedFull(); //intentionally excluded as it takes a long time as expected.
    procedure TestX25519Vector1();
    procedure TestX25519Vector2();
  end;

implementation

{ TTestX25519 }

procedure TTestX25519.CheckValue(const AN: TBytes; const AText, ASe: String);
var
  LE: TBytes;
begin
  LE := DecodeHex(ASe);
  CheckTrue(AreEqual(LE, AN), AText);
end;

procedure TTestX25519.CheckECDHVector(const ASa, ASaPub, ASb, ASbPub, ASk,
  AText: String);
var
  LA, LB, LAPub, LBPub, LAK, LBK: TBytes;
begin
  LA := DecodeHex(ASa);
  CheckEquals(TX25519.ScalarSize, System.Length(LA), AText);

  LB := DecodeHex(ASb);
  CheckEquals(TX25519.ScalarSize, System.Length(LB), AText);

  System.SetLength(LAPub, TX25519.PointSize);
  TX25519.ScalarMultBase(LA, 0, LAPub, 0);
  CheckValue(LAPub, AText, ASaPub);

  System.SetLength(LBPub, TX25519.PointSize);
  TX25519.ScalarMultBase(LB, 0, LBPub, 0);
  CheckValue(LBPub, AText, ASbPub);

  System.SetLength(LAK, TX25519.PointSize);
  TX25519.ScalarMult(LA, 0, LBPub, 0, LAK, 0);
  CheckValue(LAK, AText, ASk);

  System.SetLength(LBK, TX25519.PointSize);
  TX25519.ScalarMult(LB, 0, LAPub, 0, LBK, 0);
  CheckValue(LBK, AText, ASk);
end;

procedure TTestX25519.CheckIterated(ACount: Int32);
var
  LK, LU, LR: TBytes;
  LIterations: Int32;
begin
  CheckEquals(TX25519.PointSize, TX25519.ScalarSize, 'PointSize = ScalarSize');

  System.SetLength(LK, TX25519.PointSize);
  LK[0] := 9;
  System.SetLength(LU, TX25519.PointSize);
  LU[0] := 9;
  System.SetLength(LR, TX25519.PointSize);

  LIterations := 0;
  while LIterations < ACount do
  begin
    TX25519.ScalarMult(LK, 0, LU, 0, LR, 0);

    System.Move(LK[0], LU[0], TX25519.PointSize);
    System.Move(LR[0], LK[0], TX25519.PointSize);

    System.Inc(LIterations);
    case LIterations of
      1:
        CheckValue(LK, 'Iterated @1',
          '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079');
      1000:
        CheckValue(LK, 'Iterated @1000',
          '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51');
      1000000:
        CheckValue(LK, 'Iterated @1000000',
          '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424');
    else
      ;
    end;
  end;
end;

procedure TTestX25519.CheckX25519Vector(const ASk, ASu, ASe, AText: String);
var
  LK, LU, LR: TBytes;
begin
  LK := DecodeHex(ASk);
  CheckEquals(TX25519.ScalarSize, System.Length(LK), AText);

  LU := DecodeHex(ASu);
  CheckEquals(TX25519.PointSize, System.Length(LU), AText);

  System.SetLength(LR, TX25519.PointSize);
  TX25519.ScalarMult(LK, 0, LU, 0, LR, 0);
  CheckValue(LR, AText, ASe);
end;

procedure TTestX25519.SetUp;
begin
  inherited SetUp();
  FRandom := TSecureRandom.Create();
  TX25519.Precompute();
end;

procedure TTestX25519.TearDown;
begin
  FRandom := nil;
  inherited TearDown();
end;

procedure TTestX25519.TestConsistency();
var
  LU, LK, LRf, LRv: TBytes;
  LI: Int32;
begin
  System.SetLength(LU, TX25519.PointSize);
  LU[0] := 9;
  System.SetLength(LK, TX25519.ScalarSize);
  System.SetLength(LRf, TX25519.PointSize);
  System.SetLength(LRv, TX25519.PointSize);

  for LI := 1 to 100 do
  begin
    FRandom.NextBytes(LK);
    TX25519.ScalarMultBase(LK, 0, LRf, 0);
    TX25519.ScalarMult(LK, 0, LU, 0, LRv, 0);
    CheckTrue(AreEqual(LRf, LRv), Format('Consistency #%d', [LI]));
  end;
end;

procedure TTestX25519.TestECDH();
var
  LKa, LKb, LQa, LQb, LSa, LSb: TBytes;
  LRa, LRb: Boolean;
  LI: Int32;
begin
  System.SetLength(LKa, TX25519.ScalarSize);
  System.SetLength(LKb, TX25519.ScalarSize);
  System.SetLength(LQa, TX25519.PointSize);
  System.SetLength(LQb, TX25519.PointSize);
  System.SetLength(LSa, TX25519.PointSize);
  System.SetLength(LSb, TX25519.PointSize);

  for LI := 1 to 100 do
  begin
    TX25519.GeneratePrivateKey(FRandom, LKa);
    TX25519.GeneratePrivateKey(FRandom, LKb);

    TX25519.GeneratePublicKey(LKa, 0, LQa, 0);
    TX25519.GeneratePublicKey(LKb, 0, LQb, 0);

    LRa := TX25519.CalculateAgreement(LKa, 0, LQb, 0, LSa, 0);
    LRb := TX25519.CalculateAgreement(LKb, 0, LQa, 0, LSb, 0);

    CheckTrue((LRa = LRb) and AreEqual(LSa, LSb), Format('ECDH #%d', [LI]));
  end;
end;

procedure TTestX25519.TestECDHVector1();
begin
  CheckECDHVector(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    'ECDH Vector #1');
end;

procedure TTestX25519.TestX25519Iterated();
begin
  CheckIterated(1000);
end;
(*
procedure TTestX25519.TestX25519IteratedFull();
begin
  CheckIterated(1000000);
end; *)

procedure TTestX25519.TestX25519Vector1();
begin
  CheckX25519Vector(
    'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    'Vector #1');
end;

procedure TTestX25519.TestX25519Vector2();
begin
  CheckX25519Vector(
    '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    'Vector #2');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX25519);
{$ELSE}
  RegisterTest(TTestX25519.Suite);
{$ENDIF FPC}

end.
