{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SignerUtilitiesTests;

interface

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  //ClpBase64,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpISigner,
  ClpECCurve,
  ClpECPoint,
  ClpIRandom,
  ClpSignerUtilities,
  ClpSecureRandom,
  ClpECDomainParameters,
  ClpICipherParameters,
  ClpIECDomainParameters,
  ClpECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpIECInterface;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  TTestSignerUtilities = class(TCryptoLibTestCase)
  private

  var
    //
    // ECDSA parameters
    //

    FECParraGX, FECParraGY, FECParraH, FECParraN, FECPubQX, FECPubQY,
      FECPrivD: TBigInteger;
    Fcurve: IECCurve;
    FecDomain: IECDomainParameters;
    FecPub: IECPublicKeyParameters;
    FecPriv: IECPrivateKeyParameters;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestAlgorithms;

  end;

implementation

{ TTestSignerUtilities }

procedure TTestSignerUtilities.SetUp;
begin
  inherited;
  // FECParraGX := TBigInteger.Create
  // (TBase64.Decode('D/qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqv'));
  // FECParraGY := TBigInteger.Create
  // (TBase64.Decode('AhQXGxb1olGRv6s1LPRfuatMF+cx3ZTGgzSE/Q5R'));
  // FECParraH := TBigInteger.Create(TBase64.Decode('AQ:=:='));
  // FECParraN := TBigInteger.Create
  // (TBase64.Decode('f///////////////f///nl6an12QcfvRUiaIkJ0L'));
  // FECPubQX := TBigInteger.Create
  // (TBase64.Decode('HWWi17Yb+Bm3PYr/DMjLOYNFhyOwX1QY7ZvqqM+l'));
  // FECPubQY := TBigInteger.Create
  // (TBase64.Decode('JrlJfxu3WGhqwtL/55BOs/wsUeiDFsvXcGhB8DGx'));
  // FECPrivD := TBigInteger.Create
  // (TBase64.Decode('GYQmd/NF1B+He1iMkWt3by2Az6Eu07t0ynJ4YCAo'));

  FECParraGX := TBigInteger.Create(TCryptoLibByteArray.Create(15, 250, 150, 60,
    220, 168, 129, 108, 204, 51, 184, 100, 43, 237, 249, 5, 195, 211, 88, 87,
    61, 63, 39, 251, 189, 59, 60, 185, 170, 175));
  FECParraGY := TBigInteger.Create(TCryptoLibByteArray.Create(2, 20, 23, 27, 22,
    245, 162, 81, 145, 191, 171, 53, 44, 244, 95, 185, 171, 76, 23, 231, 49,
    221, 148, 198, 131, 52, 132, 253, 14, 81));

  FECParraH := TBigInteger.Create(TCryptoLibByteArray.Create(1));
  FECParraN := TBigInteger.Create(TCryptoLibByteArray.Create(127, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 127, 255, 255, 158, 94, 154, 159,
    93, 144, 113, 251, 209, 82, 38, 136, 144, 157, 11));
  FECPubQX := TBigInteger.Create(TCryptoLibByteArray.Create(29, 101, 162, 215,
    182, 27, 248, 25, 183, 61, 138, 255, 12, 200, 203, 57, 131, 69, 135, 35,
    176, 95, 84, 24, 237, 155, 234, 168, 207, 165));
  FECPubQY := TBigInteger.Create(TCryptoLibByteArray.Create(38, 185, 73, 127,
    27, 183, 88, 104, 106, 194, 210, 255, 231, 144, 78, 179, 252, 44, 81, 232,
    131, 22, 203, 215, 112, 104, 65, 240, 49, 177));
  FECPrivD := TBigInteger.Create(TCryptoLibByteArray.Create(25, 132, 38, 119,
    243, 69, 212, 31, 135, 123, 88, 140, 145, 107, 119, 111, 45, 128, 207, 161,
    46, 211, 187, 116, 202, 114, 120, 96, 32, 40));

  Fcurve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16)); // b

  FecDomain := TECDomainParameters.Create(Fcurve,
    TFpPoint.Create(Fcurve, Fcurve.FromBigInteger(FECParraGX),
    Fcurve.FromBigInteger(FECParraGY)) as IFpPoint, FECParraN);

  FecPub := TECPublicKeyParameters.Create(TFpPoint.Create(Fcurve,
    Fcurve.FromBigInteger(FECPubQX), Fcurve.FromBigInteger(FECPubQY))
    as IFpPoint, FecDomain);

  FecPriv := TECPrivateKeyParameters.Create(FECPrivD, FecDomain);

end;

procedure TTestSignerUtilities.TearDown;
begin
  inherited;

end;

procedure TTestSignerUtilities.TestAlgorithms;
var
  shortMsg, longMsg, sig: TCryptoLibByteArray;
  LRandom: IRandom;
  algorithm, upper, cipherName: string;
  signer: ISigner;
  withPos: Int32;
  signParams, verifyParams: ICipherParameters;
  b: Byte;
begin
  //
  // signer loop
  //
  shortMsg := TCryptoLibByteArray.Create(1, 4, 5, 6, 8, 8, 4, 2, 1, 3);
  System.SetLength(longMsg, 100);

  LRandom := TSecureRandom.Create();
  LRandom.NextBytes(longMsg);

  for algorithm in TSignerUtilities.Algorithms do
  begin

    signer := TSignerUtilities.GetSigner(algorithm);

    upper := UpperCase(algorithm);
    withPos := System.Pos('WITH', upper);

    if withPos = 0 then

    begin
      cipherName := upper;
    end
    else
    begin
      cipherName := System.Copy(upper, withPos + System.length('WITH'),
        System.length(upper) - withPos + System.length('WITH'));
    end;

    if (cipherName = 'ECDSA') then
    begin
      signParams := FecPriv;
      verifyParams := FecPub;
    end
    else
    begin
      Fail('Unknown algorithm encountered: ' + cipherName);
    end;

    signer.Init(true, signParams);
    for b in shortMsg do
    begin
      signer.Update(b);
    end;
    signer.BlockUpdate(longMsg, 0, System.length(longMsg));
    sig := signer.GenerateSignature();

    signer.Init(false, verifyParams);
    for b in shortMsg do
    begin
      signer.Update(b);
    end;
    signer.BlockUpdate(longMsg, 0, System.length(longMsg));

    CheckTrue(signer.VerifySignature(sig), cipherName + ' signer ' + algorithm +
      ' failed.');
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSignerUtilities);
{$ELSE}
  RegisterTest(TTestSignerUtilities.Suite);
{$ENDIF FPC}

end.
