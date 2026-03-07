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

unit ClpBip340SchnorrSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  SyncObjs,
  ClpICipherParameters,
  ClpISigner,
  ClpISecureRandom,
  ClpIECCommon,
  ClpIECParameters,
  ClpIBip340SchnorrSigner,
  ClpIBip340SchnorrParameters,
  ClpBip340SchnorrParameters,
  ClpBip340SchnorrUtilities,
  ClpIParametersWithRandom,
  ClpBigInteger,
  ClpParameterUtilities,
  ClpECUtilities,
  ClpECParameters,
  ClpECAlgorithms,
  ClpIX9ECAsn1Objects,
  ClpBigIntegerUtilities,
  ClpArrayUtilities,
  ClpConverters,
  ClpCryptoLibTypes;

resourcestring
  SNotInitializedForSigning =
    'BIP340SchnorrSigner not Initialised for Signature Generation.';
  SNotInitializedForVerifying =
    'BIP340SchnorrSigner not Initialised for Verification';

type
  TBip340SchnorrSigner = class(TInterfacedObject, ISigner, IBip340SchnorrSigner)
  strict private
  const
    /// <summary>Tag for BIP-340 auxiliary randomness (encoded as UTF-8 bytes).</summary>
    BIP0340_AUX_TAG_STR = 'BIP0340/aux';
    /// <summary>Tag for BIP-340 nonce derivation (encoded as UTF-8 bytes).</summary>
    BIP0340_NONCE_TAG_STR = 'BIP0340/nonce';
    /// <summary>Tag for BIP-340 challenge hash (encoded as UTF-8 bytes).</summary>
    BIP0340_CHALLENGE_TAG_STR = 'BIP0340/challenge';
  type
    TBuffer = class
    strict private
      var
        FStream: TMemoryStream;
        FLock: TCriticalSection;
      function GetBufferContent: TCryptoLibByteArray;
      procedure ResetInternal;
    public
      constructor Create();
      destructor Destroy(); override;
      procedure WriteByte(AInput: Byte);
      procedure Write(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
      procedure Reset();
      function GenerateSignature(const APrivateKey: IBip340SchnorrPrivateKeyParameters;
        const AInitParams: ICipherParameters): TCryptoLibByteArray;
      function VerifySignature(const APublicKey: IBip340SchnorrPublicKeyParameters;
        const ASignature: TCryptoLibByteArray): Boolean;
    end;
  strict private
    var
      FBuffer: TBuffer;
      FForSigning: Boolean;
      FPrivateKey: IBip340SchnorrPrivateKeyParameters;
      FPublicKey: IBip340SchnorrPublicKeyParameters;
      FInitParams: ICipherParameters;
  strict protected
    function GetAlgorithmName: String; virtual;
  public
    constructor Create();
    destructor Destroy(); override;

    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;
    procedure Update(AInput: Byte); virtual;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32); virtual;
    function GetMaxSignatureSize: Int32; virtual;
    function GenerateSignature(): TCryptoLibByteArray; virtual;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
      virtual;
    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TBip340SchnorrSigner.TBuffer }

constructor TBip340SchnorrSigner.TBuffer.Create();
begin
  Inherited Create();
  FStream := TMemoryStream.Create();
  FLock := TCriticalSection.Create();
end;

destructor TBip340SchnorrSigner.TBuffer.Destroy;
begin
  FLock.Free;
  FStream.Free;
  inherited Destroy;
end;

function TBip340SchnorrSigner.TBuffer.GetBufferContent: TCryptoLibByteArray;
begin
  Result := nil;
  if FStream.Size > 0 then
  begin
    FStream.Position := 0;
    System.SetLength(Result, FStream.Size);
    FStream.Read(Result[0], FStream.Size);
  end;
end;

procedure TBip340SchnorrSigner.TBuffer.ResetInternal;
var
  LCount: Int64;
begin
  LCount := FStream.Size;
  if LCount > 0 then
  begin
    FillChar(PByte(FStream.Memory)^, LCount, 0);
  end;
  FStream.Clear;
  FStream.SetSize(Int64(0));
end;

procedure TBip340SchnorrSigner.TBuffer.Reset();
begin
  FLock.Enter;
  try
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

procedure TBip340SchnorrSigner.TBuffer.WriteByte(AInput: Byte);
var
  LB: TCryptoLibByteArray;
begin
  LB := TCryptoLibByteArray.Create(AInput);
  FStream.Write(LB[0], 1);
end;

procedure TBip340SchnorrSigner.TBuffer.Write(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32);
begin
  if (ABuf <> nil) and (ALen > 0) then
    FStream.Write(ABuf[AOff], ALen);
end;

function TBip340SchnorrSigner.TBuffer.GenerateSignature(const APrivateKey: IBip340SchnorrPrivateKeyParameters;
  const AInitParams: ICipherParameters): TCryptoLibByteArray;
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
  LMsg: TCryptoLibByteArray;
  LAuxTagBytes, LAuxHash, LKPrimeBytes: TCryptoLibByteArray;
  LNonceTagBytes: TCryptoLibByteArray;
  LDBytes, LT, LNonceMsg: TCryptoLibByteArray;
  LChallengeTagBytes: TCryptoLibByteArray;
  LD, LN, LK, LE, LS: TBigInteger;
  LP, LR: IECPoint;
  LRPubBytes, LPPubBytes: TCryptoLibByteArray;
  LChallenge: TCryptoLibByteArray;
  LChallengeLen: Int32;
  LProvidedRandom: ISecureRandom;
  LAuxRand: TCryptoLibByteArray;
begin
  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
    raise EInvalidOperationCryptoLibException.Create('secp256k1 curve not found');
  LDomain := TECDomainParameters.FromX9ECParameters(LX9);
  LN := LDomain.N;

  FLock.Enter;
  try
    LMsg := GetBufferContent();
    TParameterUtilities.GetRandom(AInitParams, LProvidedRandom);
    System.SetLength(LAuxRand, TBip340SchnorrUtilities.BIP340_SECKEY_SIZE);
    if (LProvidedRandom <> nil) then
      LProvidedRandom.NextBytes(LAuxRand)
    else
      TArrayUtilities.Fill<Byte>(LAuxRand, 0, System.Length(LAuxRand), Byte(0));

    LD := TBigInteger.Create(1, APrivateKey.GetEncoded()).&Mod(LN);
    if (LD.SignValue = 0) then
      raise EInvalidOperationCryptoLibException.Create('invalid private key');
    LP := TECAlgorithms.ReferenceMultiply(LDomain.G, LD).Normalize();
    if (not TBip340SchnorrUtilities.HasEvenY(LP)) then
      LD := LN.Subtract(LD);
    LPPubBytes := TBip340SchnorrUtilities.BytesFromPoint(LP);

    LAuxTagBytes := TConverters.ConvertStringToBytes(TBip340SchnorrSigner.BIP0340_AUX_TAG_STR, TEncoding.UTF8);
    LAuxHash := TBip340SchnorrUtilities.TaggedHash(LAuxTagBytes, LAuxRand);
    System.SetLength(LDBytes, TBip340SchnorrUtilities.BIP340_SECKEY_SIZE);
    TBigIntegerUtilities.AsUnsignedByteArray(LD, LDBytes, 0, TBip340SchnorrUtilities.BIP340_SECKEY_SIZE);
    System.SetLength(LT, TBip340SchnorrUtilities.BIP340_SECKEY_SIZE);
    TBip340SchnorrUtilities.XorBytes(LDBytes, 0, LAuxHash, 0, LT, 0, TBip340SchnorrUtilities.BIP340_SECKEY_SIZE);

    LNonceTagBytes := TConverters.ConvertStringToBytes(TBip340SchnorrSigner.BIP0340_NONCE_TAG_STR, TEncoding.UTF8);
    LChallengeLen := 32 + 32 + System.Length(LMsg);
    System.SetLength(LNonceMsg, LChallengeLen);
    System.Move(LT[0], LNonceMsg[0], 32);
    System.Move(LPPubBytes[0], LNonceMsg[32], 32);
    if System.Length(LMsg) > 0 then
      System.Move(LMsg[0], LNonceMsg[64], System.Length(LMsg));
    LKPrimeBytes := TBip340SchnorrUtilities.TaggedHash(LNonceTagBytes, LNonceMsg);
    LK := TBigInteger.Create(1, LKPrimeBytes).&Mod(LN);

    if (LK.SignValue = 0) then
      raise EInvalidOperationCryptoLibException.Create('k'' = 0 in BIP340 signing');

    LR := TECAlgorithms.ReferenceMultiply(LDomain.G, LK).Normalize();
    if (not TBip340SchnorrUtilities.HasEvenY(LR)) then
      LK := LN.Subtract(LK);
    LRPubBytes := TBip340SchnorrUtilities.BytesFromPoint(LR);

    LChallengeLen := 32 + 32 + System.Length(LMsg);
    System.SetLength(LChallenge, LChallengeLen);
    System.Move(LRPubBytes[0], LChallenge[0], 32);
    System.Move(LPPubBytes[0], LChallenge[32], 32);
    if System.Length(LMsg) > 0 then
      System.Move(LMsg[0], LChallenge[64], System.Length(LMsg));
    LChallengeTagBytes := TConverters.ConvertStringToBytes(TBip340SchnorrSigner.BIP0340_CHALLENGE_TAG_STR, TEncoding.UTF8);
    LE := TBigInteger.Create(1,
      TBip340SchnorrUtilities.TaggedHash(LChallengeTagBytes, LChallenge)).&Mod(LN);
    LS := LK.Add(LE.Multiply(LD)).&Mod(LN);

    System.SetLength(Result, TBip340SchnorrUtilities.BIP340_SIG_SIZE);
    System.Move(LRPubBytes[0], Result[0], 32);
    TBigIntegerUtilities.AsUnsignedByteArray(LS, Result, 32, 32);

    ResetInternal();
  finally
    FLock.Leave;
  end;
end;

function TBip340SchnorrSigner.TBuffer.VerifySignature(const APublicKey: IBip340SchnorrPublicKeyParameters;
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
  LMsg: TCryptoLibByteArray;
  LRBytes, LSBytes: TCryptoLibByteArray;
  LChallengeTagBytes: TCryptoLibByteArray;
  LR, LS: TBigInteger;
  LP: IECPoint;
  LChallenge: TCryptoLibByteArray;
  LChallengeLen: Int32;
  LE: TBigInteger;
  LRGen: IECPoint;
  LCurve: IECCurve;
begin
  if (ASignature = nil) or (System.Length(ASignature) <> TBip340SchnorrUtilities.BIP340_SIG_SIZE)
  then
  begin
    Reset();
    Result := False;
    Exit;
  end;

  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
  begin
    Reset();
    Result := False;
    Exit;
  end;
  LDomain := TECDomainParameters.FromX9ECParameters(LX9);
  LCurve := LDomain.Curve;

  try
    LP := TBip340SchnorrUtilities.LiftX(LDomain, APublicKey.GetEncoded());
  except
    Reset();
    Result := False;
    Exit;
  end;

  System.SetLength(LRBytes, 32);
  System.SetLength(LSBytes, 32);
  System.Move(ASignature[0], LRBytes[0], 32);
  System.Move(ASignature[32], LSBytes[0], 32);

  LR := TBigInteger.Create(1, LRBytes);
  LS := TBigInteger.Create(1, LSBytes);
  if (LR.CompareTo(LCurve.Field.Characteristic) >= 0) or
    (LS.CompareTo(LDomain.N) >= 0) then
  begin
    Reset();
    Result := False;
    Exit;
  end;

  FLock.Enter;
  try
    LMsg := GetBufferContent();
    LChallengeLen := 32 + 32 + System.Length(LMsg);
    System.SetLength(LChallenge, LChallengeLen);
    System.Move(LRBytes[0], LChallenge[0], 32);
    System.Move(APublicKey.GetEncoded()[0], LChallenge[32], 32);
    if System.Length(LMsg) > 0 then
      System.Move(LMsg[0], LChallenge[64], System.Length(LMsg));
    LChallengeTagBytes := TConverters.ConvertStringToBytes(TBip340SchnorrSigner.BIP0340_CHALLENGE_TAG_STR, TEncoding.UTF8);
    LE := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(LChallengeTagBytes, LChallenge)).&Mod(LDomain.N);

    LRGen := TECAlgorithms.SumOfTwoMultiplies(LDomain.G, LS, LP.Negate(), LE);
    if (LRGen.IsInfinity) or (not TBip340SchnorrUtilities.HasEvenY(LRGen)) then
    begin
      Reset();
      Result := False;
      Exit;
    end;
    Result := TArrayUtilities.FixedTimeEquals(
      TBigIntegerUtilities.AsUnsignedByteArray(32,
      LRGen.Normalize().AffineXCoord.ToBigInteger()), LRBytes);
    Reset();
  finally
    FLock.Leave;
  end;
end;

{ TBip340SchnorrSigner }

procedure TBip340SchnorrSigner.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32);
begin
  FBuffer.Write(AInput, AInOff, ALength);
end;

constructor TBip340SchnorrSigner.Create();
begin
  Inherited Create();
  FBuffer := TBuffer.Create();
end;

destructor TBip340SchnorrSigner.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TBip340SchnorrSigner.GetAlgorithmName: String;
begin
  Result := 'BIP340Schnorr';
end;

function TBip340SchnorrSigner.GenerateSignature: TCryptoLibByteArray;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  Result := FBuffer.GenerateSignature(FPrivateKey, FInitParams);
end;

procedure TBip340SchnorrSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LParams: ICipherParameters;
  LRandom: ISecureRandom;
begin
  FForSigning := AForSigning;
  FInitParams := AParameters;
  LParams := TParameterUtilities.GetRandom(AParameters, LRandom);

  if (AForSigning) then
  begin
    if (not Supports(LParams, IBip340SchnorrPrivateKeyParameters, FPrivateKey))
    then
      raise EInvalidKeyCryptoLibException.Create
        ('BIP340 Schnorr private key required for signing');
    FPublicKey := nil;
  end
  else
  begin
    if (not Supports(LParams, IBip340SchnorrPublicKeyParameters, FPublicKey))
    then
      raise EInvalidKeyCryptoLibException.Create
        ('BIP340 Schnorr public key required for verification');
    FPrivateKey := nil;
  end;

  Reset();
end;

procedure TBip340SchnorrSigner.Reset;
begin
  FBuffer.Reset();
end;

procedure TBip340SchnorrSigner.Update(AInput: Byte);
begin
  FBuffer.WriteByte(AInput);
end;

function TBip340SchnorrSigner.GetMaxSignatureSize: Int32;
begin
  Result := TBip340SchnorrUtilities.BIP340_SIG_SIZE;
end;

function TBip340SchnorrSigner.VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
begin
  if ((FForSigning) or (FPublicKey = nil)) then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifying);
  Result := FBuffer.VerifySignature(FPublicKey, ASignature);
end;

end.
