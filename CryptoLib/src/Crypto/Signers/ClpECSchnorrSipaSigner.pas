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

unit ClpECSchnorrSipaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpISchnorrExt,
  ClpIECC,
  ClpIECSchnorrSipaSigner,
  ClpBigInteger,
  ClpBigIntegers,
  ClpISecureRandom,
  ClpIECKeyParameters,
  ClpICipherParameters,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpSecureRandom,
  ClpECAlgorithms,
  ClpDigestUtilities,
  ClpParameterUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SECPublicKeyNotFound = 'EC Public Key Required for Verification';
  SECPrivateKeyNotFound = 'EC Private Key Required for Signing';
  SNotInitializedForSigning = 'Not Initialised For Signing';
  SNotInitializedForVerifying = 'Not Initialised For Verifying';
  SSignatureGenerationError = 'An Error Occurred During Signature Generation';
  SOnlyFPCurvesAllowed =
    'Only FP (Prime Field) Curves are Allowed for This Schnorr Implementation';

type

  /// <summary>
  /// <para>
  /// Schnorr Signature as described in <see href="https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki">
  /// bip-schnorr</see>
  /// </para>
  /// <para>
  /// This <c>Schnorr</c> implementation only allows <c>FP(Prime Field)</c>
  /// Curves.
  /// </para>
  /// </summary>
  TECSchnorrSipaSigner = class sealed(TInterfacedObject, ISchnorrExt,
    IECSchnorrSipaSigner)

  strict private
  var
    FForSigning: Boolean;
    FKey: IECKeyParameters;
    FRandom: ISecureRandom;
    FDigest: IDigest;

    function GetAlgorithmName: String; virtual;
    function GetOrder: TBigInteger; virtual;

    function GetPP: TBigInteger; inline;
    function GetG: IECPoint; inline;
    function GetCurve: IECCurve; inline;

    property PP: TBigInteger read GetPP;
    property G: IECPoint read GetG;
    property Curve: IECCurve read GetCurve;

    class procedure ValidateAllowedCurves(const ACurve: IECCurve);
      static; inline;

    procedure Reset();

  public

    property Order: TBigInteger read GetOrder;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters;
      const ADigest: IDigest); virtual;

    function GenerateSignature(const AMessage: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    function VerifySignature(const AMessage: TCryptoLibByteArray;
      const ARSig, ASSig: TBigInteger): Boolean; virtual;

  end;

implementation

{ TECSchnorrSipaSigner }

function TECSchnorrSipaSigner.GenerateSignature(const AMessage
  : TCryptoLibByteArray): TCryptoLibGenericArray<TBigInteger>;
var
  LN, LK, LS, LXr, LYr, LE, LPrivateKey: TBigInteger;
  LInput, LKeyPrefixedM: TCryptoLibByteArray;
  LP, LR: IECPoint;
  LNumBytes: Int32;
begin
  if (not FForSigning) then
  begin
    // not properly initialized... deal with it
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  end;

  LN := Order;
  LNumBytes := TBigIntegers.GetUnsignedByteLength(LN);

  LPrivateKey := (FKey as IECPrivateKeyParameters).D;

  LInput := TArrayUtilities.Concatenate<Byte>(TBigIntegers.BigIntegerToBytes(LPrivateKey,
    LNumBytes), AMessage);

  LK := TBigInteger.Create(1, TDigestUtilities.DoFinal(FDigest, LInput)).&Mod(LN);

  if LK.CompareTo(TBigInteger.Zero) = 0 then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SSignatureGenerationError);
  end;

  LR := G.Multiply(LK).Normalize();
  LXr := LR.XCoord.ToBigInteger();
  LYr := LR.YCoord.ToBigInteger();
  if (TBigInteger.Jacobi(LYr, PP) <> 1) then
  begin
    LK := LN.Subtract(LK);
  end;

  LP := G.Multiply(LPrivateKey);

  LKeyPrefixedM := TArrayUtilities.Concatenate<Byte>
  ([
    TBigIntegers.BigIntegerToBytes(LXr, LNumBytes),
    LP.GetEncoded(true),
    AMessage
  ]);

  LE := TBigInteger.Create(1, TDigestUtilities.DoFinal(FDigest,
    LKeyPrefixedM)).&Mod(LN);

  LS := LK.Add(LE.Multiply(LPrivateKey)).&Mod(LN);

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LXr, LS);
end;

function TECSchnorrSipaSigner.GetAlgorithmName: String;
begin
  Result := 'ECSCHNORRSIPA';
end;

function TECSchnorrSipaSigner.GetCurve: IECCurve;
begin
  Result := FKey.Parameters.Curve;
end;

function TECSchnorrSipaSigner.GetG: IECPoint;
begin
  Result := FKey.Parameters.G;
end;

function TECSchnorrSipaSigner.GetOrder: TBigInteger;
begin
  Result := FKey.Parameters.N;
end;

function TECSchnorrSipaSigner.GetPP: TBigInteger;
begin
  Result := Curve.Field.Characteristic;
end;

class procedure TECSchnorrSipaSigner.ValidateAllowedCurves
  (const ACurve: IECCurve);
begin
  if (not(TECAlgorithms.IsFpCurve(ACurve))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOnlyFPCurvesAllowed);
  end;
end;

procedure TECSchnorrSipaSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters; const ADigest: IDigest);
var
  LParameters: ICipherParameters;
  LProvidedRandom: ISecureRandom;
begin
  FForSigning := AForSigning;
  FDigest := ADigest;

  if (AForSigning) then
  begin
    LParameters := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

    if LProvidedRandom <> nil then
      FRandom := LProvidedRandom
    else
      FRandom := TSecureRandom.Create();

    if (not(Supports(LParameters, IECPrivateKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPrivateKeyNotFound);
    end;

    FKey := LParameters as IECPrivateKeyParameters;
  end
  else
  begin
    LParameters := TParameterUtilities.IgnoreRandom(AParameters);

    if (not(Supports(LParameters, IECPublicKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPublicKeyNotFound);
    end;

    FKey := LParameters as IECPublicKeyParameters;
  end;

  ValidateAllowedCurves(Curve);
  Reset();
end;

procedure TECSchnorrSipaSigner.Reset;
begin
  FDigest.Reset;
end;

function TECSchnorrSipaSigner.VerifySignature(const AMessage
  : TCryptoLibByteArray; const ARSig, ASSig: TBigInteger): Boolean;
var
  LN, LE: TBigInteger;
  LPublicKeyBytes, LInput: TCryptoLibByteArray;
  LPublicKey: IECPublicKeyParameters;
  LP, LQ, LR: IECPoint;
  LNumBytes: Int32;
begin
  if (FForSigning) then
  begin
    // not properly initialized... deal with it
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifying);
  end;

  LN := Order;
  LNumBytes := TBigIntegers.GetUnsignedByteLength(LN);

  if ((ARSig.CompareTo(PP) >= 0) or (ASSig.CompareTo(LN) >= 0)) then
  begin
    Result := false;
    Exit;
  end;

  LPublicKey := (FKey as IECPublicKeyParameters);
  LPublicKeyBytes := LPublicKey.Q.GetEncoded(true);

  LInput := TArrayUtilities.Concatenate<Byte>
  ([
    TBigIntegers.BigIntegerToBytes(ARSig, LNumBytes),
    LPublicKeyBytes,
    AMessage
  ]);

  LE := TBigInteger.Create(1, TDigestUtilities.DoFinal(FDigest, LInput)).&Mod(LN);
  LQ := LPublicKey.Q.Normalize();
  LP := Curve.CreatePoint(LQ.XCoord.ToBigInteger(), LQ.YCoord.ToBigInteger());

  LR := G.Multiply(ASSig).Add(LP.Multiply(LN.Subtract(LE))).Normalize();

  if ((LR.IsInfinity) or (LR.XCoord.ToBigInteger().CompareTo(ARSig) <> 0) or
    (TBigInteger.Jacobi(LR.YCoord.ToBigInteger(), PP) <> 1)) then
  begin
    Result := false;
    Exit;
  end;

  Result := true;
end;

end.
