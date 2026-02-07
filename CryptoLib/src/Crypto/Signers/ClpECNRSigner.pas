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

unit ClpECNRSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDsa,
  ClpIECCore,
  ClpIECNRSigner,
  ClpBigInteger,
  ClpBigIntegers,
  ClpISecureRandom,
  ClpIECParameters,
  ClpICipherParameters,
  ClpIECGenerators,
  ClpECGenerators,
  ClpECParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpSecureRandom,
  ClpECAlgorithms,
  ClpParameterUtilities,
  ClpCryptoLibTypes;

resourcestring
  SECPublicKeyNotFound = 'EC Public Key Required for Verification';
  SECPrivateKeyNotFound = 'EC Private Key Required for Signing';
  SNotInitializedForSigning = 'Not Initialised For Signing';
  SNotInitializedForVerifying = 'Not Initialised For Verifying';
  SNotInitializedForVerifyingRecovery =
    'Not Initialised For Verifying/Recovery';
  SInputTooLargeForECNRKey = 'Input Too Large For ECNR Key.';

type

  /// <summary>
  /// EC-NR as described in IEEE 1363-2000 - a signature algorithm for Elliptic Curve which
  /// also offers message recovery.
  /// </summary>
  TECNRSigner = class sealed(TInterfacedObject, IDsa, IECNRSigner)

  strict private
  var
    FForSigning: Boolean;
    FKey: IECKeyParameters;
    FRandom: ISecureRandom;

    function GetAlgorithmName: String;
    function GetOrder: TBigInteger;

    function ExtractT(const APubKey: IECPublicKeyParameters;
      const AR, &AS: TBigInteger): TBigInteger;

  public

    property Order: TBigInteger read GetOrder;
    property AlgorithmName: String read GetAlgorithmName;

    /// <summary>
    /// Initialise the signer.
    /// </summary>
    /// <param name="forSigning">
    /// forSigning true if we are generating a signature, false for
    /// verification or if we want to use the signer for message recovery.
    /// </param>
    /// <param name="parameters">
    /// key parameters for signature generation.
    /// </param>
    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;

    /// <summary>
    /// <para>
    /// Section 7.2.5 ECSP-NR, pg 34
    /// </para>
    /// <para>
    /// generate a signature for the given message using the key we were <br />
    /// initialised with. Generally, the order of the curve should be at <br />
    /// least as long as the hash of the message of interest, and with <br />
    /// ECNR it *must* be at least as long.
    /// </para>
    /// </summary>
    /// <param name="&amp;message">
    /// the digest to be signed.
    /// </param>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if the digest is longer than the key allows
    /// </exception>
    function GenerateSignature(const AMessage: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    /// <summary>
    /// <para>
    /// Section 7.2.6 ECVP-NR, pg 35
    /// </para>
    /// <para>
    /// return true if the value r and s represent a signature for the <br />
    /// message passed in. Generally, the order of the curve should be at
    /// <br />least as long as the hash of the message of interest, and
    /// with <br />ECNR, it *must* be at least as long. But just in case
    /// the signer <br />applied mod(n) to the longer digest, this
    /// implementation will <br />apply mod(n) during verification.
    /// </para>
    /// </summary>
    /// <param name="&amp;message">
    /// the digest to be verified.
    /// </param>
    /// <param name="r">
    /// the r value of the signature.
    /// </param>
    /// <param name="s">
    /// the s value of the signature.
    /// </param>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if the digest is longer than the key allows
    /// </exception>
    function VerifySignature(const AMessage: TCryptoLibByteArray;
      const AR, &AS: TBigInteger): Boolean;

    /// <summary>
    /// Returns the data used for the signature generation, assuming the
    /// public key passed to Init() is correct.
    /// </summary>
    /// <returns>
    /// null if r and s are not valid.
    /// </returns>
    function GetRecoveredMessage(const AR, &AS: TBigInteger): TCryptoLibByteArray;

  end;

implementation

{ TECNRSigner }

function TECNRSigner.ExtractT(const APubKey: IECPublicKeyParameters;
  const AR, &AS: TBigInteger): TBigInteger;
var
  LN, LX: TBigInteger;
  LG, LW, LP: IECPoint;
begin
  LN := APubKey.Parameters.N;

  // r in the range [1,n-1]
  if ((AR.CompareTo(TBigInteger.One) < 0) or (AR.CompareTo(LN) >= 0)) then
  begin
    Result := TBigInteger.GetDefault;
    Exit;
  end;

  // s in the range [0,n-1]           NB: ECNR spec says 0
  if ((&AS.CompareTo(TBigInteger.Zero) < 0) or (&AS.CompareTo(LN) >= 0)) then
  begin
    Result := TBigInteger.GetDefault;
    Exit;
  end;

  // compute P = sG + rW

  LG := APubKey.Parameters.G;
  LW := APubKey.Q;
  // calculate P using Bouncy math
  LP := TECAlgorithms.SumOfTwoMultiplies(LG, &AS, LW, AR).Normalize();

  // components must be bogus.
  if (LP.IsInfinity) then
  begin
    Result := TBigInteger.GetDefault;
    Exit;
  end;

  LX := LP.AffineXCoord.ToBigInteger();

  Result := AR.Subtract(LX).&Mod(LN);
end;

function TECNRSigner.GenerateSignature(const AMessage: TCryptoLibByteArray)
  : TCryptoLibGenericArray<TBigInteger>;
var
  LN, LE, LR, LS, LVx, LX, LU: TBigInteger;
  LPrivKey: IECPrivateKeyParameters;
  LTempPair: IAsymmetricCipherKeyPair;
  LKeyGen: IECKeyPairGenerator;
  LV: IECPublicKeyParameters;
begin
  if (not FForSigning) then
  begin
    // not properly initialized... deal with it
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  end;

  LN := Order;

  LE := TBigInteger.Create(1, AMessage);

  LPrivKey := FKey as IECPrivateKeyParameters;

  if (LE.CompareTo(LN) >= 0) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooLargeForECNRKey);
  end;

  repeat // generate r
    // generate another, but very temporary, key pair using
    // the same EC parameters
    LKeyGen := TECKeyPairGenerator.Create();

    LKeyGen.Init(TECKeyGenerationParameters.Create(LPrivKey.Parameters, FRandom)
      as IECKeyGenerationParameters);

    LTempPair := LKeyGen.GenerateKeyPair();

    LV := LTempPair.Public as IECPublicKeyParameters; // get temp's public key
    LVx := LV.Q.AffineXCoord.ToBigInteger(); // get the point's x coordinate

    LR := LVx.Add(LE).&Mod(LN);
  until (not(LR.SignValue = 0));

  // generate s
  LX := LPrivKey.D; // private key value
  LU := (LTempPair.Private as IECPrivateKeyParameters).D;
  // temp's private key value
  LS := LU.Subtract(LR.Multiply(LX)).&Mod(LN);

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LR, LS);
end;

function TECNRSigner.GetAlgorithmName: String;
begin
  Result := 'ECNR';
end;

function TECNRSigner.GetOrder: TBigInteger;
begin
  Result := FKey.Parameters.N;
end;

procedure TECNRSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LProvidedRandom: ISecureRandom;
  LParameters: ICipherParameters;
begin
  FForSigning := AForSigning;

  if (AForSigning) then
  begin
    LParameters := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

    if (not(Supports(LParameters, IECPrivateKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPrivateKeyNotFound);
    end;

    FKey := LParameters as IECPrivateKeyParameters;
    if (LProvidedRandom <> nil) then
    begin
      FRandom := LProvidedRandom;
    end
    else
    begin
      FRandom := TSecureRandom.Create();
    end;
  end
  else
  begin
    if (not(Supports(AParameters, IECPublicKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPublicKeyNotFound);
    end;

    FKey := AParameters as IECPublicKeyParameters;
    FRandom := nil;
  end;
end;

function TECNRSigner.VerifySignature(const AMessage: TCryptoLibByteArray;
  const AR, &AS: TBigInteger): Boolean;
var
  LPubKey: IECPublicKeyParameters;
  LN, LE, LT: TBigInteger;
  LNBitLength, LEBitLength: Int32;
begin
  if (FForSigning) then
  begin
    // not properly initialized... deal with it
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifying);
  end;

  LPubKey := FKey as IECPublicKeyParameters;
  LN := LPubKey.Parameters.N;
  LNBitLength := LN.BitLength;

  LE := TBigInteger.Create(1, AMessage);
  LEBitLength := LE.BitLength;

  if (LEBitLength > LNBitLength) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooLargeForECNRKey);
  end;

  LT := ExtractT(LPubKey, AR, &AS);

  Result := (LT.IsInitialized) and (LT.Equals(LE.&Mod(LN)));
end;

function TECNRSigner.GetRecoveredMessage(const AR, &AS: TBigInteger)
  : TCryptoLibByteArray;
var
  LT: TBigInteger;
begin
  if (FForSigning) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifyingRecovery);
  end;

  LT := ExtractT(FKey as IECPublicKeyParameters, AR, &AS);

  if (LT.IsInitialized) then
  begin
    Result := TBigIntegers.AsUnsignedByteArray(LT);
    Exit;
  end;

  Result := nil;
end;

end.
