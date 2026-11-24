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

unit ClpDsaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpIDsa,
  ClpIDsaSigner,
  ClpISecureRandom,
  ClpIDsaParameters,
  ClpIDsaKCalculator,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpRandomDsaKCalculator,
  ClpBitOperations,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SDSAPrivateKeyNotFound = 'DSA private key required for signing';
  SDSAPublicKeyNotFound = 'DSA public key required for verification';

type
  /// <summary>
  /// The Digital Signature Algorithm - as described in "Handbook of Applied <br />
  /// Cryptography", pages 452 - 453.
  /// </summary>
  TDsaSigner = class(TInterfacedObject, IDsa, IDsaSigner)

  strict private
    function GetOrder: TBigInteger; virtual;
    function GetAlgorithmName: String; virtual;
  strict protected
  var
    FKCalculator: IDsaKCalculator;
    FKey: IDsaKeyParameters;
    FRandom: ISecureRandom;

    function CalculateE(const AN: TBigInteger;
      const AMessage: TCryptoLibByteArray): TBigInteger; virtual;

    function InitSecureRandom(ANeeded: Boolean; const AProvided: ISecureRandom)
      : ISecureRandom; virtual;

  public

    /// <summary>
    /// Default configuration, random K values.
    /// </summary>
    constructor Create(); overload;

    /// <summary>
    /// Configuration with an alternate, possibly deterministic calculator of
    /// K.
    /// </summary>
    /// <param name="AKCalculator">
    /// a K value calculator.
    /// </param>
    constructor Create(const AKCalculator: IDsaKCalculator); overload;

    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);

    /// <summary>
    /// Generate a signature for the given message using the key we were <br />
    /// initialised with. For conventional DSA the message should be a SHA-1 <br />
    /// hash of the message of interest.
    /// </summary>
    /// <param name="AMessage">
    /// the message that will be verified later.
    /// </param>
    function GenerateSignature(const AMessage: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    /// <summary>
    /// return true if the value r and s represent a DSA signature for <br />
    /// the passed in message for standard DSA the message should be a <br />
    /// SHA-1 hash of the real message to be verified.
    /// </summary>
    function VerifySignature(const AMessage: TCryptoLibByteArray;
      const AR, &AS: TBigInteger): Boolean; virtual;

    property Order: TBigInteger read GetOrder;
    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TDsaSigner }

constructor TDsaSigner.Create;
begin
  Inherited Create();
  FKCalculator := TRandomDsaKCalculator.Create();
end;

function TDsaSigner.CalculateE(const AN: TBigInteger;
  const AMessage: TCryptoLibByteArray): TBigInteger;
var
  LLength: Int32;
begin
  LLength := Math.Min(System.length(AMessage), TBitOperations.Asr32(AN.BitLength, 3));
  Result := TBigInteger.Create(1, AMessage, 0, LLength);
end;

constructor TDsaSigner.Create(const AKCalculator: IDsaKCalculator);
begin
  Inherited Create();
  FKCalculator := AKCalculator;
end;

function TDsaSigner.GenerateSignature(const AMessage: TCryptoLibByteArray)
  : TCryptoLibGenericArray<TBigInteger>;
var
  LParameters: IDsaParameters;
  LQ, LM, LX, LK, LBlindedK, LR, LS: TBigInteger;
begin
  LParameters := FKey.Parameters;
  LQ := LParameters.Q;
  // m is public, and CalculateE can leave it at or past q, which ModAdd below rejects rather than reduces
  LM := CalculateE(LQ, AMessage).&Mod(LQ);
  LX := (FKey as IDsaPrivateKeyParameters).X;

  if (FKCalculator.IsDeterministic) then
  begin
    FKCalculator.Init(LQ, LX, AMessage);
  end
  else
  begin
    FKCalculator.Init(LQ, FRandom);
  end;

  LK := FKCalculator.NextK();

  // k leaks x through s, so the exponent is blinded with a random multiple of q before the
  // variable-time ModPow; g has order q, so r is unchanged
  LBlindedK := TBigIntegerUtilities.CreateBlindedExponent(LK, LQ, FRandom);
  LR := LParameters.G.ModPow(LBlindedK, LParameters.P).&Mod(LQ);

  // s = k^-1 * (m + x * r) mod q, keeping secret x and k^-1 off BigInteger.Mod, whose cost follows the quotient
  LS := TBigIntegerUtilities.ModMult(LQ, TBigIntegerUtilities.ModOddInverse(LQ, LK),
    TBigIntegerUtilities.ModAdd(LQ, LM, TBigIntegerUtilities.ModMult(LQ, LX, LR)));

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LR, LS);
end;

function TDsaSigner.GetOrder: TBigInteger;
begin
  Result := FKey.Parameters.Q;
end;

function TDsaSigner.GetAlgorithmName: String;
begin
  Result := 'DSA';
end;

procedure TDsaSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LProvidedRandom: ISecureRandom;
  LParameters: ICipherParameters;
begin
  if (AForSigning) then
  begin
    LParameters := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

    if (not Supports(LParameters, IDsaPrivateKeyParameters)) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SDSAPrivateKeyNotFound);
    end;

    FKey := LParameters as IDsaPrivateKeyParameters;
    // needed even for a deterministic k: signing blinds the exponent
    FRandom := InitSecureRandom(True, LProvidedRandom);
  end
  else
  begin
    if (not Supports(AParameters, IDsaPublicKeyParameters)) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SDSAPublicKeyNotFound);
    end;

    FKey := AParameters as IDsaPublicKeyParameters;
    FRandom := nil;
  end;
end;

function TDsaSigner.InitSecureRandom(ANeeded: Boolean;
  const AProvided: ISecureRandom): ISecureRandom;
begin
  if (not ANeeded) then
    Result := nil
  else
    Result := TCryptoServicesRegistrar.GetSecureRandom(AProvided);
end;

function TDsaSigner.VerifySignature(const AMessage: TCryptoLibByteArray;
  const AR, &AS: TBigInteger): Boolean;
var
  LParameters: IDsaParameters;
  LQ, LM, LW, LU1, LU2, LP, LV: TBigInteger;
begin
  LParameters := FKey.Parameters;
  LQ := LParameters.Q;
  LM := CalculateE(LQ, AMessage);

  if ((AR.SignValue <= 0) or (LQ.CompareTo(AR) <= 0)) then
  begin
    Result := False;
    Exit;
  end;

  if ((&AS.SignValue <= 0) or (LQ.CompareTo(&AS) <= 0)) then
  begin
    Result := False;
    Exit;
  end;

  LW := TBigIntegerUtilities.ModOddInverseVar(LQ, &AS);

  LU1 := LM.Multiply(LW).&Mod(LQ);
  LU2 := AR.Multiply(LW).&Mod(LQ);

  LP := LParameters.P;
  LU1 := LParameters.G.ModPow(LU1, LP);
  LU2 := (FKey as IDsaPublicKeyParameters).Y.ModPow(LU2, LP);

  LV := LU1.Multiply(LU2).&Mod(LP).&Mod(LQ);

  Result := LV.Equals(AR);
end;

end.
