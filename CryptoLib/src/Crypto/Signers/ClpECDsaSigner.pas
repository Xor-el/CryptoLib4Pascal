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

unit ClpECDsaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpSecureRandom,
  ClpECAlgorithms,
  ClpIECC,
  ClpIECParameters,
  ClpMultipliers,
  ClpCryptoLibTypes,
  ClpICipherParameters,
  ClpISecureRandom,
  ClpParameterUtilities,
  ClpRandomDsaKCalculator,
  ClpIDsaKCalculator,
  ClpECCurveConstants,
  ClpIDsa,
  ClpIECDsaSigner;

resourcestring
  SECPublicKeyNotFound = 'EC Public Key Required for Verification';
  SECPrivateKeyNotFound = 'EC Private Key Required for Signing';

type

  /// <summary>
  /// EC-DSA as described in X9.62
  /// </summary>
  TECDsaSigner = class(TInterfacedObject, IDsa, IECDsaSigner)

  strict private

    class var

      FEight: TBigInteger;

    class procedure Boot(); static;
    class constructor ECDsaSigner();

    class function GetEight: TBigInteger; static; inline;

    class property Eight: TBigInteger read GetEight;

    function GetOrder: TBigInteger; virtual;
    function GetAlgorithmName: String; virtual;

  strict protected
  var
    FKCalculator: IDsaKCalculator;
    FKey: IECKeyParameters;
    FRandom: ISecureRandom;

    function CalculateE(const AN: TBigInteger;
      const AMessage: TCryptoLibByteArray): TBigInteger; virtual;

    function CreateBasePointMultiplier(): IECMultiplier; virtual;

    function GetDenominator(ACoordinateSystem: Int32; const AP: IECPoint)
      : IECFieldElement; virtual;

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
    /// <param name="kCalculator">
    /// kCalculator a K value calculator.
    /// </param>
    constructor Create(const AKCalculator: IDsaKCalculator); overload;

    property Order: TBigInteger read GetOrder;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;

    // // 5.3 pg 28
    // /**
    // * Generate a signature for the given message using the key we were
    // * initialised with. For conventional DSA the message should be a SHA-1
    // * hash of the message of interest.
    // *
    // * @param message the message that will be verified later.
    function GenerateSignature(const AMessage: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    // // 5.4 pg 29
    // /**
    // * return true if the value r and s represent a DSA signature for
    // * the passed in message (for standard DSA the message should be
    // * a SHA-1 hash of the real message to be verified).
    // */
    function VerifySignature(const AMessage: TCryptoLibByteArray;
      const AR, &AS: TBigInteger): Boolean;

  end;

implementation

{ TECDsaSigner }

constructor TECDsaSigner.Create;
begin
  inherited Create();
  FKCalculator := TRandomDsaKCalculator.Create();
end;

class procedure TECDsaSigner.Boot;
begin
  FEight := TBigInteger.ValueOf(8);
end;

function TECDsaSigner.CalculateE(const AN: TBigInteger;
  const AMessage: TCryptoLibByteArray): TBigInteger;
var
  LMessageBitLength: Int32;
  LTrunc: TBigInteger;
begin
  LMessageBitLength := System.Length(AMessage) * 8;
  LTrunc := TBigInteger.Create(1, AMessage);

  if (AN.BitLength < LMessageBitLength) then
  begin
    LTrunc := LTrunc.ShiftRight(LMessageBitLength - AN.BitLength);
  end;

  Result := LTrunc;
end;

constructor TECDsaSigner.Create(const AKCalculator: IDsaKCalculator);
begin
  inherited Create();
  FKCalculator := AKCalculator;
end;

function TECDsaSigner.CreateBasePointMultiplier: IECMultiplier;
begin
  Result := TFixedPointCombMultiplier.Create();
end;

class constructor TECDsaSigner.ECDsaSigner;
begin
  TECDsaSigner.Boot;
end;

function TECDsaSigner.GenerateSignature(const AMessage: TCryptoLibByteArray)
  : TCryptoLibGenericArray<TBigInteger>;
var
  LEC: IECDomainParameters;
  LBasePointMultiplier: IECMultiplier;
  LN, LE, LD, LR, LS, LK: TBigInteger;
  LP: IECPoint;
begin
  LEC := FKey.Parameters;
  LN := LEC.N;
  LE := CalculateE(LN, AMessage);
  LD := (FKey as IECPrivateKeyParameters).D;

  if (FKCalculator.IsDeterministic) then
  begin
    FKCalculator.Init(LN, LD, AMessage);
  end
  else
  begin
    FKCalculator.Init(LN, FRandom);
  end;

  LBasePointMultiplier := CreateBasePointMultiplier();

  // 5.3.2
  repeat // Generate s

    repeat // Generate r
      LK := FKCalculator.NextK();

      LP := LBasePointMultiplier.Multiply(LEC.G, LK).Normalize();

      // 5.3.3
      LR := LP.AffineXCoord.ToBigInteger().&Mod(LN);
    until (not(LR.SignValue = 0));

    LS := LK.ModInverse(LN).Multiply(LE.Add(LD.Multiply(LR))).&Mod(LN);

  until (not(LS.SignValue = 0));

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LR, LS);
end;

function TECDsaSigner.GetAlgorithmName: String;
begin
  Result := 'ECDSA';
end;

function TECDsaSigner.GetDenominator(ACoordinateSystem: Int32; const AP: IECPoint)
  : IECFieldElement;
begin
  case (ACoordinateSystem) of
    TECCurveConstants.COORD_HOMOGENEOUS,
      TECCurveConstants.COORD_LAMBDA_PROJECTIVE, TECCurveConstants.COORD_SKEWED:
      begin
        Result := AP.GetZCoord(0);
      end;

    TECCurveConstants.COORD_JACOBIAN,
      TECCurveConstants.COORD_JACOBIAN_CHUDNOVSKY,
      TECCurveConstants.COORD_JACOBIAN_MODIFIED:
      begin
        Result := AP.GetZCoord(0).Square();
      end
  else
    begin
      Result := nil;
    end;
  end;
end;

class function TECDsaSigner.GetEight: TBigInteger;
begin
  Result := FEight;
end;

function TECDsaSigner.GetOrder: TBigInteger;
begin
  Result := FKey.Parameters.N;
end;

procedure TECDsaSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LProvidedRandom: ISecureRandom;
  LParameters: ICipherParameters;
begin
  if (AForSigning) then
  begin
    LParameters := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

    if (not(Supports(LParameters, IECPrivateKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPrivateKeyNotFound);
    end;

    FKey := LParameters as IECPrivateKeyParameters;
    FRandom := InitSecureRandom(not FKCalculator.IsDeterministic, LProvidedRandom);
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

function TECDsaSigner.InitSecureRandom(ANeeded: Boolean;
  const AProvided: ISecureRandom): ISecureRandom;
begin
  if (not ANeeded) then
  begin
    Result := nil;
  end
  else
  begin
    if (AProvided <> nil) then
    begin
      Result := AProvided;
    end
    else
    begin
      Result := TSecureRandom.Create();
    end;
  end;
end;

function TECDsaSigner.VerifySignature(const AMessage: TCryptoLibByteArray;
  const AR, &AS: TBigInteger): Boolean;
var
  LN, LE, LC, LU1, LU2, LCofactor, LV, LSmallR: TBigInteger;
  LG, LQ, LPoint: IECPoint;
  LCurve: IECCurve;
  LD, LX, LRLocal: IECFieldElement;
begin
  LN := FKey.Parameters.N;
  LSmallR := AR;

  // r and s should both in the range [1,n-1]
  if ((LSmallR.SignValue < 1) or (&AS.SignValue < 1) or (LSmallR.CompareTo(LN) >= 0)
    or (&AS.CompareTo(LN) >= 0)) then
  begin
    Result := false;
    Exit;
  end;

  LE := CalculateE(LN, AMessage);
  LC := &AS.ModInverse(LN);

  LU1 := LE.Multiply(LC).&Mod(LN);
  LU2 := LSmallR.Multiply(LC).&Mod(LN);

  LG := FKey.Parameters.G;

  LQ := (FKey as IECPublicKeyParameters).Q;

  LPoint := TECAlgorithms.SumOfTwoMultiplies(LG, LU1, LQ, LU2);

  if (LPoint.IsInfinity) then
  begin
    Result := false;
    Exit;
  end;

  // /*
  // * If possible, avoid normalizing the point (to save a modular inversion in the curve field).
  // *
  // * There are ~cofactor elements of the curve field that reduce (modulo the group order) to 'r'.
  // * If the cofactor is known and small, we generate those possible field values and project each
  // * of them to the same "denominator" (depending on the particular projective coordinates in use)
  // * as the calculated point.X. If any of the projected values matches point.X, then we have:
  // *     (point.X / Denominator mod p) mod n == r
  // * as required, and verification succeeds.
  // *
  // * Based on an original idea by Gregory Maxwell (https://github.com/gmaxwell), as implemented in
  // * the libsecp256k1 project (https://github.com/bitcoin/secp256k1).
  // */
  LCurve := LPoint.Curve;
  if (LCurve <> nil) then
  begin
    LCofactor := LCurve.Cofactor;
    if ((LCofactor.IsInitialized) and (LCofactor.CompareTo(Eight) <= 0)) then
    begin
      LD := GetDenominator(LCurve.CoordinateSystem, LPoint);
      if ((LD <> nil) and (not LD.IsZero)) then
      begin
        LX := LPoint.XCoord;
        while (LCurve.IsValidFieldElement(LSmallR)) do
        begin
          LRLocal := LCurve.FromBigInteger(LSmallR).Multiply(LD);
          if (LRLocal.Equals(LX)) then
          begin
            Result := True;
            Exit;
          end;
          LSmallR := LSmallR.Add(LN);
        end;
        Result := false;
        Exit;
      end;
    end;
  end;

  LV := LPoint.Normalize().AffineXCoord.ToBigInteger().&Mod(LN);
  Result := LV.Equals(LSmallR);
end;

end.
