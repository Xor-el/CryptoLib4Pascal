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

unit ClpDHParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  ClpICipherParameters,
  ClpIDHParameters,
  ClpAsymmetricKeyParameter,
  ClpPkcsObjectIdentifiers,
  ClpIAsn1Objects,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpBigInteger,
  ClpNat,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SPUnInitialized = '"P" Cannot Be Uninitialized';
  SGUnInitialized = '"G" Cannot Be Uninitialized';
  SMustBeOddPrime = 'Field must be an Odd Prime, "P"';
  SInvalidGeneratorRange = 'Generator must in the Range [2, p - 2], "G"';
  SQTooBigToBeAFactor = 'Q too Big to be a Factor of (P - 1), "Q"';
  SMTooBig = 'M value must be < BitLength of P, "M"';
  SLErrorOne = 'when L value specified, it must be less than bitlength(P), "L"';
  SLErrorTwo = 'when L value specified, it may not be less than m value, "L"';
  SInvalidSubGroupFactor = 'Subgroup factor must be >= 2, "j"';
  SSeedNil = '"Seed" Cannot Be Nil';
  SYUnInitialized = '"Y" Cannot Be Uninitialized';
  SInvalidDHPublicKey = 'Invalid DH public key "Y"';
  SInvalidYInCorrectGroup = '"Y" Value Does Not Appear To Be In Correct Group';
  SXUnInitialized = '"X" Cannot Be Uninitialized';

type
  TDHValidationParameters = class(TInterfacedObject, IDHValidationParameters)
  strict private
  var
    FSeed: TCryptoLibByteArray;
    FCounter: Int32;

    function GetCounter: Int32; virtual;
    function GetSeed: TCryptoLibByteArray; virtual;

  public
    constructor Create(const ASeed: TCryptoLibByteArray; ACounter: Int32);

    function Equals(const AOther: IDHValidationParameters): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Counter: Int32 read GetCounter;
    property Seed: TCryptoLibByteArray read GetSeed;
  end;

  TDHParameters = class(TInterfacedObject, ICipherParameters, IDHParameters)

  strict private

  const
    DefaultMinimumLength = Int32(160);

  var
    FP, FQ, FG, FJ: TBigInteger;
    FM, FL: Int32;
    FValidation: IDHValidationParameters;

    function GetG: TBigInteger; inline;
    function GetP: TBigInteger; inline;
    function GetQ: TBigInteger; inline;
    function GetJ: TBigInteger; inline;
    function GetM: Int32; inline;
    function GetL: Int32; inline;
    function GetValidationParameters: IDHValidationParameters; inline;

    class function GetDefaultMParam(ALParam: Int32): Int32; static; inline;

  public

    constructor Create(const AP, AG: TBigInteger); overload;

    constructor Create(const AP, AG, AQ: TBigInteger); overload;

    constructor Create(const AP, AG, AQ: TBigInteger; AL: Int32); overload;

    constructor Create(const AP, AG, AQ: TBigInteger; AM, AL: Int32); overload;

    constructor Create(const AP, AG, AQ, AJ: TBigInteger;
      const AValidation: IDHValidationParameters); overload;

    constructor Create(const AP, AG, AQ: TBigInteger; AM, AL: Int32;
      const AJ: TBigInteger; const AValidation: IDHValidationParameters);
      overload;

    function Equals(const AOther: IDHParameters): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property P: TBigInteger read GetP;
    property Q: TBigInteger read GetQ;
    property G: TBigInteger read GetG;
    property J: TBigInteger read GetJ;
    property M: Int32 read GetM;
    property L: Int32 read GetL;
    property ValidationParameters: IDHValidationParameters
      read GetValidationParameters;

  end;

  TDHKeyParameters = class abstract(TAsymmetricKeyParameter, IDHKeyParameters)

  strict private
  var
    FParameters: IDHParameters;
    FAlgorithmOid: IDerObjectIdentifier;
  strict protected
    function GetParameters: IDHParameters;
    function GetAlgorithmOid: IDerObjectIdentifier;

    constructor Create(AIsPrivate: Boolean;
      const AParameters: IDHParameters); overload;

    constructor Create(AIsPrivate: Boolean; const AParameters: IDHParameters;
      const AAlgorithmOid: IDerObjectIdentifier); overload;

  public
    function Equals(const AOther: IDHKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Parameters: IDHParameters read GetParameters;
    property AlgorithmOid: IDerObjectIdentifier read GetAlgorithmOid;

  end;

  TDHPublicKeyParameters = class(TDHKeyParameters,
    IDHPublicKeyParameters)

  strict private
  var
    FY: TBigInteger;

    class function Legendre(const AA, AB: TBigInteger): Int32; static;

    class function Validate(const AY: TBigInteger; const ADHParams: IDHParameters)
      : TBigInteger; static;

  strict protected

    function GetY: TBigInteger; virtual;

  public
    constructor Create(const AY: TBigInteger;
      const AParameters: IDHParameters); overload;

    constructor Create(const AY: TBigInteger; const AParameters: IDHParameters;
      const AAlgorithmOid: IDerObjectIdentifier); overload;

    function Equals(const AOther: IDHPublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Y: TBigInteger read GetY;
  end;

  TDHPrivateKeyParameters = class(TDHKeyParameters,
    IDHPrivateKeyParameters)

  strict private
  var
    FX: TBigInteger;

    class function Validate(const AX: TBigInteger): TBigInteger; static; inline;

  strict protected

    function GetX: TBigInteger; virtual;

  public
    constructor Create(const AX: TBigInteger;
      const AParameters: IDHParameters); overload;

    constructor Create(const AX: TBigInteger; const AParameters: IDHParameters;
      const AAlgorithmOid: IDerObjectIdentifier); overload;

    function Equals(const AOther: IDHPrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property X: TBigInteger read GetX;
  end;

  TDHKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IDHKeyGenerationParameters)
  strict private
  var
    FParameters: IDHParameters;

    function GetParameters: IDHParameters; inline;

    class function GetStrengthLocal(const AParameters: IDHParameters): Int32;
      static; inline;

  public
    constructor Create(const ARandom: ISecureRandom;
      const AParameters: IDHParameters);

    property Parameters: IDHParameters read GetParameters;
  end;

implementation

{ TDHValidationParameters }

constructor TDHValidationParameters.Create(const ASeed: TCryptoLibByteArray;
  ACounter: Int32);
begin
  inherited Create();
  if (ASeed = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SSeedNil);
  end;

  FSeed := System.Copy(ASeed);
  FCounter := ACounter;
end;

function TDHValidationParameters.Equals(const AOther: IDHValidationParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDHValidationParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (Counter = AOther.Counter) and (TArrayUtilities.AreEqual(Seed,
    AOther.Seed));
end;

function TDHValidationParameters.GetCounter: Int32;
begin
  Result := FCounter;
end;

function TDHValidationParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := Counter xor TArrayUtilities.GetArrayHashCode(Seed);
end;

function TDHValidationParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := System.Copy(FSeed);
end;

{ TDHParameters }

function TDHParameters.GetL: Int32;
begin
  Result := FL;
end;

function TDHParameters.GetM: Int32;
begin
  Result := FM;
end;

function TDHParameters.GetJ: TBigInteger;
begin
  Result := FJ;
end;

function TDHParameters.GetP: TBigInteger;
begin
  Result := FP;
end;

function TDHParameters.GetQ: TBigInteger;
begin
  Result := FQ;
end;

function TDHParameters.GetG: TBigInteger;
begin
  Result := FG;
end;

class function TDHParameters.GetDefaultMParam(ALParam: Int32): Int32;
begin
  if (ALParam = 0) then
  begin
    Result := DefaultMinimumLength;
    Exit;
  end;

  Result := Min(ALParam, DefaultMinimumLength);
end;

constructor TDHParameters.Create(const AP, AG: TBigInteger);
begin
  Create(AP, AG, TBigInteger.GetDefault, 0);
end;

constructor TDHParameters.Create(const AP, AG, AQ: TBigInteger);
begin
  Create(AP, AG, AQ, 0);
end;

constructor TDHParameters.Create(const AP, AG, AQ: TBigInteger; AL: Int32);
begin
  Create(AP, AG, AQ, GetDefaultMParam(AL), AL, TBigInteger.GetDefault, nil);
end;

constructor TDHParameters.Create(const AP, AG, AQ: TBigInteger; AM, AL: Int32);
begin
  Create(AP, AG, AQ, AM, AL, TBigInteger.GetDefault, nil);
end;

constructor TDHParameters.Create(const AP, AG, AQ, AJ: TBigInteger;
  const AValidation: IDHValidationParameters);
begin
  Create(AP, AG, AQ, DefaultMinimumLength, 0, AJ, AValidation)
end;

constructor TDHParameters.Create(const AP, AG, AQ: TBigInteger; AM, AL: Int32;
  const AJ: TBigInteger; const AValidation: IDHValidationParameters);
begin
  inherited Create();
  if (not AP.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SPUnInitialized);
  end;

  if (not AG.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SGUnInitialized);
  end;

  if (not AP.TestBit(0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SMustBeOddPrime);
  end;

  if ((AG.CompareTo(TBigInteger.Two) < 0) or
    (AG.CompareTo(AP.Subtract(TBigInteger.Two)) > 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidGeneratorRange);
  end;

  if ((AQ.IsInitialized) and (AQ.BitLength >= AP.BitLength)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SQTooBigToBeAFactor);
  end;

  if (AM >= AP.BitLength) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SMTooBig);
  end;

  if (AL <> 0) then
  begin

    if (AL >= AP.BitLength) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SLErrorOne);
    end;
    if (AL < AM) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SLErrorTwo);
    end;
  end;

  if ((AJ.IsInitialized) and (AJ.CompareTo(TBigInteger.Two) < 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSubGroupFactor);
  end;

  FP := AP;
  FG := AG;
  FQ := AQ;
  FM := AM;
  FL := AL;
  FJ := AJ;
  FValidation := AValidation;
end;

function TDHParameters.Equals(const AOther: IDHParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDHParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := P.Equals(AOther.P) and Q.Equals(AOther.Q) and G.Equals(AOther.G);
end;

function TDHParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := P.GetHashCode() xor G.GetHashCode();

  if FQ.IsInitialized then
  begin
    Result := Result xor Q.GetHashCode();
  end;
end;

function TDHParameters.GetValidationParameters: IDHValidationParameters;
begin
  Result := FValidation;
end;

{ TDHKeyParameters }

function TDHKeyParameters.GetParameters: IDHParameters;
begin
  Result := FParameters;
end;

function TDHKeyParameters.GetAlgorithmOid: IDerObjectIdentifier;
begin
  Result := FAlgorithmOid;
end;

constructor TDHKeyParameters.Create(AIsPrivate: Boolean;
  const AParameters: IDHParameters);
begin
  Create(AIsPrivate, AParameters, TPkcsObjectIdentifiers.DhKeyAgreement);
end;

constructor TDHKeyParameters.Create(AIsPrivate: Boolean;
  const AParameters: IDHParameters; const AAlgorithmOid: IDerObjectIdentifier);
begin
  inherited Create(AIsPrivate);
  FParameters := AParameters;
  FAlgorithmOid := AAlgorithmOid;
end;

function TDHKeyParameters.Equals(const AOther: IDHKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDHKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;

  Result := Parameters.Equals(AOther.Parameters) and (inherited Equals(AOther));
end;

function TDHKeyParameters.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := inherited GetHashCode();

  if (Parameters <> nil) then
  begin
    Result := Result xor Parameters.GetHashCode();
  end;
end;

{ TDHPublicKeyParameters }

function TDHPublicKeyParameters.GetY: TBigInteger;
begin
  Result := FY;
end;

class function TDHPublicKeyParameters.Legendre(const AA, AB: TBigInteger): Int32;
var
  LBitLength: Int32;
  LLen: Int32;
  LA, LB, LT: TCryptoLibUInt32Array;
  LR: Int32;
  LShift: Int32;
  LBits: Int32;
  LCmp: Int32;
begin
  LBitLength := AB.BitLength;
  LLen := TNat.GetLengthForBits(LBitLength);
  LA := TNat.FromBigInteger(LBitLength, AA);
  LB := TNat.FromBigInteger(LBitLength, AB);
  LR := 0;

  while True do
  begin
    while LA[0] = 0 do
    begin
      TNat.ShiftDownWord(LLen, LA, 0);
    end;

    LShift := TBitOperations.NumberOfTrailingZeros32(LA[0]);
    if LShift > 0 then
    begin
      TNat.ShiftDownBits(LLen, LA, LShift, 0);
      LBits := Int32(LB[0]);
      LR := LR xor ((LBits xor (TBitOperations.Asr32(LBits, 1))) and (LShift shl 1));
    end;

    LCmp := TNat.Compare(LLen, LA, LB);
    if LCmp = 0 then
    begin
      Break;
    end;

    if LCmp < 0 then
    begin
      LR := LR xor Int32(UInt32(LA[0]) and UInt32(LB[0]));
      LT := LA;
      LA := LB;
      LB := LT;
    end;

    while (LLen > 0) and (LA[LLen - 1] = 0) do
    begin
      System.Dec(LLen);
    end;

    TNat.Sub(LLen, LA, LB, LA);
  end;

  if TNat.IsOne(LLen, LB) then
  begin
    Result := 1 - (LR and 2);
  end
  else
  begin
    Result := 0;
  end;
end;

class function TDHPublicKeyParameters.Validate(const AY: TBigInteger;
  const ADHParams: IDHParameters): TBigInteger;
var
  LP, LQ: TBigInteger;
begin
  if (not AY.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SYUnInitialized);
  end;

  LP := ADHParams.P;

  if ((AY.CompareTo(TBigInteger.Two) < 0) or
    (AY.CompareTo(LP.Subtract(TBigInteger.Two)) > 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidDHPublicKey);
  end;

  if (not ADHParams.Q.IsInitialized) then
  begin
    Result := AY;
    Exit;
  end;

  LQ := ADHParams.Q;

  if LP.TestBit(0) and ((LP.BitLength - 1) = LQ.BitLength) and
    LP.ShiftRight(1).Equals(LQ) then
  begin
    if Legendre(AY, LP) <> 1 then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidYInCorrectGroup);
    end;
    Result := AY;
    Exit;
  end;

  if (not AY.ModPow(LQ, LP).Equals(TBigInteger.One)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidYInCorrectGroup);
  end;

  Result := AY;
end;

constructor TDHPublicKeyParameters.Create(const AY: TBigInteger;
  const AParameters: IDHParameters);
begin
  inherited Create(False, AParameters);
  FY := Validate(AY, AParameters);
end;

constructor TDHPublicKeyParameters.Create(const AY: TBigInteger;
  const AParameters: IDHParameters; const AAlgorithmOid: IDerObjectIdentifier);
begin
  inherited Create(False, AParameters, AAlgorithmOid);
  FY := Validate(AY, AParameters);
end;

function TDHPublicKeyParameters.Equals(const AOther: IDHPublicKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDHPublicKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (Y.Equals(AOther.Y)) and (inherited Equals(AOther));
end;

function TDHPublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := Y.GetHashCode() xor (inherited GetHashCode());
end;

{ TDHPrivateKeyParameters }

function TDHPrivateKeyParameters.GetX: TBigInteger;
begin
  Result := FX;
end;

class function TDHPrivateKeyParameters.Validate(const AX: TBigInteger): TBigInteger;
begin
  if (not AX.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SXUnInitialized);
  end;
  Result := AX;
end;

constructor TDHPrivateKeyParameters.Create(const AX: TBigInteger;
  const AParameters: IDHParameters);
begin
  inherited Create(True, AParameters);
  FX := Validate(AX);
end;

constructor TDHPrivateKeyParameters.Create(const AX: TBigInteger;
  const AParameters: IDHParameters; const AAlgorithmOid: IDerObjectIdentifier);
begin
  inherited Create(True, AParameters, AAlgorithmOid);
  FX := Validate(AX);
end;

function TDHPrivateKeyParameters.Equals(const AOther: IDHPrivateKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDHPrivateKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (X.Equals(AOther.X)) and (inherited Equals(AOther));
end;

function TDHPrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := X.GetHashCode() xor (inherited GetHashCode());
end;

{ TDHKeyGenerationParameters }

function TDHKeyGenerationParameters.GetParameters: IDHParameters;
begin
  Result := FParameters;
end;

class function TDHKeyGenerationParameters.GetStrengthLocal(const AParameters: IDHParameters): Int32;
begin
  if AParameters.L <> 0 then
  begin
    Result := AParameters.L;
  end
  else
  begin
    Result := AParameters.P.BitLength;
  end;
end;

constructor TDHKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParameters: IDHParameters);
begin
  inherited Create(ARandom, GetStrengthLocal(AParameters));
  FParameters := AParameters;
end;

end.
