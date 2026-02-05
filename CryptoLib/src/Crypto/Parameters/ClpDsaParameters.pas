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

unit ClpDsaParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIDsaParameters,
  ClpAsymmetricKeyParameter,
  ClpBigInteger,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SPUnInitialized = '"P" Cannot Be Uninitialized';
  SQUnInitialized = '"Q" Cannot Be Uninitialized';
  SGUnInitialized = '"G" Cannot Be Uninitialized';
  SSeedNil = '"Seed" Cannot Be Nil';
  SYUnInitialized = '"Y" Cannot Be Uninitialized';
  SInvalidYInCorrectGroup = '"Y" Value Does Not Appear To Be In Correct Group';
  SXUnInitialized = '"X" Cannot Be Uninitialized';

type
  TDsaValidationParameters = class(TInterfacedObject, IDsaValidationParameters)
  strict private
  var
    FSeed: TCryptoLibByteArray;
    FCounter, FUsageIndex: Int32;

    function GetCounter: Int32; virtual;
    function GetUsageIndex: Int32; virtual;
    function GetSeed: TCryptoLibByteArray; virtual;

  public
    constructor Create(const ASeed: TCryptoLibByteArray;
      ACounter: Int32); overload;
    constructor Create(const ASeed: TCryptoLibByteArray;
      ACounter, AUsageIndex: Int32); overload;

    function Equals(const AOther: IDsaValidationParameters): Boolean;
      reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Counter: Int32 read GetCounter;
    property UsageIndex: Int32 read GetUsageIndex;
    property Seed: TCryptoLibByteArray read GetSeed;
  end;

  TDsaParameters = class(TInterfacedObject, ICipherParameters, IDsaParameters)

  strict private
  var
    FP, FQ, FG: TBigInteger;
    FValidation: IDsaValidationParameters;

    function GetG: TBigInteger; inline;
    function GetP: TBigInteger; inline;
    function GetQ: TBigInteger; inline;
    function GetValidationParameters: IDsaValidationParameters; inline;

  public

    constructor Create(const AP, AQ, AG: TBigInteger); overload;
    constructor Create(const AP, AQ, AG: TBigInteger;
      const AValidationParameters: IDsaValidationParameters); overload;

    function Equals(const AOther: IDsaParameters): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property P: TBigInteger read GetP;
    property Q: TBigInteger read GetQ;
    property G: TBigInteger read GetG;
    property ValidationParameters: IDsaValidationParameters
      read GetValidationParameters;

  end;

  TDsaKeyParameters = class abstract(TAsymmetricKeyParameter, IDsaKeyParameters)

  strict private
  var
    FParameters: IDsaParameters;
  strict protected
    function GetParameters: IDsaParameters;
    constructor Create(AIsPrivate: Boolean; const AParameters: IDsaParameters);

  public
    function Equals(const AOther: IDsaKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Parameters: IDsaParameters read GetParameters;

  end;

  TDsaPublicKeyParameters = class sealed(TDsaKeyParameters,
    IDsaPublicKeyParameters)

  strict private
  var
    FY: TBigInteger;

    class function Validate(const AY: TBigInteger;
      const AParameters: IDsaParameters): TBigInteger; static; inline;

    function GetY: TBigInteger; inline;

  public
    constructor Create(const AY: TBigInteger; const AParameters: IDsaParameters);

    function Equals(const AOther: IDsaPublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Y: TBigInteger read GetY;
  end;

  TDsaPrivateKeyParameters = class sealed(TDsaKeyParameters,
    IDsaPrivateKeyParameters)

  strict private
  var
    FX: TBigInteger;

    function GetX: TBigInteger; inline;

    class function Validate(const AX: TBigInteger): TBigInteger; static; inline;

  public
    constructor Create(const AX: TBigInteger; const AParameters: IDsaParameters);

    function Equals(const AOther: IDsaPrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property X: TBigInteger read GetX;
  end;

  TDsaKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IDsaKeyGenerationParameters)
  strict private
  var
    FParameters: IDsaParameters;

    function GetParameters: IDsaParameters; inline;

  public
    constructor Create(const ARandom: ISecureRandom;
      const AParameters: IDsaParameters);

    property Parameters: IDsaParameters read GetParameters;
  end;

  TDsaParameterGenerationParameters = class(TInterfacedObject,
    IDsaParameterGenerationParameters)

  strict private
  var
    FL, FN, FCertainty, FUsageIndex: Int32;
    FRandom: ISecureRandom;

  strict protected

    function GetL: Int32; virtual;
    function GetN: Int32; virtual;
    function GetCertainty: Int32; virtual;
    function GetUsageIndex: Int32; virtual;
    function GetRandom: ISecureRandom; virtual;

  public

    const
    DigitalSignatureUsage = Int32(1);
    KeyEstablishmentUsage = Int32(2);

    constructor Create(AL, AN, ACertainty: Int32;
      const ARandom: ISecureRandom); overload;

    constructor Create(AL, AN, ACertainty: Int32; const ARandom: ISecureRandom;
      AUsageIndex: Int32); overload;

    property L: Int32 read GetL;
    property N: Int32 read GetN;
    property UsageIndex: Int32 read GetUsageIndex;
    property Certainty: Int32 read GetCertainty;
    property Random: ISecureRandom read GetRandom;

  end;

implementation

{ TDsaValidationParameters }

constructor TDsaValidationParameters.Create(const ASeed: TCryptoLibByteArray;
  ACounter: Int32);
begin
  Create(ASeed, ACounter, -1);
end;

constructor TDsaValidationParameters.Create(const ASeed: TCryptoLibByteArray;
  ACounter, AUsageIndex: Int32);
begin
  inherited Create();
  if (ASeed = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SSeedNil);
  end;

  FSeed := System.Copy(ASeed);
  FCounter := ACounter;
  FUsageIndex := AUsageIndex;
end;

function TDsaValidationParameters.Equals(const AOther: IDsaValidationParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDsaValidationParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (Counter = AOther.Counter) and TArrayUtilities.AreEqual<Byte>(Seed,
    AOther.Seed);
end;

function TDsaValidationParameters.GetCounter: Int32;
begin
  Result := FCounter;
end;

function TDsaValidationParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := Counter xor TArrayUtilities.GetArrayHashCode(Seed);
end;

function TDsaValidationParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := System.Copy(FSeed);
end;

function TDsaValidationParameters.GetUsageIndex: Int32;
begin
  Result := FUsageIndex;
end;

{ TDsaParameters }

function TDsaParameters.GetG: TBigInteger;
begin
  Result := FG;
end;

function TDsaParameters.GetP: TBigInteger;
begin
  Result := FP;
end;

function TDsaParameters.GetQ: TBigInteger;
begin
  Result := FQ;
end;

function TDsaParameters.GetValidationParameters: IDsaValidationParameters;
begin
  Result := FValidation;
end;

constructor TDsaParameters.Create(const AP, AQ, AG: TBigInteger);
begin
  Create(AP, AQ, AG, nil);
end;

constructor TDsaParameters.Create(const AP, AQ, AG: TBigInteger;
  const AValidationParameters: IDsaValidationParameters);
begin
  inherited Create();
  if (not AP.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SPUnInitialized);
  end;

  if (not AQ.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SQUnInitialized);
  end;

  if (not AG.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SGUnInitialized);
  end;

  FP := AP;
  FQ := AQ;
  FG := AG;
  FValidation := AValidationParameters;
end;

function TDsaParameters.Equals(const AOther: IDsaParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDsaParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := P.Equals(AOther.P) and Q.Equals(AOther.Q) and G.Equals(AOther.G);
end;

function TDsaParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := P.GetHashCode() xor Q.GetHashCode() xor G.GetHashCode();
end;

{ TDsaKeyParameters }

constructor TDsaKeyParameters.Create(AIsPrivate: Boolean;
  const AParameters: IDsaParameters);
begin
  inherited Create(AIsPrivate);
  FParameters := AParameters;
end;

function TDsaKeyParameters.Equals(const AOther: IDsaKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDsaKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;

  Result := Parameters.Equals(AOther.Parameters) and (inherited Equals(AOther));
end;

function TDsaKeyParameters.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := inherited GetHashCode();

  if (Parameters <> nil) then
  begin
    Result := Result xor Parameters.GetHashCode();
  end;
end;

function TDsaKeyParameters.GetParameters: IDsaParameters;
begin
  Result := FParameters;
end;

{ TDsaPublicKeyParameters }

function TDsaPublicKeyParameters.GetY: TBigInteger;
begin
  Result := FY;
end;

class function TDsaPublicKeyParameters.Validate(const AY: TBigInteger;
  const AParameters: IDsaParameters): TBigInteger;
begin
  if (not AY.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SYUnInitialized);
  end;
  if (AParameters <> nil) then
  begin
    if ((AY.CompareTo(TBigInteger.Two) < 0) or
      (AY.CompareTo(AParameters.P.Subtract(TBigInteger.Two)) > 0) or
      (not AY.ModPow(AParameters.Q, AParameters.P).Equals(TBigInteger.One))) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidYInCorrectGroup);
    end;
  end;

  Result := AY;
end;

constructor TDsaPublicKeyParameters.Create(const AY: TBigInteger;
  const AParameters: IDsaParameters);
begin
  inherited Create(False, AParameters);
  FY := Validate(AY, AParameters);
end;

function TDsaPublicKeyParameters.Equals(const AOther: IDsaPublicKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDsaPublicKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (Y.Equals(AOther.Y)) and (inherited Equals(AOther));
end;

function TDsaPublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := Y.GetHashCode() xor (inherited GetHashCode());
end;

{ TDsaPrivateKeyParameters }

function TDsaPrivateKeyParameters.GetX: TBigInteger;
begin
  Result := FX;
end;

class function TDsaPrivateKeyParameters.Validate(const AX: TBigInteger): TBigInteger;
begin
  if (not AX.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SXUnInitialized);
  end;
  Result := AX;
end;

constructor TDsaPrivateKeyParameters.Create(const AX: TBigInteger;
  const AParameters: IDsaParameters);
begin
  inherited Create(True, AParameters);
  FX := Validate(AX);
end;

function TDsaPrivateKeyParameters.Equals(const AOther: IDsaPrivateKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IDsaPrivateKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (X.Equals(AOther.X)) and (inherited Equals(AOther));
end;

function TDsaPrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := X.GetHashCode() xor (inherited GetHashCode());
end;

{ TDsaKeyGenerationParameters }

constructor TDsaKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParameters: IDsaParameters);
var
  LP: TBigInteger;
begin
  LP := AParameters.P;
  inherited Create(ARandom, LP.BitLength - 1);
  FParameters := AParameters;
end;

function TDsaKeyGenerationParameters.GetParameters: IDsaParameters;
begin
  Result := FParameters;
end;

{ TDsaParameterGenerationParameters }

constructor TDsaParameterGenerationParameters.Create(AL, AN, ACertainty: Int32;
  const ARandom: ISecureRandom);
begin
  Create(AL, AN, ACertainty, ARandom, -1);
end;

constructor TDsaParameterGenerationParameters.Create(AL, AN, ACertainty: Int32;
  const ARandom: ISecureRandom; AUsageIndex: Int32);
begin
  inherited Create();
  FL := AL;
  FN := AN;
  FCertainty := ACertainty;
  FRandom := ARandom;
  FUsageIndex := AUsageIndex;
end;

function TDsaParameterGenerationParameters.GetL: Int32;
begin
  Result := FL;
end;

function TDsaParameterGenerationParameters.GetN: Int32;
begin
  Result := FN;
end;

function TDsaParameterGenerationParameters.GetCertainty: Int32;
begin
  Result := FCertainty;
end;

function TDsaParameterGenerationParameters.GetUsageIndex: Int32;
begin
  Result := FUsageIndex;
end;

function TDsaParameterGenerationParameters.GetRandom: ISecureRandom;
begin
  Result := FRandom;
end;

end.
