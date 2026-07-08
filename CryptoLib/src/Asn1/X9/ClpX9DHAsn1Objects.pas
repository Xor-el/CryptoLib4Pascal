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

unit ClpX9DHAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX9DHAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SInvalidParameters = 'invalid parameters';
  SSeedNil = 'seed cannot be nil';
  SPGenCounterNil = 'PGenCounter cannot be nil';
  SInvalidDHValidationParms = 'invalid DHValidationParms: %s';
  SPNil = 'P cannot be nil';
  SGNil = 'G cannot be nil';
  SQNil = 'Q cannot be nil';
  SJNil = 'J cannot be nil';
  SInvalidDHDomainParameters = 'invalid DHDomainParameters: %s';
  SInvalidDomainParameters = 'invalid DomainParameters: %s';
  SInvalidValidationParams = 'invalid ValidationParams: %s';
  SYNil = 'Y cannot be nil';
  SAlgorithmNil = 'algorithm cannot be nil';
  SCounterNil = 'counter cannot be nil';
  SKeyInfoNil = 'KeyInfo cannot be nil';
  SSuppPubInfoNil = 'SuppPubInfo cannot be nil';
  SElementNil = 'element cannot be nil';

type
  /// <summary>
  /// The DHPublicKey object (X9.42).
  /// </summary>
  TDHPublicKey = class(TAsn1Encodable, IDHPublicKey)

  strict private
  var
    FY: IDerInteger;

  strict protected
    function GetY: IDerInteger;

  public
    class function GetInstance(AObj: TObject): IDHPublicKey; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDHPublicKey; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHPublicKey; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHPublicKey; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHPublicKey; static;

    constructor Create(const AY: IDerInteger);

    function ToAsn1Object: IAsn1Object; override;

    property Y: IDerInteger read GetY;

  end;

  /// <summary>
  /// Diffie-Hellman domain validation parameters (X9.44).
  /// </summary>
  TValidationParams = class sealed(TAsn1Encodable, IValidationParams)

  strict private
  var
    FSeed: IDerBitString;
    FPgenCounter: IDerInteger;

  strict protected
    function GetSeed: IDerBitString;
    function GetPgenCounter: IDerInteger;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IValidationParams; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IValidationParams; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IValidationParams; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IValidationParams; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IValidationParams; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IValidationParams; static;

    constructor Create(const ASeed: IDerBitString;
      const APgenCounter: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Seed: IDerBitString read GetSeed;
    property PgenCounter: IDerInteger read GetPgenCounter;

  end;

  /// <summary>
  /// X9.44 Diffie-Hellman domain parameters.
  /// </summary>
  TDomainParameters = class sealed(TAsn1Encodable, IDomainParameters)

  strict private
  var
    FP, FG, FQ, FJ: IDerInteger;
    FValidationParams: IValidationParams;


  strict protected
    function GetP: IDerInteger;
    function GetG: IDerInteger;
    function GetQ: IDerInteger;
    function GetJ: IDerInteger;
    function GetValidationParams: IValidationParams;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IDomainParameters; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDomainParameters; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDomainParameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDomainParameters; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IDomainParameters; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDomainParameters; static;

    constructor Create(const AP, AG, AQ, AJ: IDerInteger;
      const AValidationParams: IValidationParams); overload;

    function ToAsn1Object: IAsn1Object; override;

    property P: IDerInteger read GetP;
    property G: IDerInteger read GetG;
    property Q: IDerInteger read GetQ;
    property J: IDerInteger read GetJ;
    property ValidationParams: IValidationParams read GetValidationParams;

  end;

  /// <summary>
  /// The DHValidationParms object.
  /// </summary>
  TDHValidationParms = class(TAsn1Encodable, IDHValidationParms)

  strict private
  var
    FSeed: IDerBitString;
    FPGenCounter: IDerInteger;

  strict protected
    function GetSeed: IDerBitString;
    function GetPGenCounter: IDerInteger;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    /// <summary>
    /// Parse a DHValidationParms from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDHValidationParms; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDHValidationParms; overload; static;
    /// <summary>
    /// Parse a DHValidationParms from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHValidationParms; overload; static;
    /// <summary>
    /// Parse a DHValidationParms from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHValidationParms; overload; static;
    /// <summary>
    /// Get optional DHValidationParms.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDHValidationParms; static;
    /// <summary>
    /// Get tagged DHValidationParms.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHValidationParms; static;

    constructor Create(const ASeed: IDerBitString;
      const APGenCounter: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Seed: IDerBitString read GetSeed;
    property PGenCounter: IDerInteger read GetPGenCounter;

  end deprecated 'Use TValidationParams instead';

  /// <summary>
  /// The DHDomainParameters object.
  /// </summary>
  TDHDomainParameters = class(TAsn1Encodable, IDHDomainParameters)

  strict private
  var
    FP, FG, FQ, FJ: IDerInteger;
    FValidationParams: IValidationParams;


  strict protected
    function GetP: IDerInteger;
    function GetG: IDerInteger;
    function GetQ: IDerInteger;
    function GetJ: IDerInteger;
    function GetValidationParms: IDHValidationParms;
    function GetValidationParams: IValidationParams;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    /// <summary>
    /// Parse a DHDomainParameters from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDHDomainParameters; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDHDomainParameters; overload; static;
    /// <summary>
    /// Parse a DHDomainParameters from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHDomainParameters; overload; static;
    /// <summary>
    /// Parse a DHDomainParameters from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHDomainParameters; overload; static;
    /// <summary>
    /// Get tagged DHDomainParameters.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHDomainParameters; static;

    constructor Create(const AP, AG, AQ, AJ: IDerInteger;
      const AValidationParms: IDHValidationParms); overload;
    constructor Create(const AP, AG, AQ, AJ: IDerInteger;
      const AValidationParams: IValidationParams); overload;

    function ToAsn1Object: IAsn1Object; override;

    property P: IDerInteger read GetP;
    property G: IDerInteger read GetG;
    property Q: IDerInteger read GetQ;
    property J: IDerInteger read GetJ;
    property ValidationParms: IDHValidationParms read GetValidationParms;
    property ValidationParams: IValidationParams read GetValidationParams;

  end deprecated 'Use TDomainParameters instead';

  /// <summary>
  /// ASN.1 KeySpecificInfo structure (RFC 2631 / X9.42).
  /// </summary>
  TKeySpecificInfo = class(TAsn1Encodable, IKeySpecificInfo)

  strict private
  var
    FAlgorithm: IDerObjectIdentifier;
    FCounter: IAsn1OctetString;

  strict protected
    function GetAlgorithm: IDerObjectIdentifier;
    function GetCounter: IAsn1OctetString;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IKeySpecificInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IKeySpecificInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IKeySpecificInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IKeySpecificInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IKeySpecificInfo; static;

    constructor Create(const AAlgorithm: IDerObjectIdentifier;
      const ACounter: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Counter: IAsn1OctetString read GetCounter;

  end;

  /// <summary>
  /// ASN.1 OtherInfo structure (RFC 2631 / X9.42).
  /// </summary>
  TOtherInfo = class(TAsn1Encodable, IOtherInfo)

  strict private
  var
    FKeyInfo: IKeySpecificInfo;
    FPartyAInfo: IAsn1OctetString;
    FSuppPubInfo: IAsn1OctetString;


  strict protected
    function GetKeyInfo: IKeySpecificInfo;
    function GetPartyAInfo: IAsn1OctetString;
    function GetSuppPubInfo: IAsn1OctetString;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IOtherInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IOtherInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IOtherInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IOtherInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IOtherInfo; static;

    constructor Create(const AKeyInfo: IKeySpecificInfo;
      const APartyAInfo: IAsn1OctetString; const ASuppPubInfo: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property KeyInfo: IKeySpecificInfo read GetKeyInfo;
    property PartyAInfo: IAsn1OctetString read GetPartyAInfo;
    property SuppPubInfo: IAsn1OctetString read GetSuppPubInfo;

  end;

implementation

{ TDHPublicKey }

class function TDHPublicKey.GetInstance(AObj: TObject): IDHPublicKey;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHPublicKey, Result) then
    Exit;

  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AObj));
end;

class function TDHPublicKey.GetInstance(const AObj: IAsn1Convertible): IDHPublicKey;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHPublicKey, Result) then
    Exit;

  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AObj));
end;

class function TDHPublicKey.GetInstance(const AEncoded: TCryptoLibByteArray): IDHPublicKey;
begin
  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AEncoded));
end;

class function TDHPublicKey.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHPublicKey;
begin
  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AObj, AExplicitly));
end;

class function TDHPublicKey.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHPublicKey;
begin
  Result := TDHPublicKey.Create(TDerInteger.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDHPublicKey.Create(const AY: IDerInteger);
begin
  inherited Create();
  if AY = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SYNil);
  FY := AY;
end;

function TDHPublicKey.GetY: IDerInteger;
begin
  Result := FY;
end;

function TDHPublicKey.ToAsn1Object: IAsn1Object;
begin
  Result := FY;
end;

{ TValidationParams }

class function TValidationParams.GetInstance(AObj: TObject): IValidationParams;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IValidationParams, Result) then
    Exit;

  Result := TValidationParams.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TValidationParams.GetInstance(const AObj: IAsn1Convertible): IValidationParams;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IValidationParams, Result) then
    Exit;

  Result := TValidationParams.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TValidationParams.GetInstance(const AEncoded: TCryptoLibByteArray): IValidationParams;
begin
  Result := TValidationParams.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TValidationParams.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IValidationParams;
begin
  Result := TValidationParams.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TValidationParams.GetOptional(const AElement: IAsn1Encodable): IValidationParams;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SElementNil);

  if Supports(AElement, IValidationParams, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TValidationParams.Create(LSequence)
  else
    Result := nil;
end;

class function TValidationParams.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IValidationParams;
begin
  Result := TValidationParams.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TValidationParams.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  FSeed := TAsn1Utilities.Read<IDerBitString>(ASeq, LPos, TDerBitString.GetInstance);
  FPgenCounter := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TValidationParams.Create(const ASeed: IDerBitString;
  const APgenCounter: IDerInteger);
begin
  inherited Create();

  if ASeed = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSeedNil);

  if APgenCounter = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPGenCounterNil);

  FSeed := ASeed;
  FPgenCounter := APgenCounter;
end;

function TValidationParams.GetSeed: IDerBitString;
begin
  Result := FSeed;
end;

function TValidationParams.GetPgenCounter: IDerInteger;
begin
  Result := FPgenCounter;
end;

function TValidationParams.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FSeed, FPgenCounter]);
end;

{ TDomainParameters }

class function TDomainParameters.GetInstance(AObj: TObject): IDomainParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDomainParameters, Result) then
    Exit;

  Result := TDomainParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDomainParameters.GetInstance(const AObj: IAsn1Convertible): IDomainParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDomainParameters, Result) then
    Exit;

  Result := TDomainParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDomainParameters.GetInstance(const AEncoded: TCryptoLibByteArray): IDomainParameters;
begin
  Result := TDomainParameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDomainParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDomainParameters;
begin
  Result := TDomainParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDomainParameters.GetOptional(const AElement: IAsn1Encodable): IDomainParameters;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SElementNil);

  if Supports(AElement, IDomainParameters, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TDomainParameters.Create(LSequence)
  else
    Result := nil;
end;

class function TDomainParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDomainParameters;
begin
  Result := TDomainParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDomainParameters.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 3, 5);
  FP := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FG := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FQ := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FJ := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, TDerInteger.GetOptional);
  FValidationParams := TAsn1Utilities.ReadOptional<IValidationParams>(ASeq, LPos, TValidationParams.GetOptional);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TDomainParameters.Create(const AP, AG, AQ, AJ: IDerInteger;
  const AValidationParams: IValidationParams);
begin
  inherited Create();

  if AP = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPNil);

  if AG = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SGNil);

  if AQ = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  FP := AP;
  FG := AG;
  FQ := AQ;
  FJ := AJ;
  FValidationParams := AValidationParams;
end;

function TDomainParameters.GetP: IDerInteger;
begin
  Result := FP;
end;

function TDomainParameters.GetG: IDerInteger;
begin
  Result := FG;
end;

function TDomainParameters.GetQ: IDerInteger;
begin
  Result := FQ;
end;

function TDomainParameters.GetJ: IDerInteger;
begin
  Result := FJ;
end;

function TDomainParameters.GetValidationParams: IValidationParams;
begin
  Result := FValidationParams;
end;

function TDomainParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create([FP, FG, FQ]);
  if FJ <> nil then
    LV.Add([FJ]);
  if FValidationParams <> nil then
    LV.Add([FValidationParams]);
  Result := TDerSequence.Create(LV);
end;

{ TDHValidationParms }

class function TDHValidationParms.GetInstance(AObj: TObject): IDHValidationParms;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHValidationParms, Result) then
    Exit;

  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHValidationParms.GetInstance(const AObj: IAsn1Convertible): IDHValidationParms;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHValidationParms, Result) then
    Exit;

  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHValidationParms.GetInstance(const AEncoded: TCryptoLibByteArray): IDHValidationParms;
begin
  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDHValidationParms.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHValidationParms;
begin
  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDHValidationParms.GetOptional(const AElement: IAsn1Encodable): IDHValidationParms;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SElementNil);

  if Supports(AElement, IDHValidationParms, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TDHValidationParms.Create(LSequence)
  else
    Result := nil;
end;

class function TDHValidationParms.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHValidationParms;
begin
  Result := TDHValidationParms.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDHValidationParms.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  FSeed := TAsn1Utilities.Read<IDerBitString>(ASeq, LPos, TDerBitString.GetInstance);
  FPGenCounter := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TDHValidationParms.Create(const ASeed: IDerBitString;
  const APGenCounter: IDerInteger);
begin
  inherited Create();

  if ASeed = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSeedNil);

  if APGenCounter = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPGenCounterNil);

  FSeed := ASeed;
  FPGenCounter := APGenCounter;
end;

function TDHValidationParms.GetSeed: IDerBitString;
begin
  Result := FSeed;
end;

function TDHValidationParms.GetPGenCounter: IDerInteger;
begin
  Result := FPGenCounter;
end;

function TDHValidationParms.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FSeed, FPGenCounter]);
end;

{ TDHDomainParameters }

class function TDHDomainParameters.GetInstance(AObj: TObject): IDHDomainParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHDomainParameters, Result) then
    Exit;

  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHDomainParameters.GetInstance(const AObj: IAsn1Convertible): IDHDomainParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHDomainParameters, Result) then
    Exit;

  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHDomainParameters.GetInstance(const AEncoded: TCryptoLibByteArray): IDHDomainParameters;
begin
  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDHDomainParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHDomainParameters;
begin
  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDHDomainParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHDomainParameters;
begin
  Result := TDHDomainParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDHDomainParameters.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 3, 5);
  FP := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FG := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FQ := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FJ := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, TDerInteger.GetOptional);
  FValidationParams := TAsn1Utilities.ReadOptional<IValidationParams>(ASeq, LPos, TValidationParams.GetOptional);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TDHDomainParameters.Create(const AP, AG, AQ, AJ: IDerInteger;
  const AValidationParms: IDHValidationParms);
var
  LValidationParams: IValidationParams;
begin
  if AValidationParms <> nil then
    LValidationParams := TValidationParams.Create(AValidationParms.Seed,
      AValidationParms.PGenCounter)
  else
    LValidationParams := nil;
  Create(AP, AG, AQ, AJ, LValidationParams);
end;

constructor TDHDomainParameters.Create(const AP, AG, AQ, AJ: IDerInteger;
  const AValidationParams: IValidationParams);
begin
  inherited Create();

  if AP = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPNil);

  if AG = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SGNil);

  if AQ = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  FP := AP;
  FG := AG;
  FQ := AQ;
  FJ := AJ;
  FValidationParams := AValidationParams;
end;

function TDHDomainParameters.GetP: IDerInteger;
begin
  Result := FP;
end;

function TDHDomainParameters.GetG: IDerInteger;
begin
  Result := FG;
end;

function TDHDomainParameters.GetQ: IDerInteger;
begin
  Result := FQ;
end;

function TDHDomainParameters.GetJ: IDerInteger;
begin
  Result := FJ;
end;

function TDHDomainParameters.GetValidationParms: IDHValidationParms;
begin
  if FValidationParams = nil then
    Result := nil
  else
    Result := TDHValidationParms.Create(FValidationParams.Seed,
      FValidationParams.PgenCounter);
end;

function TDHDomainParameters.GetValidationParams: IValidationParams;
begin
  Result := FValidationParams;
end;

function TDHDomainParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create([FP, FG, FQ]);
  if FJ <> nil then
    LV.Add([FJ]);
  if FValidationParams <> nil then
    LV.Add([FValidationParams]);
  Result := TDerSequence.Create(LV);
end;

{ TKeySpecificInfo }

class function TKeySpecificInfo.GetInstance(AObj: TObject): IKeySpecificInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IKeySpecificInfo, Result) then
    Exit;

  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TKeySpecificInfo.GetInstance(const AObj: IAsn1Convertible): IKeySpecificInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IKeySpecificInfo, Result) then
    Exit;

  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TKeySpecificInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IKeySpecificInfo;
begin
  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TKeySpecificInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IKeySpecificInfo;
begin
  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TKeySpecificInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IKeySpecificInfo;
begin
  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TKeySpecificInfo.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  FAlgorithm := TAsn1Utilities.Read<IDerObjectIdentifier>(ASeq, LPos, TDerObjectIdentifier.GetInstance);
  FCounter := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TKeySpecificInfo.Create(const AAlgorithm: IDerObjectIdentifier;
  const ACounter: IAsn1OctetString);
begin
  inherited Create();

  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if ACounter = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCounterNil);

  FAlgorithm := AAlgorithm;
  FCounter := ACounter;
end;

function TKeySpecificInfo.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

function TKeySpecificInfo.GetCounter: IAsn1OctetString;
begin
  Result := FCounter;
end;

function TKeySpecificInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FAlgorithm, FCounter);
end;

{ TOtherInfo }

class function TOtherInfo.GetInstance(AObj: TObject): IOtherInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOtherInfo, Result) then
    Exit;

  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOtherInfo.GetInstance(const AObj: IAsn1Convertible): IOtherInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOtherInfo, Result) then
    Exit;

  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOtherInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IOtherInfo;
begin
  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TOtherInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IOtherInfo;
begin
  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TOtherInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IOtherInfo;
begin
  Result := TOtherInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TOtherInfo.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 3);
  FKeyInfo := TAsn1Utilities.Read<IKeySpecificInfo>(ASeq, LPos, TKeySpecificInfo.GetInstance);
  FPartyAInfo := TAsn1Utilities.ReadOptionalContextTagged<IAsn1OctetString>(ASeq, LPos, 0, True,
    TAsn1OctetString.GetTagged);
  FSuppPubInfo := TAsn1Utilities.ReadContextTagged<IAsn1OctetString>(ASeq, LPos, 2, True,
    TAsn1OctetString.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TOtherInfo.Create(const AKeyInfo: IKeySpecificInfo;
  const APartyAInfo: IAsn1OctetString; const ASuppPubInfo: IAsn1OctetString);
begin
  inherited Create();

  if AKeyInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SKeyInfoNil);

  if ASuppPubInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSuppPubInfoNil);

  FKeyInfo := AKeyInfo;
  FPartyAInfo := APartyAInfo;
  FSuppPubInfo := ASuppPubInfo;
end;

function TOtherInfo.GetKeyInfo: IKeySpecificInfo;
begin
  Result := FKeyInfo;
end;

function TOtherInfo.GetPartyAInfo: IAsn1OctetString;
begin
  Result := FPartyAInfo;
end;

function TOtherInfo.GetSuppPubInfo: IAsn1OctetString;
begin
  Result := FSuppPubInfo;
end;

function TOtherInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.Add(FKeyInfo);
  LV.AddOptionalTagged(True, 0, FPartyAInfo);
  LV.AddTagged(True, 2, FSuppPubInfo);
  Result := TDerSequence.Create(LV);
end;

end.
