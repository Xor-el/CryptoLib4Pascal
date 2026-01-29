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

unit ClpX9Asn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX9Asn1Objects,
  ClpIX9ECParameters,
  ClpX9ECParameters,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SInvalidParameters = 'Invalid parameters';
  SBadSequenceSize = 'Bad sequence size: %d';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SSeedNil = 'Seed Cannot be Nil';
  SPGenCounterNil = 'PGenCounter Cannot be Nil';
  SInvalidDHValidationParms = 'Invalid DHValidationParms: %s';
  SPNil = 'P Cannot be Nil';
  SGNil = 'G Cannot be Nil';
  SQNil = 'Q Cannot be Nil';
  SJNil = 'J Cannot be Nil';
  SInvalidDHDomainParameters = 'Invalid DHDomainParameters: %s';

type
  /// <summary>
  /// The X962Parameters object.
  /// </summary>
  TX962Parameters = class(TAsn1Encodable, IX962Parameters)

  strict private
  var
    FParameters: IAsn1Object;

  strict protected
    function GetParameters: IAsn1Object;
    function GetNamedCurve: IDerObjectIdentifier;
    function IsImplicitlyCA: Boolean;
    function IsNamedCurve: Boolean;

  public
    class function GetInstance(AObj: TObject): IX962Parameters; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IX962Parameters; overload; static;
    class function GetInstance(const AElement: IAsn1Encodable): IX962Parameters; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IX962Parameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IX962Parameters; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IX962Parameters; static;

    constructor Create(const AParameters: IX9ECParameters); overload;
    constructor Create(const AParameters: IDerObjectIdentifier); overload;
    constructor Create(const AParameters: IAsn1Null); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Parameters: IAsn1Object read GetParameters;

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

  end;

  /// <summary>
  /// The DHDomainParameters object.
  /// </summary>
  TDHDomainParameters = class(TAsn1Encodable, IDHDomainParameters)

  strict private
  var
    FP, FG, FQ, FJ: IDerInteger;
    FValidationParms: IDHValidationParms;

  strict protected
    function GetP: IDerInteger;
    function GetG: IDerInteger;
    function GetQ: IDerInteger;
    function GetJ: IDerInteger;
    function GetValidationParms: IDHValidationParms;

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

    function ToAsn1Object: IAsn1Object; override;

    property P: IDerInteger read GetP;
    property G: IDerInteger read GetG;
    property Q: IDerInteger read GetQ;
    property J: IDerInteger read GetJ;
    property ValidationParms: IDHValidationParms read GetValidationParms;

  end;

implementation

{ TX962Parameters }

class function TX962Parameters.GetInstance(AObj: TObject): IX962Parameters;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX962Parameters>(AObj,
    function(AElement: IAsn1Encodable): IX962Parameters
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TX962Parameters.GetOptional(const AElement: IAsn1Encodable): IX962Parameters;
var
  LECParams: IX9ECParameters;
  LNamedCurve: IDerObjectIdentifier;
  LNull: IAsn1Null;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX962Parameters, Result) then
    Exit;

  LECParams := TX9ECParameters.GetOptional(AElement);
  if LECParams <> nil then
  begin
    Result := TX962Parameters.Create(LECParams);
    Exit;
  end;

  LNamedCurve := TDerObjectIdentifier.GetOptional(AElement);
  if LNamedCurve <> nil then
  begin
    Result := TX962Parameters.Create(LNamedCurve);
    Exit;
  end;

  LNull := TAsn1Null.GetOptional(AElement);
  if LNull <> nil then
  begin
    Result := TX962Parameters.Create(LNull);
    Exit;
  end;

  Result := nil;
end;

class function TX962Parameters.GetInstance(const AObj: IAsn1Object): IX962Parameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX962Parameters, Result) then
    Exit;

  Result := GetOptional(AObj);
end;

class function TX962Parameters.GetInstance(const AElement: IAsn1Encodable): IX962Parameters;
begin
  if AElement = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := GetOptional(AElement);
  if Result = nil then
    raise EArgumentCryptoLibException.Create('unable to parse X962Parameters');
end;

class function TX962Parameters.GetInstance(const AEncoded: TCryptoLibByteArray): IX962Parameters;
var
  LAsn1Obj: IAsn1Object;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    LAsn1Obj := TAsn1Object.FromByteArray(AEncoded);
    Result := GetInstance(LAsn1Obj);
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct X962Parameters from byte[]: ' + E.Message);
  end;
end;

class function TX962Parameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IX962Parameters;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX962Parameters>(AObj, AExplicitly,
    function(AElement: IAsn1Encodable): IX962Parameters
    begin
      Result := GetInstance(AElement);
    end);
end;

constructor TX962Parameters.Create(const AParameters: IX9ECParameters);
begin
  inherited Create();
  FParameters := AParameters.ToAsn1Object();
end;

constructor TX962Parameters.Create(const AParameters: IDerObjectIdentifier);
begin
  inherited Create();
  FParameters := AParameters;
end;

constructor TX962Parameters.Create(const AParameters: IAsn1Null);
begin
  inherited Create();
  FParameters := AParameters;
end;

function TX962Parameters.GetParameters: IAsn1Object;
begin
  Result := FParameters;
end;

function TX962Parameters.IsImplicitlyCA: Boolean;
var
  LNull: IAsn1Null;
begin
  // IsImplicitlyCA => m_params is Asn1Null
  // Check if FParameters is an Asn1Null instance (not nil check)
  Result := Supports(FParameters, IAsn1Null, LNull);
end;

function TX962Parameters.GetNamedCurve: IDerObjectIdentifier;
begin
  if not Supports(FParameters, IDerObjectIdentifier, Result) then
    Result := nil;
end;

function TX962Parameters.IsNamedCurve: Boolean;
begin
  Result := GetNamedCurve <> nil;
end;

function TX962Parameters.ToAsn1Object: IAsn1Object;
begin
  Result := FParameters;
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
    raise EArgumentNilCryptoLibException.Create('element');

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
begin
  inherited Create();
  if ASeq.Count <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [ASeq.Count]);

  FSeed := TDerBitString.GetInstance(ASeq[0]);
  FPGenCounter := TDerInteger.GetInstance(ASeq[1]);
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
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 5) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FP := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FG := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FQ := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FJ := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, function(AElement: IAsn1Encodable): IDerInteger
    begin
      Result := TDerInteger.GetOptional(AElement);
    end);

  FValidationParms := TAsn1Utilities.ReadOptional<IDHValidationParms>(ASeq, LPos, function(AElement: IAsn1Encodable): IDHValidationParms
    begin
      Result := TDHValidationParms.GetOptional(AElement);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TDHDomainParameters.Create(const AP, AG, AQ, AJ: IDerInteger;
  const AValidationParms: IDHValidationParms);
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
  FValidationParms := AValidationParms;
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
  Result := FValidationParms;
end;

function TDHDomainParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create([FP, FG, FQ]);
  if FJ <> nil then
    LV.Add([FJ]);
  if FValidationParms <> nil then
    LV.Add([FValidationParms]);
  Result := TDerSequence.Create(LV);
end;

end.
