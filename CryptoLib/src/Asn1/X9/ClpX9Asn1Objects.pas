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
  ClpIX9ECAsn1Objects,
  ClpX9ECAsn1Objects,
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
