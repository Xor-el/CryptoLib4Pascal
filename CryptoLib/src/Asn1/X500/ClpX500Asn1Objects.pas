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

unit ClpX500Asn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX500Asn1Objects,
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  ClpAsn1Utilities,
  ClpAsn1Comparers;

resourcestring
  SBadSequenceSize = 'bad sequence size: %d';
  SX500Asn1ElementNil = 'ASN.1 encodable element cannot be nil';
  SAttrTypeNil = 'attribute type cannot be nil';
  SAttrValueNil = 'attribute value cannot be nil';
  SAttrTypeAndValueNil = 'attribute type and value cannot be nil';

type
  /// <summary>
  /// AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY DEFINED BY type }
  /// </summary>
  TAttributeTypeAndValue = class(TAsn1Encodable, IAttributeTypeAndValue)

  strict private
  var
    FAttrType: IDerObjectIdentifier;
    FValue: IAsn1Encodable;

  strict protected
    function GetAttrType: IDerObjectIdentifier;
    function GetValue: IAsn1Encodable;

  public
    class function GetInstance(AObj: TObject): IAttributeTypeAndValue; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAttributeTypeAndValue; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeTypeAndValue; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAttributeTypeAndValue; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAttributeTypeAndValue; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributeTypeAndValue; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAttrType: IDerObjectIdentifier;
      const AValue: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property Value: IAsn1Encodable read GetValue;

  end;

  /// <summary>
  /// RelativeDistinguishedName ::= SET SIZE(1..MAX) OF AttributeTypeAndValue
  /// </summary>
  TRdn = class(TAsn1Encodable, IRdn)

  strict private
  var
    FValues: IAsn1Set;

    class function ElementToAttributeTypeAndValue(AElement: IAsn1Encodable): IAttributeTypeAndValue; static;

  strict protected
    function GetIsMultiValued: Boolean;
    function GetCount: Int32;
    function GetFirst: IAttributeTypeAndValue;
    function GetTypesAndValues: TCryptoLibGenericArray<IAttributeTypeAndValue>;

  public
    class function GetInstance(AObj: TObject): IRdn; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IRdn; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRdn; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRdn; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRdn; static;

    constructor Create(const ASet: IAsn1Set); overload;
    constructor Create(const AAttrType: IDerObjectIdentifier;
      const AValue: IAsn1Encodable); overload;
    constructor Create(const AAttr: IAttributeTypeAndValue); overload;
    constructor Create(const AAttrs: array of IAttributeTypeAndValue); overload;
    constructor Create(const AAttrs: TCryptoLibGenericArray<IAttributeTypeAndValue>); overload;

    function ToAsn1Object: IAsn1Object; override;

    property IsMultiValued: Boolean read GetIsMultiValued;
    property Count: Int32 read GetCount;
    property First: IAttributeTypeAndValue read GetFirst;

  end;

  /// <summary>
  /// DirectoryString ::= CHOICE { teletexString, printableString, universalString, utf8String, bmpString }
  /// </summary>
  TDirectoryString = class(TAsn1Encodable, IDirectoryString, IAsn1Choice, IAsn1String)

  strict private
  var
    FStr: IDerStringBase;

    class function ChoiceGetOptional(AElement: IAsn1Encodable): IDirectoryString; static;
    class function ChoiceGetInstance(AElement: IAsn1Encodable): IDirectoryString; static;
    class function GetOptionalInnerObject(const AElement: IAsn1Encodable): IDerStringBase; static;

  strict protected
    function GetString: String;

  public
    class function GetInstance(AObj: TObject): IDirectoryString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDirectoryString; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDirectoryString; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDirectoryString; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IDirectoryString; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDirectoryString; static;

    constructor Create(const AStr: IDerStringBase); overload;
    constructor Create(const AStr: String); overload;

    function ToAsn1Object: IAsn1Object; override;

  end;

implementation

{ TAttributeTypeAndValue }

class function TAttributeTypeAndValue.GetInstance(AObj: TObject): IAttributeTypeAndValue;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeTypeAndValue, Result) then
    Exit;

  Result := TAttributeTypeAndValue.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeTypeAndValue.GetInstance(const AObj: IAsn1Convertible): IAttributeTypeAndValue;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeTypeAndValue, Result) then
    Exit;

  Result := TAttributeTypeAndValue.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeTypeAndValue.GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeTypeAndValue;
begin
  Result := TAttributeTypeAndValue.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttributeTypeAndValue.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAttributeTypeAndValue;
begin
  Result := TAttributeTypeAndValue.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TAttributeTypeAndValue.GetOptional(const AElement: IAsn1Encodable): IAttributeTypeAndValue;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SX500Asn1ElementNil);

  if Supports(AElement, IAttributeTypeAndValue, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TAttributeTypeAndValue.Create(LSequence)
  else
    Result := nil;
end;

class function TAttributeTypeAndValue.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributeTypeAndValue;
begin
  Result := TAttributeTypeAndValue.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttributeTypeAndValue.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  FAttrType := TAsn1Utilities.Read<IDerObjectIdentifier>(ASeq, LPos, TDerObjectIdentifier.GetInstance);
  FValue := TAsn1Utilities.ReadEncodable(ASeq, LPos);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TAttributeTypeAndValue.Create(const AAttrType: IDerObjectIdentifier;
  const AValue: IAsn1Encodable);
begin
  inherited Create();

  if AAttrType = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAttrTypeNil);
  if AValue = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAttrValueNil);

  FAttrType := AAttrType;
  FValue := AValue;
end;

function TAttributeTypeAndValue.GetAttrType: IDerObjectIdentifier;
begin
  Result := FAttrType;
end;

function TAttributeTypeAndValue.GetValue: IAsn1Encodable;
begin
  Result := FValue;
end;

function TAttributeTypeAndValue.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FAttrType, FValue]);
end;

{ TRdn }

class function TRdn.ElementToAttributeTypeAndValue(AElement: IAsn1Encodable): IAttributeTypeAndValue;
begin
  Result := TAttributeTypeAndValue.GetInstance(AElement);
end;

class function TRdn.GetInstance(AObj: TObject): IRdn;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRdn, Result) then
    Exit;

  Result := TRdn.Create(TAsn1Set.GetInstance(AObj));
end;

class function TRdn.GetInstance(const AObj: IAsn1Convertible): IRdn;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRdn, Result) then
    Exit;

  Result := TRdn.Create(TAsn1Set.GetInstance(AObj));
end;

class function TRdn.GetInstance(const AEncoded: TCryptoLibByteArray): IRdn;
begin
  Result := TRdn.Create(TAsn1Set.GetInstance(AEncoded));
end;

class function TRdn.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRdn;
begin
  Result := TRdn.Create(TAsn1Set.GetInstance(AObj, AExplicitly));
end;

class function TRdn.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRdn;
begin
  Result := TRdn.Create(TAsn1Set.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRdn.Create(const ASet: IAsn1Set);
begin
  inherited Create();
  FValues := ASet;
end;

constructor TRdn.Create(const AAttrType: IDerObjectIdentifier;
  const AValue: IAsn1Encodable);
begin
  Create(TAttributeTypeAndValue.Create(AAttrType, AValue));
end;

constructor TRdn.Create(const AAttr: IAttributeTypeAndValue);
begin
  inherited Create();

  if AAttr = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAttrTypeAndValueNil);

  FValues := TDerSet.Create(AAttr as IAsn1Encodable);
end;

constructor TRdn.Create(const AAttrs: array of IAttributeTypeAndValue);
var
  LI: Int32;
  LElements: array of IAsn1Encodable;
begin
  inherited Create();
  System.SetLength(LElements, System.Length(AAttrs));
  for LI := 0 to System.Length(AAttrs) - 1 do
    LElements[LI] := AAttrs[LI];
  FValues := TDerSet.Create(LElements);
end;

constructor TRdn.Create(const AAttrs: TCryptoLibGenericArray<IAttributeTypeAndValue>);
var
  LI: Int32;
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  inherited Create();
  System.SetLength(LElements, System.Length(AAttrs));
  for LI := 0 to System.Length(AAttrs) - 1 do
    LElements[LI] := AAttrs[LI];
  FValues := TDerSet.Create(LElements);
end;

function TRdn.GetIsMultiValued: Boolean;
begin
  Result := FValues.Count > 1;
end;

function TRdn.GetCount: Int32;
begin
  Result := FValues.Count;
end;

function TRdn.GetFirst: IAttributeTypeAndValue;
begin
  if FValues.Count = 0 then
    Result := nil
  else
    Result := TAttributeTypeAndValue.GetInstance(FValues[0]);
end;

function TRdn.GetTypesAndValues: TCryptoLibGenericArray<IAttributeTypeAndValue>;
begin
  Result := TArrayUtilities.Map<IAsn1Encodable, IAttributeTypeAndValue>(FValues.Elements,
    ElementToAttributeTypeAndValue);
end;

function TRdn.ToAsn1Object: IAsn1Object;
begin
  Result := FValues as IAsn1Object;
end;

{ TDirectoryString }

class function TDirectoryString.ChoiceGetOptional(AElement: IAsn1Encodable): IDirectoryString;
begin
  Result := GetOptional(AElement);
end;

class function TDirectoryString.ChoiceGetInstance(AElement: IAsn1Encodable): IDirectoryString;
begin
  Result := GetInstance(AElement);
end;

class function TDirectoryString.GetOptionalInnerObject(const AElement: IAsn1Encodable): IDerStringBase;
var
  LT61: IDerT61String;
  LPrintable: IDerPrintableString;
  LUniversal: IDerUniversalString;
  LUtf8: IDerUtf8String;
  LBmp: IDerBmpString;
begin
  LT61 := TDerT61String.GetOptional(AElement);
  if LT61 <> nil then
  begin
    Result := LT61;
    Exit;
  end;

  LPrintable := TDerPrintableString.GetOptional(AElement);
  if LPrintable <> nil then
  begin
    Result := LPrintable;
    Exit;
  end;

  LUniversal := TDerUniversalString.GetOptional(AElement);
  if LUniversal <> nil then
  begin
    Result := LUniversal;
    Exit;
  end;

  LUtf8 := TDerUtf8String.GetOptional(AElement);
  if LUtf8 <> nil then
  begin
    Result := LUtf8;
    Exit;
  end;

  LBmp := TDerBmpString.GetOptional(AElement);
  if LBmp <> nil then
  begin
    Result := LBmp;
    Exit;
  end;

  Result := nil;
end;

class function TDirectoryString.GetInstance(AObj: TObject): IDirectoryString;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IDirectoryString>(AObj, ChoiceGetOptional);
end;

class function TDirectoryString.GetInstance(const AObj: IAsn1Convertible): IDirectoryString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDirectoryString, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IDirectoryString>(AObj.ToAsn1Object(), ChoiceGetOptional);
end;

class function TDirectoryString.GetInstance(const AEncoded: TCryptoLibByteArray): IDirectoryString;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IDirectoryString>(AEncoded, ChoiceGetOptional);
end;

class function TDirectoryString.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDirectoryString;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IDirectoryString>(AObj, AExplicitly, ChoiceGetInstance);
end;

class function TDirectoryString.GetOptional(const AElement: IAsn1Encodable): IDirectoryString;
var
  LInner: IDerStringBase;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SX500Asn1ElementNil);

  if Supports(AElement, IDirectoryString, Result) then
    Exit;

  LInner := GetOptionalInnerObject(AElement);
  if LInner <> nil then
    Result := TDirectoryString.Create(LInner)
  else
    Result := nil;
end;

class function TDirectoryString.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDirectoryString;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IDirectoryString>(ATaggedObject, ADeclaredExplicit, ChoiceGetInstance);
end;

constructor TDirectoryString.Create(const AStr: IDerStringBase);
begin
  inherited Create();

  if AStr = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SX500Asn1ElementNil);

  FStr := AStr;
end;

constructor TDirectoryString.Create(const AStr: String);
begin
  Create(TDerUtf8String.Create(AStr) as IDerStringBase);
end;

function TDirectoryString.GetString: String;
begin
  Result := FStr.GetString();
end;

function TDirectoryString.ToAsn1Object: IAsn1Object;
begin
  Result := FStr.ToAsn1Object();
end;

end.
