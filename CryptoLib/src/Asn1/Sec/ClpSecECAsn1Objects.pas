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

unit ClpSecECAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpISecECAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SKeyNil = 'key cannot be nil';
  SOrderBitLengthTooSmall = 'order must be at least the key bit length';
  SPrivateKeyNil = 'private key cannot be nil';


type
  /// <summary>
  /// the elliptic curve private key object from SEC 1
  /// </summary>
  TECPrivateKeyStructure = class(TAsn1Encodable, IECPrivateKeyStructure)

  strict private
  var
    FVersion: IDerInteger;
    FPrivateKey: IAsn1OctetString;
    FParameters: IAsn1Encodable;
    FPublicKey: IDerBitString;

  strict protected
    function GetVersion: IDerInteger;
    function GetPrivateKey: IAsn1OctetString;
    function GetParameters: IAsn1Encodable;
    function GetPublicKey: IDerBitString;

  public
    class function GetInstance(AObj: TObject): IECPrivateKeyStructure; overload; static;
    class function GetInstance(AObj: IAsn1Convertible): IECPrivateKeyStructure; overload; static;
    class function GetInstance(AObj: TCryptoLibByteArray): IECPrivateKeyStructure; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IECPrivateKeyStructure; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IECPrivateKeyStructure; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(AOrderBitLength: Int32; const AKey: TBigInteger); overload;
    constructor Create(AOrderBitLength: Int32; const AKey: TBigInteger;
      const AParameters: IAsn1Encodable); overload;
    constructor Create(AOrderBitLength: Int32; const AKey: TBigInteger;
      const APublicKey: IDerBitString; const AParameters: IAsn1Encodable); overload;
    /// <summary>
    /// Create from explicit SEC 1 ASN.1 components (version 1).
    /// </summary>
    constructor Create(const APrivateKey: IAsn1OctetString; const AParameters: IAsn1Encodable;
      const APublicKey: IDerBitString); overload;

    function GetKey: TBigInteger;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property Parameters: IAsn1Encodable read GetParameters;
    property PublicKey: IDerBitString read GetPublicKey;

  end;

implementation

{ TECPrivateKeyStructure }

class function TECPrivateKeyStructure.GetInstance(AObj: TObject): IECPrivateKeyStructure;
var
  LInstance: IECPrivateKeyStructure;
  LAsn1Obj: IAsn1Object;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IECPrivateKeyStructure, LInstance) then
  begin
    Result := LInstance;
    Exit;
  end;

  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := TECPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(LAsn1Obj));
    Exit;
  end;

  Result := TECPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TECPrivateKeyStructure.GetInstance(AObj: IAsn1Convertible): IECPrivateKeyStructure;
begin
  Result := TECPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TECPrivateKeyStructure.GetInstance(AObj: TCryptoLibByteArray): IECPrivateKeyStructure;
begin
  Result := TECPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TECPrivateKeyStructure.GetInstance(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IECPrivateKeyStructure;
begin
  Result := TECPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(ATaggedObject, ADeclaredExplicit));
end;

class function TECPrivateKeyStructure.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IECPrivateKeyStructure;
begin
  Result := TECPrivateKeyStructure.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TECPrivateKeyStructure.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 4);
  FVersion := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FPrivateKey := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  FParameters := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Encodable>(ASeq, LPos, 0, True,
    TAsn1Utilities.GetTaggedExplicitBaseObject);
  FPublicKey := TAsn1Utilities.ReadOptionalContextTagged<IDerBitString>(ASeq, LPos, 1, True,
    TDerBitString.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TECPrivateKeyStructure.Create(AOrderBitLength: Int32; const AKey: TBigInteger);
begin
  Create(AOrderBitLength, AKey, nil);
end;

constructor TECPrivateKeyStructure.Create(AOrderBitLength: Int32; const AKey: TBigInteger;
  const AParameters: IAsn1Encodable);
begin
  Create(AOrderBitLength, AKey, nil, AParameters);
end;

constructor TECPrivateKeyStructure.Create(AOrderBitLength: Int32; const AKey: TBigInteger;
  const APublicKey: IDerBitString; const AParameters: IAsn1Encodable);
var
  LPrivateKeyContents: TCryptoLibByteArray;
begin
  inherited Create();
  
  if not AKey.IsInitialized then
    raise EArgumentNilCryptoLibException.CreateRes(@SKeyNil);
  if AOrderBitLength < AKey.BitLength then
    raise EArgumentCryptoLibException.CreateRes(@SOrderBitLengthTooSmall);

  LPrivateKeyContents := TBigIntegerUtilities.AsUnsignedByteArray((AOrderBitLength + 7) div 8, AKey);

  FVersion := TDerInteger.One;
  FPrivateKey := TDerOctetString.Create(LPrivateKeyContents);
  FParameters := AParameters;
  FPublicKey := APublicKey;
end;

constructor TECPrivateKeyStructure.Create(const APrivateKey: IAsn1OctetString;
  const AParameters: IAsn1Encodable; const APublicKey: IDerBitString);
begin
  inherited Create();

  if APrivateKey = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPrivateKeyNil);

  FVersion := TDerInteger.One;
  FPrivateKey := APrivateKey;
  FParameters := AParameters;
  FPublicKey := APublicKey;
end;

function TECPrivateKeyStructure.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TECPrivateKeyStructure.GetPrivateKey: IAsn1OctetString;
begin
  Result := FPrivateKey;
end;

function TECPrivateKeyStructure.GetParameters: IAsn1Encodable;
begin
  Result := FParameters;
end;

function TECPrivateKeyStructure.GetPublicKey: IDerBitString;
begin
  Result := FPublicKey;
end;

function TECPrivateKeyStructure.GetKey: TBigInteger;
begin
  Result := TBigInteger.Create(1, FPrivateKey.GetOctets());
end;

function TECPrivateKeyStructure.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.Add(FVersion);
  LV.Add(FPrivateKey);
  LV.AddOptionalTagged(True, 0, FParameters);
  LV.AddOptionalTagged(True, 1, FPublicKey);
  Result := TDerSequence.Create(LV);
end;

end.
