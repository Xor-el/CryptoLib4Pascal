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

unit ClpSecECAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpISecECAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SKeyNil = 'key';
  SOrderBitLengthTooSmall = 'must be >= key bitlength';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';

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
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  
  if (LCount < 2) or (LCount > 4) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  
  FPrivateKey := TAsn1OctetString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  
  FParameters := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Encodable>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Encodable
    begin
      Result := ATagged.GetExplicitBaseObject();
    end);
  
  FPublicKey := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBitString>(ASeq, LPos, 1, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBitString
    begin
      Result := TDerBitString.GetTagged(ATagged, AState);
    end);
  
  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
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
    raise EArgumentNilCryptoLibException.Create(SKeyNil);
  if AOrderBitLength < AKey.BitLength then
    raise EArgumentCryptoLibException.Create(SOrderBitLengthTooSmall);

  LPrivateKeyContents := TBigIntegers.AsUnsignedByteArray((AOrderBitLength + 7) div 8, AKey);

  FVersion := TDerInteger.One;
  FPrivateKey := TDerOctetString.Create(LPrivateKeyContents);
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
