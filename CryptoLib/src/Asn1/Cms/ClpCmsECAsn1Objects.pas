{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCmsECAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpAsn1Utilities,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpICmsECAsn1Objects,
  ClpCryptoLibTypes;

resourcestring
  SEccCmsBadSequenceSize = 'Bad sequence size: %d';
  SEccCmsUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SEccCmsKeyInfoNil = 'KeyInfo cannot be Nil';
  SEccCmsSuppPubInfoNil = 'SuppPubInfo cannot be Nil';

type
  /// <summary>
  /// ECC-CMS-SharedInfo structure (RFC 5753 / CMS ECC).
  /// </summary>
  TEccCmsSharedInfo = class(TAsn1Encodable, IEccCmsSharedInfo)

  strict private
  var
    FKeyInfo: IAlgorithmIdentifier;
    FEntityUInfo: IAsn1OctetString;
    FSuppPubInfo: IAsn1OctetString;

    class function GetTaggedAsn1OctetString(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1OctetString; static;

  strict protected
    function GetKeyInfo: IAlgorithmIdentifier;
    function GetEntityUInfo: IAsn1OctetString;
    function GetSuppPubInfo: IAsn1OctetString;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IEccCmsSharedInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IEccCmsSharedInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IEccCmsSharedInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IEccCmsSharedInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IEccCmsSharedInfo; static;

    constructor Create(const AKeyInfo: IAlgorithmIdentifier; const ASuppPubInfo: IAsn1OctetString); overload;
    constructor Create(const AKeyInfo: IAlgorithmIdentifier; const AEntityUInfo: IAsn1OctetString;
      const ASuppPubInfo: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property KeyInfo: IAlgorithmIdentifier read GetKeyInfo;
    property EntityUInfo: IAsn1OctetString read GetEntityUInfo;
    property SuppPubInfo: IAsn1OctetString read GetSuppPubInfo;

  end;

implementation

{ TEccCmsSharedInfo }

class function TEccCmsSharedInfo.GetInstance(AObj: TObject): IEccCmsSharedInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IEccCmsSharedInfo, Result) then
    Exit;

  Result := TEccCmsSharedInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TEccCmsSharedInfo.GetInstance(const AObj: IAsn1Convertible): IEccCmsSharedInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IEccCmsSharedInfo, Result) then
    Exit;

  Result := TEccCmsSharedInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TEccCmsSharedInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IEccCmsSharedInfo;
begin
  Result := TEccCmsSharedInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TEccCmsSharedInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IEccCmsSharedInfo;
begin
  Result := TEccCmsSharedInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TEccCmsSharedInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IEccCmsSharedInfo;
begin
  Result := TEccCmsSharedInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TEccCmsSharedInfo.GetTaggedAsn1OctetString(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1OctetString;
begin
  Result := TAsn1OctetString.GetTagged(ATagged, AState);
end;

constructor TEccCmsSharedInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SEccCmsBadSequenceSize, [LCount]);

  FKeyInfo := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FEntityUInfo := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1OctetString>(ASeq, LPos, 0, True,
    GetTaggedAsn1OctetString);

  FSuppPubInfo := TAsn1Utilities.ReadContextTagged<Boolean, IAsn1OctetString>(ASeq, LPos, 2, True,
    GetTaggedAsn1OctetString);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SEccCmsUnexpectedElementsInSequence);
end;

constructor TEccCmsSharedInfo.Create(const AKeyInfo: IAlgorithmIdentifier; const ASuppPubInfo: IAsn1OctetString);
begin
  Create(AKeyInfo, nil, ASuppPubInfo);
end;

constructor TEccCmsSharedInfo.Create(const AKeyInfo: IAlgorithmIdentifier; const AEntityUInfo: IAsn1OctetString;
  const ASuppPubInfo: IAsn1OctetString);
begin
  inherited Create();

  if AKeyInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SEccCmsKeyInfoNil);

  if ASuppPubInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SEccCmsSuppPubInfoNil);

  FKeyInfo := AKeyInfo;
  FEntityUInfo := AEntityUInfo;
  FSuppPubInfo := ASuppPubInfo;
end;

function TEccCmsSharedInfo.GetKeyInfo: IAlgorithmIdentifier;
begin
  Result := FKeyInfo;
end;

function TEccCmsSharedInfo.GetEntityUInfo: IAsn1OctetString;
begin
  Result := FEntityUInfo;
end;

function TEccCmsSharedInfo.GetSuppPubInfo: IAsn1OctetString;
begin
  Result := FSuppPubInfo;
end;

function TEccCmsSharedInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.Add(FKeyInfo);
  LV.AddOptionalTagged(True, 0, FEntityUInfo);
  LV.AddTagged(True, 2, FSuppPubInfo);
  Result := TDerSequence.Create(LV);
end;

end.
