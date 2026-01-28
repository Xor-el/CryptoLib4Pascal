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

unit ClpV2AttributeCertificateInfoGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for V2 AttributeCertificateInfo generator.
  /// </summary>
  IV2AttributeCertificateInfoGenerator = interface
    ['{C3D4E5F6-A7B8-9012-CDEF-012345678901}']
    procedure SetHolder(const AHolder: IHolder);
    procedure AddAttribute(const AOid: String; const AValue: IAsn1Encodable); overload;
    procedure AddAttribute(const AAttribute: IAttributeX509); overload;
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IAttCertIssuer);
    procedure SetStartDate(const AStartDate: IAsn1GeneralizedTime);
    procedure SetEndDate(const AEndDate: IAsn1GeneralizedTime);
    procedure SetIssuerUniqueID(const AIssuerUniqueID: IDerBitString);
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GenerateAttributeCertificateInfo: IAttributeCertificateInfo;
  end;

  /// <summary>
  /// Generator for Version 2 AttributeCertificateInfo.
  /// </summary>
  TV2AttributeCertificateInfoGenerator = class(TInterfacedObject, IV2AttributeCertificateInfoGenerator)
  strict private
    FVersion: IDerInteger;
    FHolder: IHolder;
    FIssuer: IAttCertIssuer;
    FSignature: IAlgorithmIdentifier;
    FSerialNumber: IDerInteger;
    FAttributes: IAsn1EncodableVector;
    FIssuerUniqueID: IDerBitString;
    FExtensions: IX509Extensions;
    FStartDate: IAsn1GeneralizedTime;
    FEndDate: IAsn1GeneralizedTime;
  public
    constructor Create;
    procedure SetHolder(const AHolder: IHolder);
    procedure AddAttribute(const AOid: String; const AValue: IAsn1Encodable); overload;
    procedure AddAttribute(const AAttribute: IAttributeX509); overload;
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IAttCertIssuer);
    procedure SetStartDate(const AStartDate: IAsn1GeneralizedTime);
    procedure SetEndDate(const AEndDate: IAsn1GeneralizedTime);
    procedure SetIssuerUniqueID(const AIssuerUniqueID: IDerBitString);
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GenerateAttributeCertificateInfo: IAttributeCertificateInfo;
  end;

implementation

{ TV2AttributeCertificateInfoGenerator }

constructor TV2AttributeCertificateInfoGenerator.Create;
begin
  inherited Create;
  FVersion := TDerInteger.One;
  FAttributes := TAsn1EncodableVector.Create;
end;

procedure TV2AttributeCertificateInfoGenerator.SetHolder(const AHolder: IHolder);
begin
  FHolder := AHolder;
end;

procedure TV2AttributeCertificateInfoGenerator.AddAttribute(const AOid: String; const AValue: IAsn1Encodable);
begin
  FAttributes.Add(TAttributeX509.Create(TDerObjectIdentifier.Create(AOid), TDerSet.Create(AValue)));
end;

procedure TV2AttributeCertificateInfoGenerator.AddAttribute(const AAttribute: IAttributeX509);
begin
  FAttributes.Add(AAttribute);
end;

procedure TV2AttributeCertificateInfoGenerator.SetSerialNumber(const ASerialNumber: IDerInteger);
begin
  FSerialNumber := ASerialNumber;
end;

procedure TV2AttributeCertificateInfoGenerator.SetSignature(const ASignature: IAlgorithmIdentifier);
begin
  FSignature := ASignature;
end;

procedure TV2AttributeCertificateInfoGenerator.SetIssuer(const AIssuer: IAttCertIssuer);
begin
  FIssuer := AIssuer;
end;

procedure TV2AttributeCertificateInfoGenerator.SetStartDate(const AStartDate: IAsn1GeneralizedTime);
begin
  FStartDate := AStartDate;
end;

procedure TV2AttributeCertificateInfoGenerator.SetEndDate(const AEndDate: IAsn1GeneralizedTime);
begin
  FEndDate := AEndDate;
end;

procedure TV2AttributeCertificateInfoGenerator.SetIssuerUniqueID(const AIssuerUniqueID: IDerBitString);
begin
  FIssuerUniqueID := AIssuerUniqueID;
end;

procedure TV2AttributeCertificateInfoGenerator.SetExtensions(const AExtensions: IX509Extensions);
begin
  FExtensions := AExtensions;
end;

function TV2AttributeCertificateInfoGenerator.GenerateAttributeCertificateInfo: IAttributeCertificateInfo;
var
  LV: IAsn1EncodableVector;
  LSeq: IAsn1Sequence;
begin
  if (FSerialNumber = nil) or (FSignature = nil) or (FIssuer = nil) or
     (FStartDate = nil) or (FEndDate = nil) or (FHolder = nil) or (FAttributes = nil) then
    raise EInvalidOperationCryptoLibException.Create('not all mandatory fields set in V2 AttributeCertificateInfo generator');

  LV := TAsn1EncodableVector.Create([FVersion, FHolder, FIssuer, FSignature, FSerialNumber]);
  LV.Add(TAttCertValidityPeriod.Create(FStartDate, FEndDate));
  LV.Add(TDerSequence.Create(FAttributes));
  LV.AddOptional(FIssuerUniqueID, FExtensions);
  LSeq := TDerSequence.Create(LV);
  Result := TAttributeCertificateInfo.GetInstance(LSeq);
end;

end.
