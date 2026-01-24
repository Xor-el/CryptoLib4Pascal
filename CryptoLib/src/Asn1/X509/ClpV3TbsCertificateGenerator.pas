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

unit ClpV3TbsCertificateGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for V3 TbsCertificate structure generator.
  /// </summary>
  IV3TbsCertificateGenerator = interface
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetStartDate(const AStartDate: ITime); overload;
    procedure SetStartDate(const AStartDate: IAsn1UtcTime); overload;
    procedure SetEndDate(const AEndDate: ITime); overload;
    procedure SetEndDate(const AEndDate: IAsn1UtcTime); overload;
    procedure SetSubject(const ASubject: IX509Name);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    procedure SetIssuerUniqueID(const AUniqueID: IDerBitString);
    procedure SetSubjectUniqueID(const AUniqueID: IDerBitString);
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GeneratePreTbsCertificate: IAsn1Sequence;
    function GenerateTbsCertificate: ITbsCertificateStructure;
  end;

  /// <summary>
  /// Generator for Version 3 TbsCertificateStructures.
  /// </summary>
  TV3TbsCertificateGenerator = class(TInterfacedObject, IV3TbsCertificateGenerator)
  strict private
    FSerialNumber: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FValidity: IValidity;
    FStartDate: ITime;
    FEndDate: ITime;
    FSubject: IX509Name;
    FSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    FExtensions: IX509Extensions;
    FIssuerUniqueID: IDerBitString;
    FSubjectUniqueID: IDerBitString;
    FAltNamePresentAndCritical: Boolean;
  public
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetStartDate(const AStartDate: ITime); overload;
    procedure SetStartDate(const AStartDate: IAsn1UtcTime); overload;
    procedure SetEndDate(const AEndDate: ITime); overload;
    procedure SetEndDate(const AEndDate: IAsn1UtcTime); overload;
    procedure SetSubject(const ASubject: IX509Name);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    procedure SetIssuerUniqueID(const AUniqueID: IDerBitString);
    procedure SetSubjectUniqueID(const AUniqueID: IDerBitString);
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GeneratePreTbsCertificate: IAsn1Sequence;
    function GenerateTbsCertificate: ITbsCertificateStructure;
  end;

implementation

{ TV3TbsCertificateGenerator }

procedure TV3TbsCertificateGenerator.SetSerialNumber(const ASerialNumber: IDerInteger);
begin
  FSerialNumber := ASerialNumber;
end;

procedure TV3TbsCertificateGenerator.SetSignature(const ASignature: IAlgorithmIdentifier);
begin
  FSignature := ASignature;
end;

procedure TV3TbsCertificateGenerator.SetIssuer(const AIssuer: IX509Name);
begin
  FIssuer := AIssuer;
end;

procedure TV3TbsCertificateGenerator.SetValidity(const AValidity: IValidity);
begin
  FValidity := AValidity;
  FStartDate := nil;
  FEndDate := nil;
end;

procedure TV3TbsCertificateGenerator.SetStartDate(const AStartDate: ITime);
begin
  FValidity := nil;
  FStartDate := AStartDate;
end;

procedure TV3TbsCertificateGenerator.SetStartDate(const AStartDate: IAsn1UtcTime);
begin
  SetStartDate(TTime.Create(AStartDate));
end;

procedure TV3TbsCertificateGenerator.SetEndDate(const AEndDate: ITime);
begin
  FValidity := nil;
  FEndDate := AEndDate;
end;

procedure TV3TbsCertificateGenerator.SetEndDate(const AEndDate: IAsn1UtcTime);
begin
  SetEndDate(TTime.Create(AEndDate));
end;

procedure TV3TbsCertificateGenerator.SetSubject(const ASubject: IX509Name);
begin
  FSubject := ASubject;
end;

procedure TV3TbsCertificateGenerator.SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
begin
  FSubjectPublicKeyInfo := APubKeyInfo;
end;

procedure TV3TbsCertificateGenerator.SetIssuerUniqueID(const AUniqueID: IDerBitString);
begin
  FIssuerUniqueID := AUniqueID;
end;

procedure TV3TbsCertificateGenerator.SetSubjectUniqueID(const AUniqueID: IDerBitString);
begin
  FSubjectUniqueID := AUniqueID;
end;

procedure TV3TbsCertificateGenerator.SetExtensions(const AExtensions: IX509Extensions);
var
  LAltName: IX509Extension;
begin
  FExtensions := AExtensions;
  FAltNamePresentAndCritical := False;
  if AExtensions <> nil then
  begin
    LAltName := AExtensions.GetExtension(TX509Extensions.SubjectAlternativeName);
    if (LAltName <> nil) and LAltName.IsCritical then
      FAltNamePresentAndCritical := True;
  end;
end;

function TV3TbsCertificateGenerator.GeneratePreTbsCertificate: IAsn1Sequence;
var
  LV: IAsn1EncodableVector;
  LValidity: IValidity;
  LSubject: IX509Name;
begin
  if FSignature <> nil then
    raise EInvalidOperationCryptoLibException.Create('signature field should not be set in PreTBSCertificate');

  if (FSerialNumber = nil) or (FIssuer = nil) or
     ((FValidity = nil) and ((FStartDate = nil) or (FEndDate = nil))) or
     ((FSubject = nil) and (not FAltNamePresentAndCritical)) or (FSubjectPublicKeyInfo = nil) then
    raise EInvalidOperationCryptoLibException.Create('not all mandatory fields set in V3 TBScertificate generator');

  if FValidity <> nil then
    LValidity := FValidity
  else
    LValidity := TValidity.Create(FStartDate, FEndDate);

  if FSubject <> nil then
    LSubject := FSubject
  else
    LSubject := TX509Name.GetInstance(TDerSequence.Empty as IAsn1Convertible);

  LV := TAsn1EncodableVector.Create(9);
  LV.Add(TDerTaggedObject.Create(0, TDerInteger.Two));
  LV.Add(FSerialNumber);
  LV.Add(FIssuer);
  LV.Add(LValidity);
  LV.Add(LSubject);
  LV.Add(FSubjectPublicKeyInfo);
  LV.AddOptionalTagged(False, 1, FIssuerUniqueID);
  LV.AddOptionalTagged(False, 2, FSubjectUniqueID);
  LV.AddOptionalTagged(True, 3, FExtensions);
  Result := TDerSequence.Create(LV);
end;

function TV3TbsCertificateGenerator.GenerateTbsCertificate: ITbsCertificateStructure;
var
  LValidity: IValidity;
  LSubject: IX509Name;
begin
  if (FSerialNumber = nil) or (FSignature = nil) or (FIssuer = nil) or
     ((FValidity = nil) and ((FStartDate = nil) or (FEndDate = nil))) or
     ((FSubject = nil) and (not FAltNamePresentAndCritical)) or (FSubjectPublicKeyInfo = nil) then
    raise EInvalidOperationCryptoLibException.Create('not all mandatory fields set in V3 TBScertificate generator');

  if FValidity <> nil then
    LValidity := FValidity
  else
    LValidity := TValidity.Create(FStartDate, FEndDate);

  if FSubject <> nil then
    LSubject := FSubject
  else
    LSubject := TX509Name.GetInstance(TDerSequence.Empty as IAsn1Convertible);

  Result := TTbsCertificateStructure.Create(TDerInteger.Two, FSerialNumber,
    FSignature, FIssuer, LValidity, LSubject, FSubjectPublicKeyInfo,
    FIssuerUniqueID, FSubjectUniqueID, FExtensions);
end;

end.
