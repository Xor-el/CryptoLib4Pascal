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

unit ClpX509Asn1Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Extension,
  ClpX509Extension,
  ClpCryptoLibTypes,
  ClpAsn1Comparers,
  ClpIX509Asn1Generators;

type
  /// <summary>
  /// Generator for Version 1 TbsCertificateStructures.
  /// </summary>
  TV1TbsCertificateGenerator = class(TInterfacedObject, IV1TbsCertificateGenerator)
  strict private
    FSerialNumber: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FValidity: IValidity;
    FStartDate: ITime;
    FEndDate: ITime;
    FSubject: IX509Name;
    FSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
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

  /// <summary>
  /// Generator for Version 2 TbsCertList structures.
  /// </summary>
  TV2TbsCertListGenerator = class(TInterfacedObject, IV2TbsCertListGenerator)
  strict private
    FVersion: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FThisUpdate: ITime;
    FNextUpdate: ITime;
    FExtensions: IAsn1Encodable;
    FCrlEntries: TList<IAsn1Sequence>;

    function GenerateTbsCertificateStructure: IAsn1Sequence;
  public
    constructor Create;
    destructor Destroy; override;

    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetThisUpdate(const AThisUpdate: IAsn1UtcTime); overload;
    procedure SetThisUpdate(const AThisUpdate: ITime); overload;
    procedure SetNextUpdate(const ANextUpdate: IAsn1UtcTime); overload;
    procedure SetNextUpdate(const ANextUpdate: ITime); overload;
    procedure AddCrlEntry(const ACrlEntry: IAsn1Sequence); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: IAsn1UtcTime; AReason: Int32); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: ITime; AReason: Int32); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: ITime; AReason: Int32;
      const AInvalidityDate: IAsn1GeneralizedTime); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: ITime;
      const AExtensions: IX509Extensions); overload;
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GeneratePreTbsCertList: IAsn1Sequence;
    function GenerateTbsCertList: ITbsCertificateList;
  end;

  /// <remarks>Generator for X.509 extensions</remarks>
  TX509ExtensionsGenerator = class(TInterfacedObject, IX509ExtensionsGenerator)

  strict private
  var
    FExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>;
    FOrdering: TList<IDerObjectIdentifier>;

  strict private
    class var
      FDupsAllowed: TDictionary<IDerObjectIdentifier, Boolean>;

    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  strict private
    procedure ImplAddExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension);
    procedure ImplAddExtensionDup(const AExistingExtension: IX509Extension;
      const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray);

  public
    constructor Create;
    destructor Destroy; override;

    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    procedure AddExtensions(const AExtensions: IX509Extensions);
    function Generate: IX509Extensions;
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
    function HasExtension(const AOid: IDerObjectIdentifier): Boolean;
    function IsEmpty: Boolean;
    procedure RemoveExtension(const AOid: IDerObjectIdentifier);
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    procedure Reset;

  end;

implementation

{ TV1TbsCertificateGenerator }

procedure TV1TbsCertificateGenerator.SetSerialNumber(const ASerialNumber: IDerInteger);
begin
  FSerialNumber := ASerialNumber;
end;

procedure TV1TbsCertificateGenerator.SetSignature(const ASignature: IAlgorithmIdentifier);
begin
  FSignature := ASignature;
end;

procedure TV1TbsCertificateGenerator.SetIssuer(const AIssuer: IX509Name);
begin
  FIssuer := AIssuer;
end;

procedure TV1TbsCertificateGenerator.SetValidity(const AValidity: IValidity);
begin
  FValidity := AValidity;
  FStartDate := nil;
  FEndDate := nil;
end;

procedure TV1TbsCertificateGenerator.SetStartDate(const AStartDate: ITime);
begin
  FValidity := nil;
  FStartDate := AStartDate;
end;

procedure TV1TbsCertificateGenerator.SetStartDate(const AStartDate: IAsn1UtcTime);
begin
  SetStartDate(TTime.Create(AStartDate));
end;

procedure TV1TbsCertificateGenerator.SetEndDate(const AEndDate: ITime);
begin
  FValidity := nil;
  FEndDate := AEndDate;
end;

procedure TV1TbsCertificateGenerator.SetEndDate(const AEndDate: IAsn1UtcTime);
begin
  SetEndDate(TTime.Create(AEndDate));
end;

procedure TV1TbsCertificateGenerator.SetSubject(const ASubject: IX509Name);
begin
  FSubject := ASubject;
end;

procedure TV1TbsCertificateGenerator.SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
begin
  FSubjectPublicKeyInfo := APubKeyInfo;
end;

function TV1TbsCertificateGenerator.GenerateTbsCertificate: ITbsCertificateStructure;
var
  LValidity: IValidity;
begin
  if (FSerialNumber = nil) or (FSignature = nil) or (FIssuer = nil) or
     ((FValidity = nil) and ((FStartDate = nil) or (FEndDate = nil))) or
     (FSubject = nil) or (FSubjectPublicKeyInfo = nil) then
    raise EInvalidOperationCryptoLibException.Create('not all mandatory fields set in V1 TBScertificate generator');

  if FValidity <> nil then
    LValidity := FValidity
  else
    LValidity := TValidity.Create(FStartDate, FEndDate);

  Result := TTbsCertificateStructure.Create(TDerInteger.Zero, FSerialNumber,
    FSignature, FIssuer, LValidity, FSubject, FSubjectPublicKeyInfo, nil, nil, nil);
end;

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

{ TV2TbsCertListGenerator }

constructor TV2TbsCertListGenerator.Create;
begin
  inherited Create;
  FVersion := TDerInteger.One;
  FCrlEntries := TList<IAsn1Sequence>.Create;
end;

destructor TV2TbsCertListGenerator.Destroy;
begin
  FCrlEntries.Free;
  inherited Destroy;
end;

procedure TV2TbsCertListGenerator.SetSignature(const ASignature: IAlgorithmIdentifier);
begin
  FSignature := ASignature;
end;

procedure TV2TbsCertListGenerator.SetIssuer(const AIssuer: IX509Name);
begin
  FIssuer := AIssuer;
end;

procedure TV2TbsCertListGenerator.SetThisUpdate(const AThisUpdate: IAsn1UtcTime);
begin
  FThisUpdate := TTime.Create(AThisUpdate);
end;

procedure TV2TbsCertListGenerator.SetThisUpdate(const AThisUpdate: ITime);
begin
  FThisUpdate := AThisUpdate;
end;

procedure TV2TbsCertListGenerator.SetNextUpdate(const ANextUpdate: IAsn1UtcTime);
begin
  if ANextUpdate <> nil then
    FNextUpdate := TTime.Create(ANextUpdate)
  else
    FNextUpdate := nil;
end;

procedure TV2TbsCertListGenerator.SetNextUpdate(const ANextUpdate: ITime);
begin
  FNextUpdate := ANextUpdate;
end;

procedure TV2TbsCertListGenerator.AddCrlEntry(const ACrlEntry: IAsn1Sequence);
begin
  FCrlEntries.Add(ACrlEntry);
end;

procedure TV2TbsCertListGenerator.AddCrlEntry(const AUserCertificate: IDerInteger;
  const ARevocationDate: IAsn1UtcTime; AReason: Int32);
begin
  AddCrlEntry(AUserCertificate, TTime.Create(ARevocationDate) as ITime, AReason);
end;

procedure TV2TbsCertListGenerator.AddCrlEntry(const AUserCertificate: IDerInteger;
  const ARevocationDate: ITime; AReason: Int32);
begin
  AddCrlEntry(AUserCertificate, ARevocationDate, AReason, nil);
end;

procedure TV2TbsCertListGenerator.AddCrlEntry(const AUserCertificate: IDerInteger;
  const ARevocationDate: ITime; AReason: Int32; const AInvalidityDate: IAsn1GeneralizedTime);
var
  LExtOids: TList<IDerObjectIdentifier>;
  LExtValues: TList<IX509Extension>;
  LCrlReason: ICrlReason;
  LExtensions: IX509Extensions;
begin
  LExtOids := TList<IDerObjectIdentifier>.Create;
  try
    LExtValues := TList<IX509Extension>.Create;
    try
      if AReason <> 0 then
      begin
        LCrlReason := TCrlReason.Create(AReason);
        LExtOids.Add(TX509Extensions.ReasonCode);
        LExtValues.Add(TX509Extension.Create(False, TDerOctetString.Create(LCrlReason.GetEncoded(TAsn1Encodable.Der))) as IX509Extension);
      end;

      if AInvalidityDate <> nil then
      begin
        LExtOids.Add(TX509Extensions.InvalidityDate);
        LExtValues.Add(TX509Extension.Create(False, TDerOctetString.Create(AInvalidityDate.GetEncoded(TAsn1Encodable.Der))) as IX509Extension);
      end;

      if LExtOids.Count >= 1 then
        LExtensions := TX509Extensions.Create(LExtOids, LExtValues)
      else
        LExtensions := nil;

      AddCrlEntry(AUserCertificate, ARevocationDate, LExtensions);
    finally
      LExtValues.Free;
    end;
  finally
    LExtOids.Free;
  end;
end;

procedure TV2TbsCertListGenerator.AddCrlEntry(const AUserCertificate: IDerInteger;
  const ARevocationDate: ITime; const AExtensions: IX509Extensions);
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create([AUserCertificate, ARevocationDate]);
  LV.AddOptional(AExtensions);
  AddCrlEntry(TDerSequence.Create(LV));
end;

procedure TV2TbsCertListGenerator.SetExtensions(const AExtensions: IX509Extensions);
begin
  FExtensions := AExtensions;
end;

function TV2TbsCertListGenerator.GeneratePreTbsCertList: IAsn1Sequence;
begin
  if FSignature <> nil then
    raise EInvalidOperationCryptoLibException.Create('signature should not be set in PreTBSCertList generator');

  if (FIssuer = nil) or (FThisUpdate = nil) then
    raise EInvalidOperationCryptoLibException.Create('Not all mandatory fields set in V2 PreTBSCertList generator');

  Result := GenerateTbsCertificateStructure;
end;

function TV2TbsCertListGenerator.GenerateTbsCertList: ITbsCertificateList;
begin
  if (FSignature = nil) or (FIssuer = nil) or (FThisUpdate = nil) then
    raise EInvalidOperationCryptoLibException.Create('Not all mandatory fields set in V2 TbsCertList generator.');

  Result := TTbsCertificateList.GetInstance(GenerateTbsCertificateStructure);
end;

function TV2TbsCertListGenerator.GenerateTbsCertificateStructure: IAsn1Sequence;
var
  LV: IAsn1EncodableVector;
  LCrlEntriesArray: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  LV := TAsn1EncodableVector.Create(7);
  LV.Add(FVersion);
  LV.AddOptional(FSignature);
  LV.Add(FIssuer);
  LV.Add(FThisUpdate);
  LV.AddOptional(FNextUpdate);

  if (FCrlEntries <> nil) and (FCrlEntries.Count > 0) then
  begin
    SetLength(LCrlEntriesArray, FCrlEntries.Count);
    for I := 0 to FCrlEntries.Count - 1 do
      LCrlEntriesArray[I] := FCrlEntries[I];
    LV.Add(TDerSequence.Create(LCrlEntriesArray));
  end;

  LV.AddOptionalTagged(True, 0, FExtensions);
  Result := TDerSequence.Create(LV);
end;

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

{ TX509ExtensionsGenerator }

class constructor TX509ExtensionsGenerator.Create;
begin
  Boot;
end;

class destructor TX509ExtensionsGenerator.Destroy;
begin
  FDupsAllowed.Free;
end;

class procedure TX509ExtensionsGenerator.Boot;
begin
  FDupsAllowed := TDictionary<IDerObjectIdentifier, Boolean>.Create(TAsn1Comparers.OidEqualityComparer);
  // OIDs that allow duplicate extensions
  FDupsAllowed.Add(TX509Extensions.SubjectAlternativeName, True);
  FDupsAllowed.Add(TX509Extensions.IssuerAlternativeName, True);
  FDupsAllowed.Add(TX509Extensions.SubjectDirectoryAttributes, True);
  FDupsAllowed.Add(TX509Extensions.CertificateIssuer, True);
end;

constructor TX509ExtensionsGenerator.Create;
begin
  inherited Create();
  FExtensions := TDictionary<IDerObjectIdentifier, IX509Extension>.Create(TAsn1Comparers.OidEqualityComparer);
  FOrdering := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
end;

destructor TX509ExtensionsGenerator.Destroy;
begin
  FExtensions.Free;
  FOrdering.Free;
  inherited Destroy;
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Convertible);
begin
  AddExtension(AOid, ACritical, AExtValue.ToAsn1Object());
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Encodable);
var
  LExisting: IX509Extension;
begin
  if FExtensions.TryGetValue(AOid, LExisting) then
  begin
    ImplAddExtensionDup(LExisting, AOid, ACritical, AExtValue.GetEncoded(TAsn1Encodable.Der));
  end
  else
  begin
    ImplAddExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.Create(AExtValue)));
  end;
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
var
  LExisting: IX509Extension;
begin
  if FExtensions.TryGetValue(AOid, LExisting) then
  begin
    ImplAddExtensionDup(LExisting, AOid, ACritical, AExtValue);
  end
  else
  begin
    ImplAddExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.FromContents(AExtValue)));
  end;
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  if HasExtension(AOid) then
    raise EArgumentCryptoLibException.CreateFmt('extension %s already added', [AOid.Id]);
  ImplAddExtension(AOid, AX509Extension);
end;

procedure TX509ExtensionsGenerator.AddExtensions(const AExtensions: IX509Extensions);
var
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
begin
  for LOid in AExtensions.GetExtensionOids() do
  begin
    LExt := AExtensions.GetExtension(LOid);
    AddExtension(LOid, LExt.IsCritical, LExt.Value.GetOctets());
  end;
end;

function TX509ExtensionsGenerator.Generate: IX509Extensions;
begin
  Result := TX509Extensions.Create(FOrdering, FExtensions);
end;

function TX509ExtensionsGenerator.GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
begin
  if not FExtensions.TryGetValue(AOid, Result) then
    Result := nil;
end;

function TX509ExtensionsGenerator.HasExtension(const AOid: IDerObjectIdentifier): Boolean;
begin
  Result := FExtensions.ContainsKey(AOid);
end;

function TX509ExtensionsGenerator.IsEmpty: Boolean;
begin
  Result := FOrdering.Count < 1;
end;

procedure TX509ExtensionsGenerator.RemoveExtension(const AOid: IDerObjectIdentifier);
begin
  if not HasExtension(AOid) then
    raise EInvalidOperationCryptoLibException.CreateFmt('extension %s not present', [AOid.Id]);
  FOrdering.Remove(AOid);
  FExtensions.Remove(AOid);
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Convertible);
begin
  ReplaceExtension(AOid, ACritical, AExtValue.ToAsn1Object());
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Encodable);
begin
  ReplaceExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.Create(AExtValue)));
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
begin
  ReplaceExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.FromContents(AExtValue)));
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  if not HasExtension(AOid) then
    raise EInvalidOperationCryptoLibException.CreateFmt('extension %s not present', [AOid.Id]);
  FExtensions[AOid] := AX509Extension;
end;

procedure TX509ExtensionsGenerator.Reset;
begin
  FExtensions.Clear;
  FOrdering.Clear;
end;

procedure TX509ExtensionsGenerator.ImplAddExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  FOrdering.Add(AOid);
  FExtensions.Add(AOid, AX509Extension);
end;

procedure TX509ExtensionsGenerator.ImplAddExtensionDup(const AExistingExtension: IX509Extension;
  const AOid: IDerObjectIdentifier; ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
var
  LSeq1, LSeq2, LConcat: IAsn1Sequence;
begin
  if not FDupsAllowed.ContainsKey(AOid) then
    raise EArgumentCryptoLibException.CreateFmt('extension %s already added', [AOid.Id]);

  LSeq1 := TAsn1Sequence.GetInstance(AExistingExtension.Value.GetOctets());
  LSeq2 := TAsn1Sequence.GetInstance(AExtValue);
  LConcat := TDerSequence.Concatenate([LSeq1, LSeq2]);

  FExtensions[AOid] := TX509Extension.Create(AExistingExtension.IsCritical or ACritical,
    TDerOctetString.Create(LConcat));
end;

end.
