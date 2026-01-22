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

unit ClpX509ExtensionUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpOiwObjectIdentifiers,
  ClpDigestUtilities,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpArrayUtils;

type
  /// <summary>
  /// Utility class for X509 extension operations.
  /// </summary>
  TX509ExtensionUtilities = class sealed(TObject)

  strict private
    class function CalculateSha1(const AData: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    class function CalculateSha1(const ASpki: ISubjectPublicKeyInfo): TCryptoLibByteArray; overload; static;
    class function CalculateKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): IAsn1OctetString; overload; static;
    class function CalculateKeyIdentifier(const ACertificate: IX509CertificateStructure): IAsn1OctetString; overload; static;
    class function DeriveAuthCertKeyID(const AAuthorityCert: IX509CertificateStructure): IAsn1OctetString; static;

  public
    /// <summary>
    /// Create AuthorityKeyIdentifier from SubjectPublicKeyInfo.
    /// </summary>
    class function CreateAuthorityKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): IAuthorityKeyIdentifier; overload; static;
    /// <summary>
    /// Create AuthorityKeyIdentifier from SubjectPublicKeyInfo with issuer and serial number.
    /// </summary>
    class function CreateAuthorityKeyIdentifier(const ASpki: ISubjectPublicKeyInfo;
      const AIssuer: IGeneralNames; const ASerialNumber: IDerInteger): IAuthorityKeyIdentifier; overload; static;
    /// <summary>
    /// Create AuthorityKeyIdentifier from certificate.
    /// </summary>
    class function CreateAuthorityKeyIdentifier(const ACertificate: IX509CertificateStructure): IAuthorityKeyIdentifier; overload; static;
    /// <summary>
    /// Create SubjectKeyIdentifier from SubjectPublicKeyInfo.
    /// </summary>
    class function CreateSubjectKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): ISubjectKeyIdentifier; static;
    /// <summary>
    /// Create truncated SubjectKeyIdentifier from SubjectPublicKeyInfo.
    /// </summary>
    class function CreateTruncatedSubjectKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): ISubjectKeyIdentifier; static;
    /// <summary>
    /// Get AuthorityKeyIdentifier from extensions.
    /// </summary>
    class function GetAuthorityKeyIdentifier(const AExtensions: IX509Extensions): IAuthorityKeyIdentifier; static;
    /// <summary>
    /// Get SubjectKeyIdentifier from extensions.
    /// </summary>
    class function GetSubjectKeyIdentifier(const AExtensions: IX509Extensions): ISubjectKeyIdentifier; static;
    /// <summary>
    /// Parse extension value to ASN.1 object.
    /// </summary>
    class function FromExtensionValue(const AExtensionValue: IAsn1OctetString): IAsn1Object; overload; static;
    /// <summary>
    /// Extract the value of the given extension, if it exists.
    /// </summary>
    class function FromExtensionValue(const AExtensions: IX509Extensions;
      const AOid: IDerObjectIdentifier): IAsn1Object; overload; static;
    /// <summary>
    /// Get extension value and parse it using the provided constructor function.
    /// </summary>
    class function GetExtension<TExtension>(const AExtensions: IX509Extensions;
      const AOid: IDerObjectIdentifier;
      const AConstructor: TFunc<TCryptoLibByteArray, TExtension>): TExtension; static;

  end;

implementation

{ TX509ExtensionUtilities }

class function TX509ExtensionUtilities.CalculateSha1(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest(TOiwObjectIdentifiers.IdSha1.id, AData);
end;

class function TX509ExtensionUtilities.CalculateSha1(const ASpki: ISubjectPublicKeyInfo): TCryptoLibByteArray;
var
  LPublicKey: IDerBitString;
  LBytes: TCryptoLibByteArray;
begin
  LPublicKey := ASpki.PublicKey;
  if LPublicKey.IsOctetAligned() then
  begin
    LBytes := LPublicKey.GetOctets();
  end
  else
  begin
    LBytes := LPublicKey.GetBytes();
  end;
  Result := CalculateSha1(LBytes);
end;

class function TX509ExtensionUtilities.CalculateKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): IAsn1OctetString;
begin
  Result := TDerOctetString.Create(CalculateSha1(ASpki));
end;

class function TX509ExtensionUtilities.CalculateKeyIdentifier(const ACertificate: IX509CertificateStructure): IAsn1OctetString;
begin
  Result := CalculateKeyIdentifier(ACertificate.SubjectPublicKeyInfo);
end;

class function TX509ExtensionUtilities.DeriveAuthCertKeyID(const AAuthorityCert: IX509CertificateStructure): IAsn1OctetString;
var
  LSubjectKeyIdentifier: ISubjectKeyIdentifier;
  LExtensions: IX509Extensions;
begin
  LExtensions := AAuthorityCert.Extensions;
  if LExtensions <> nil then
  begin
    LSubjectKeyIdentifier := GetSubjectKeyIdentifier(LExtensions);
    if LSubjectKeyIdentifier <> nil then
    begin
      Result := TDerOctetString.WithContents(LSubjectKeyIdentifier.GetKeyIdentifier());
      Exit;
    end;
  end;
  Result := CalculateKeyIdentifier(AAuthorityCert);
end;

class function TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): IAuthorityKeyIdentifier;
begin
  Result := TAuthorityKeyIdentifier.Create(CalculateKeyIdentifier(ASpki));
end;

class function TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(const ASpki: ISubjectPublicKeyInfo;
  const AIssuer: IGeneralNames; const ASerialNumber: IDerInteger): IAuthorityKeyIdentifier;
begin
  Result := TAuthorityKeyIdentifier.Create(CalculateKeyIdentifier(ASpki), AIssuer, ASerialNumber);
end;

class function TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(const ACertificate: IX509CertificateStructure): IAuthorityKeyIdentifier;
var
  LKeyIdentifier: IAsn1OctetString;
  LAuthorityCertIssuer: IGeneralNames;
  LAuthorityCertSerialNumber: IDerInteger;
begin
  LKeyIdentifier := DeriveAuthCertKeyID(ACertificate);
  LAuthorityCertIssuer := TGeneralNames.Create(TGeneralName.Create(ACertificate.Issuer));
  LAuthorityCertSerialNumber := ACertificate.SerialNumber;
  Result := TAuthorityKeyIdentifier.Create(LKeyIdentifier, LAuthorityCertIssuer, LAuthorityCertSerialNumber);
end;

class function TX509ExtensionUtilities.CreateSubjectKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): ISubjectKeyIdentifier;
begin
  Result := TSubjectKeyIdentifier.Create(CalculateKeyIdentifier(ASpki).GetOctets());
end;

class function TX509ExtensionUtilities.CreateTruncatedSubjectKeyIdentifier(const ASpki: ISubjectPublicKeyInfo): ISubjectKeyIdentifier;
var
  LSha1: TCryptoLibByteArray;
  LId: TCryptoLibByteArray;
begin
  LSha1 := CalculateSha1(ASpki);
  LId := TArrayUtils.CopyOfRange(LSha1, System.Length(LSha1) - 8, System.Length(LSha1));
  LId[0] := LId[0] and $0F;
  LId[0] := LId[0] or $40;
  Result := TSubjectKeyIdentifier.Create(LId);
end;

class function TX509ExtensionUtilities.GetAuthorityKeyIdentifier(const AExtensions: IX509Extensions): IAuthorityKeyIdentifier;
begin
  Result := GetExtension<IAuthorityKeyIdentifier>(AExtensions, TX509Extensions.AuthorityKeyIdentifier,
    function(AOctets: TCryptoLibByteArray): IAuthorityKeyIdentifier
    begin
      Result := TAuthorityKeyIdentifier.GetInstance(AOctets);
    end);
end;

class function TX509ExtensionUtilities.GetSubjectKeyIdentifier(const AExtensions: IX509Extensions): ISubjectKeyIdentifier;
begin
  Result := GetExtension<ISubjectKeyIdentifier>(AExtensions, TX509Extensions.SubjectKeyIdentifier,
    function(AOctets: TCryptoLibByteArray): ISubjectKeyIdentifier
    begin
      Result := TSubjectKeyIdentifier.GetInstance(AOctets);
    end);
end;

class function TX509ExtensionUtilities.FromExtensionValue(const AExtensionValue: IAsn1OctetString): IAsn1Object;
begin
  Result := TAsn1Object.FromByteArray(AExtensionValue.GetOctets());
end;

class function TX509ExtensionUtilities.FromExtensionValue(const AExtensions: IX509Extensions;
  const AOid: IDerObjectIdentifier): IAsn1Object;
begin
  if AExtensions = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := AExtensions.GetExtensionParsedValue(AOid);
end;

class function TX509ExtensionUtilities.GetExtension<TExtension>(const AExtensions: IX509Extensions;
  const AOid: IDerObjectIdentifier;
  const AConstructor: TFunc<TCryptoLibByteArray, TExtension>): TExtension;
var
  LExtensionValue: IAsn1OctetString;
begin
  if AExtensions = nil then
  begin
    Result := Default(TExtension);
    Exit;
  end;
  LExtensionValue := AExtensions.GetExtensionValue(AOid);
  if LExtensionValue = nil then
  begin
    Result := Default(TExtension);
    Exit;
  end;
  Result := AConstructor(LExtensionValue.GetOctets());
end;

end.
