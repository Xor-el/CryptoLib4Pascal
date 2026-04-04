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

unit ClpCertTestUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  SyncObjs,
  DateUtils,
  ClpDateTimeHelper,
  ClpDateTimeUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpBigInteger,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpIX509Certificate,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509ExtensionUtilities,
  ClpX509Asn1Generators,
  ClpIX509Asn1Generators,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Test utilities for generating key pairs and X.509 certificates (root, end-entity with extensions).
  /// </summary>
  TCertTestUtilities = class sealed(TObject)
  strict private
    class var
      FSerialNumber: Int64;
      FLock: TCriticalSection;

    class function NextSerialNumber: Int64; static;
    class function CreateSelfSignedCert(const ADn: IX509Name; const ASigName: String;
      const AKeyPair: IAsymmetricCipherKeyPair): IX509Certificate; static;
    class function CreateCert(const ASignerName: IX509Name;
      const ASignerKey: IAsymmetricKeyParameter; const ADn: IX509Name;
      const ASigName: String; const AExtensions: IX509Extensions;
      const APubKey: IAsymmetricKeyParameter): IX509Certificate; static;

  public
    class constructor Create;
    class destructor Destroy;

    /// <summary>Create a random RSA key pair with the given strength (e.g. 1024, 2048).</summary>
    class function GenerateRsaKeyPair(const AKeyStrength: Int32 = 1024): IAsymmetricCipherKeyPair; static;

    /// <summary>Generate a self-signed root CA with default DN "CN=Test CA Certificate".</summary>
    class function GenerateRootCert(const AKeyPair: IAsymmetricCipherKeyPair): IX509Certificate; overload; static;
    /// <summary>Generate a self-signed root CA with the given subject/issuer DN.</summary>
    class function GenerateRootCert(const AKeyPair: IAsymmetricCipherKeyPair;
      const ADn: IX509Name): IX509Certificate; overload; static;

    /// <summary>Generate an end-entity certificate signed by the given CA (default subject).</summary>
    class function GenerateEndEntityCert(const AEntityKey, ACaKey: IAsymmetricKeyParameter;
      const ACaCert: IX509Certificate): IX509Certificate; overload; static;
    /// <summary>Generate an end-entity certificate with explicit subject.</summary>
    class function GenerateEndEntityCert(const AEntityKey: IAsymmetricKeyParameter;
      const ASubject: IX509Name; const ACaKey: IAsymmetricKeyParameter;
      const ACaCert: IX509Certificate): IX509Certificate; overload; static;
    /// <summary>Generate an end-entity certificate with a single extended key usage.</summary>
    class function GenerateEndEntityCert(const AEntityKey: IAsymmetricKeyParameter;
      const ASubject: IX509Name; const AKeyPurpose: IDerObjectIdentifier;
      const ACaKey: IAsymmetricKeyParameter;
      const ACaCert: IX509Certificate): IX509Certificate; overload; static;
    /// <summary>Generate an end-entity certificate with two extended key usages (e.g. capwap AC and WTP).</summary>
    class function GenerateEndEntityCert(const AEntityKey: IAsymmetricKeyParameter;
      const ASubject: IX509Name; const AKeyPurpose1, AKeyPurpose2: IDerObjectIdentifier;
      const ACaKey: IAsymmetricKeyParameter;
      const ACaCert: IX509Certificate): IX509Certificate; overload; static;
  end;

implementation

{ TCertTestUtilities }

class constructor TCertTestUtilities.Create;
begin
  FSerialNumber := TDateTimeUtilities.DateTimeToTicks(Now.ToUniversalTime());
  FLock := TCriticalSection.Create;
end;

class destructor TCertTestUtilities.Destroy;
begin
  FLock.Free;
end;

class function TCertTestUtilities.NextSerialNumber: Int64;
begin
  FLock.Enter;
  try
    Inc(FSerialNumber);
    Result := FSerialNumber;
  finally
    FLock.Leave;
  end;
end;

class function TCertTestUtilities.GenerateRsaKeyPair(const AKeyStrength: Int32): IAsymmetricCipherKeyPair;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create;
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TKeyGenerationParameters.Create(LRandom, AKeyStrength) as IKeyGenerationParameters);
  Result := LKpg.GenerateKeyPair;
end;

class function TCertTestUtilities.CreateSelfSignedCert(const ADn: IX509Name; const ASigName: String;
  const AKeyPair: IAsymmetricCipherKeyPair): IX509Certificate;
var
  LGen: IX509V1CertificateGenerator;
  LUtcNow: TDateTime;
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create;
  LUtcNow := Now.ToUniversalTime();
  LGen := TX509V1CertificateGenerator.Create;
  LGen.SetSerialNumber(TBigInteger.ValueOf(NextSerialNumber));
  LGen.SetIssuerDN(ADn);
  LGen.SetNotBeforeUtc(IncSecond(LUtcNow, -5));
  LGen.SetNotAfterUtc(IncMinute(LUtcNow, 30));
  LGen.SetSubjectDN(ADn);
  LGen.SetPublicKey(AKeyPair.Public as IAsymmetricKeyParameter);
  Result := LGen.Generate(TAsn1SignatureFactory.Create(ASigName,
    AKeyPair.Private as IAsymmetricKeyParameter, LRandom) as ISignatureFactory);
end;

class function TCertTestUtilities.CreateCert(const ASignerName: IX509Name;
  const ASignerKey: IAsymmetricKeyParameter; const ADn: IX509Name;
  const ASigName: String; const AExtensions: IX509Extensions;
  const APubKey: IAsymmetricKeyParameter): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LUtcNow: TDateTime;
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create;
  LUtcNow := Now.ToUniversalTime();
  LGen := TX509V3CertificateGenerator.Create;
  LGen.SetSerialNumber(TBigInteger.ValueOf(NextSerialNumber));
  LGen.SetIssuerDN(ASignerName);
  LGen.SetNotBeforeUtc(IncSecond(LUtcNow, -5));
  LGen.SetNotAfterUtc(IncMinute(LUtcNow, 30));
  LGen.SetSubjectDN(ADn);
  LGen.SetPublicKey(APubKey);
  LGen.AddExtensions(AExtensions);
  Result := LGen.Generate(TAsn1SignatureFactory.Create(ASigName, ASignerKey, LRandom) as ISignatureFactory);
end;

class function TCertTestUtilities.GenerateRootCert(const AKeyPair: IAsymmetricCipherKeyPair): IX509Certificate;
var
  LDn: IX509Name;
begin
  LDn := TX509Name.Create('CN=Test CA Certificate');
  Result := CreateSelfSignedCert(LDn, 'SHA256withRSA', AKeyPair);
end;

class function TCertTestUtilities.GenerateRootCert(const AKeyPair: IAsymmetricCipherKeyPair;
  const ADn: IX509Name): IX509Certificate;
begin
  Result := CreateSelfSignedCert(ADn, 'SHA256withRSA', AKeyPair);
end;

class function TCertTestUtilities.GenerateEndEntityCert(const AEntityKey, ACaKey: IAsymmetricKeyParameter;
  const ACaCert: IX509Certificate): IX509Certificate;
var
  LSubject: IX509Name;
begin
  LSubject := TX509Name.Create('CN=Test End Certificate');
  Result := GenerateEndEntityCert(AEntityKey, LSubject, ACaKey, ACaCert);
end;

class function TCertTestUtilities.GenerateEndEntityCert(const AEntityKey: IAsymmetricKeyParameter;
  const ASubject: IX509Name; const ACaKey: IAsymmetricKeyParameter;
  const ACaCert: IX509Certificate): IX509Certificate;
var
  LCaCertLw: IX509CertificateStructure;
  LExtGen: IX509ExtensionsGenerator;
  LIssuerNames: IGeneralNames;
  LAki: IAuthorityKeyIdentifier;
begin
  LCaCertLw := ACaCert.CertificateStructure;
  LExtGen := TX509ExtensionsGenerator.Create;
  LIssuerNames := TGeneralNames.Create(TGeneralName.Create(LCaCertLw.Issuer) as IGeneralName);
  LAki := TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(LCaCertLw.SubjectPublicKeyInfo,
    LIssuerNames, LCaCertLw.SerialNumber);
  LExtGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False, LAki);
  LExtGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, False,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(AEntityKey));
  LExtGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(0) as IBasicConstraints);
  LExtGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.DigitalSignature or TKeyUsage.KeyCertSign or TKeyUsage.CrlSign) as IKeyUsage);
  Result := CreateCert(LCaCertLw.Subject, ACaKey, ASubject, 'SHA256withRSA', LExtGen.Generate, AEntityKey);
end;

class function TCertTestUtilities.GenerateEndEntityCert(const AEntityKey: IAsymmetricKeyParameter;
  const ASubject: IX509Name; const AKeyPurpose: IDerObjectIdentifier;
  const ACaKey: IAsymmetricKeyParameter;
  const ACaCert: IX509Certificate): IX509Certificate;
begin
  Result := GenerateEndEntityCert(AEntityKey, ASubject, AKeyPurpose, nil, ACaKey, ACaCert);
end;

class function TCertTestUtilities.GenerateEndEntityCert(const AEntityKey: IAsymmetricKeyParameter;
  const ASubject: IX509Name; const AKeyPurpose1, AKeyPurpose2: IDerObjectIdentifier;
  const ACaKey: IAsymmetricKeyParameter;
  const ACaCert: IX509Certificate): IX509Certificate;
var
  LCaCertLw: IX509CertificateStructure;
  LExtGen: IX509ExtensionsGenerator;
  LIssuerNames: IGeneralNames;
  LAki: IAuthorityKeyIdentifier;
  LUsages: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  LCaCertLw := ACaCert.CertificateStructure;
  LExtGen := TX509ExtensionsGenerator.Create;
  LIssuerNames := TGeneralNames.Create(TGeneralName.Create(LCaCertLw.Issuer) as IGeneralName);
  LAki := TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(LCaCertLw.SubjectPublicKeyInfo,
    LIssuerNames, LCaCertLw.SerialNumber);
  LExtGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False, LAki);
  LExtGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, False,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(AEntityKey));
  LExtGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(0) as IBasicConstraints);
  LExtGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.DigitalSignature or TKeyUsage.KeyCertSign or TKeyUsage.CrlSign) as IKeyUsage);

  if AKeyPurpose2 = nil then
  begin
    System.SetLength(LUsages, 1);
    LUsages[0] := AKeyPurpose1;
    LExtGen.AddExtension(TX509Extensions.ExtendedKeyUsage, True,
      TExtendedKeyUsage.Create(LUsages) as IExtendedKeyUsage);
  end
  else
  begin
    System.SetLength(LUsages, 2);
    LUsages[0] := AKeyPurpose1;
    LUsages[1] := AKeyPurpose2;
    LExtGen.AddExtension(TX509Extensions.ExtendedKeyUsage, True,
      TExtendedKeyUsage.Create(LUsages) as IExtendedKeyUsage);
  end;

  Result := CreateCert(LCaCertLw.Subject, ACaKey, ASubject, 'SHA256withRSA', LExtGen.Generate, AEntityKey);
end;

end.
