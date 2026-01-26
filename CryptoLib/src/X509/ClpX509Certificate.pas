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

unit ClpX509Certificate;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Rtti,
  Math,
  Generics.Collections,
  DateUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509ExtensionBase,
  ClpIX509Certificate,
  ClpAsn1Dumper,
  ClpX509ExtensionUtilities,
  ClpX509SignatureUtilities,
  ClpX509Utilities,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactory,
  ClpIVerifier,
  ClpIStreamCalculator,
  ClpIVerifierFactoryProvider,
  ClpAsn1VerifierFactory,
  ClpAsn1VerifierFactoryProvider,
  ClpPublicKeyFactory,
  ClpBigInteger,
  ClpRfc5280Asn1Utilities,
  ClpIX509Extension,
  ClpCryptoLibTypes,
  ClpArrayUtils,
  ClpEncoders,
  ClpIPAddressUtilities;

type
  /// <summary>
  /// An Object representing an X509 Certificate.
  /// Has static methods for loading Certificates encoded in many forms that return X509Certificate Objects.
  /// </summary>
  TX509Certificate = class(TX509ExtensionBase, IX509Certificate)

  strict private
  type
    ICachedEncoding = interface(IInterface)
      ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
      function GetEncoding: TCryptoLibByteArray;
      function GetEncoded: TCryptoLibByteArray;
    end;

    TCachedEncoding = class(TInterfacedObject, ICachedEncoding)
    strict private
      var
        FEncoding: TCryptoLibByteArray;
        FException: Exception;
    public
      constructor Create(const AEncoding: TCryptoLibByteArray; const AException: Exception);
      function GetEncoding: TCryptoLibByteArray;
      function GetEncoded: TCryptoLibByteArray;
    end;

  strict private
    var
      FCertificateStructure: IX509CertificateStructure;
      FSigAlgParams: TCryptoLibByteArray;
      FBasicConstraints: IBasicConstraints;
      FKeyUsage: TCryptoLibBooleanArray;
      FSigAlgName: String;
      FPublicKeyValue: IAsymmetricKeyParameter;
      FCachedEncoding: ICachedEncoding;
      FHashValueSet: Boolean;
      FHashValue: Int32;

    function GetCachedEncoding: ICachedEncoding;
    function CreateCachedEncoding(const ACert: IX509CertificateStructure): ICachedEncoding;
    function CreatePublicKey(const ACert: IX509CertificateStructure): IAsymmetricKeyParameter;
    function IPAddressToString(const AAddrBytes: TCryptoLibByteArray): String;

  strict protected
    function GetX509Extensions: IX509Extensions; override;
    function GetAlternativeNameExtension(const AOid: IDerObjectIdentifier): IGeneralNames; virtual;
    function GetAlternativeNames(const AOid: IDerObjectIdentifier): TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>; virtual;
    procedure CheckSignature(const AVerifier: IVerifierFactory); virtual;
    function CheckSignatureValid(const AVerifier: IVerifierFactory): Boolean; virtual;

  public
    constructor Create(const ACertData: TCryptoLibByteArray); overload;
    constructor Create(const ACertificate: IX509CertificateStructure); overload;

    function GetCertificateStructure: IX509CertificateStructure;
    function IsValidNow: Boolean;
    function IsValid(const ATime: TDateTime): Boolean;
    procedure CheckValidity(); overload;
    procedure CheckValidity(const ATime: TDateTime); overload;

    function GetVersion: Int32;
    function GetSerialNumber: TBigInteger;
    function GetIssuerDN: IX509Name;
    function GetSubjectDN: IX509Name;
    function GetNotBefore: TDateTime;
    function GetNotAfter: TDateTime;
    function GetTbsCertificate: ITbsCertificateStructure;
    function GetTbsCertificateEncoded: TCryptoLibByteArray;
    function GetSignature: TCryptoLibByteArray;
    function GetSigAlgName: String;
    function GetSigAlgOid: String;
    function GetSigAlgParams: TCryptoLibByteArray;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetIsCritical: Boolean;
    function GetValue: IAsn1OctetString;
    function GetParsedValue: IAsn1Object;
    function GetIssuerUniqueID: IDerBitString;
    function GetSubjectUniqueID: IDerBitString;
    function GetKeyUsage: TCryptoLibBooleanArray;
    function GetExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetBasicConstraints: Int32;
    function GetIssuerAlternativeNameExtension: IGeneralNames;
    function GetSubjectAlternativeNameExtension: IGeneralNames;
    function GetIssuerAlternativeNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
    function GetSubjectAlternativeNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetPublicKey: IAsymmetricKeyParameter;
    function GetEncoded: TCryptoLibByteArray;

    function Equals(AObj: TObject): Boolean; reintroduce;
    function GetHashCode: Int32; override;
    function ToString: String; override;

    function IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function IsAlternativeSignatureValid(const APublicKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsAlternativeSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;

    procedure Verify(const AKey: IAsymmetricKeyParameter); overload;
    procedure Verify(const AVerifierProvider: IVerifierFactoryProvider); overload;
    procedure VerifyAltSignature(const AVerifierProvider: IVerifierFactoryProvider);

    class function AreEquivalentAlgorithms(const AId1, AId2: IAlgorithmIdentifier): Boolean; static;
    class function VerifySignature(const AVerifierFactory: IVerifierFactory;
      const AAsn1Encodable: IAsn1Encodable; const ASignature: IDerBitString): Boolean; static;

    property CertificateStructure: IX509CertificateStructure read GetCertificateStructure;
    property Version: Int32 read GetVersion;
    property SerialNumber: TBigInteger read GetSerialNumber;
    property IssuerDN: IX509Name read GetIssuerDN;
    property SubjectDN: IX509Name read GetSubjectDN;
    property NotBefore: TDateTime read GetNotBefore;
    property NotAfter: TDateTime read GetNotAfter;
    property TbsCertificate: ITbsCertificateStructure read GetTbsCertificate;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SigAlgName: String read GetSigAlgName;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;

  end;

implementation

{ TX509Certificate.TCachedEncoding }

constructor TX509Certificate.TCachedEncoding.Create(const AEncoding: TCryptoLibByteArray; const AException: Exception);
begin
  inherited Create();
  FEncoding := AEncoding;
  FException := AException;
end;

function TX509Certificate.TCachedEncoding.GetEncoding: TCryptoLibByteArray;
begin
  Result := FEncoding;
end;

function TX509Certificate.TCachedEncoding.GetEncoded: TCryptoLibByteArray;
begin
  if FException <> nil then
    raise FException;
  if FEncoding = nil then
    raise EIOCryptoLibException.Create('Failed to encode certificate');
  Result := FEncoding;
end;

{ TX509Certificate }

constructor TX509Certificate.Create(const ACertData: TCryptoLibByteArray);
begin
  Create(TX509CertificateStructure.GetInstance(ACertData));
end;

constructor TX509Certificate.Create(const ACertificate: IX509CertificateStructure);
var
  LParameters: IAsn1Encodable;
  LKeyUsageBits: IDerBitString;
  LKeyUsageBytes: TCryptoLibByteArray;
  LLength, I: Int32;
begin
  inherited Create();
  if ACertificate = nil then
    raise EArgumentNilCryptoLibException.Create('certificate');

  FCertificateStructure := ACertificate;

  try
    LParameters := ACertificate.SignatureAlgorithm.Parameters;
    if LParameters <> nil then
      FSigAlgParams := LParameters.GetEncoded(TAsn1Encodable.Der)
    else
      FSigAlgParams := nil;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('Certificate contents invalid: ' + E.Message);
  end;

  try
    FBasicConstraints := TX509ExtensionUtilities.GetExtension<IBasicConstraints>(ACertificate.Extensions,
      TX509Extensions.BasicConstraints,
      function(AOctets: TCryptoLibByteArray): IBasicConstraints
      begin
        Result := TBasicConstraints.GetInstance(AOctets);
      end
    );
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('cannot construct BasicConstraints: ' + E.Message);
  end;

  try
    LKeyUsageBits := TX509ExtensionUtilities.GetExtension<IDerBitString>(ACertificate.Extensions,
      TX509Extensions.KeyUsage,
      function(AOctets: TCryptoLibByteArray): IDerBitString
      begin
        Result := TDerBitString.GetInstance(AOctets);
      end);
    if LKeyUsageBits <> nil then
    begin
      LKeyUsageBytes := LKeyUsageBits.GetBytes();
      LLength := (System.Length(LKeyUsageBytes) * 8) - LKeyUsageBits.PadBits;
      if LLength < 9 then
        LLength := 9;
      System.SetLength(FKeyUsage, LLength);
      for I := 0 to LLength - 1 do
      begin
        FKeyUsage[I] := (LKeyUsageBytes[I div 8] and ($80 shr (I mod 8))) <> 0;
      end;
    end
    else
    begin
      FKeyUsage := nil;
    end;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('cannot construct KeyUsage: ' + E.Message);
  end;
end;

function TX509Certificate.GetX509Extensions: IX509Extensions;
begin
  if FCertificateStructure.Version >= 3 then
    Result := FCertificateStructure.Extensions
  else
    Result := nil;
end;

function TX509Certificate.GetCertificateStructure: IX509CertificateStructure;
begin
  Result := FCertificateStructure;
end;

function TX509Certificate.IsValidNow: Boolean;
begin
  Result := IsValid(Now);
end;

function TX509Certificate.IsValid(const ATime: TDateTime): Boolean;
begin
  Result := (CompareDateTime(ATime, NotBefore) >= 0) and (CompareDateTime(ATime, NotAfter) <= 0);
end;

procedure TX509Certificate.CheckValidity();
begin
  CheckValidity(Now);
end;

procedure TX509Certificate.CheckValidity(const ATime: TDateTime);
begin
  if CompareDateTime(ATime, NotAfter) > 0 then
    raise EArgumentCryptoLibException.CreateFmt('certificate expired on %s', [DateTimeToStr(FCertificateStructure.EndDate.ToDateTime())]);
  if CompareDateTime(ATime, NotBefore) < 0 then
    raise EArgumentCryptoLibException.CreateFmt('certificate not valid until %s', [DateTimeToStr(FCertificateStructure.StartDate.ToDateTime())]);
end;

function TX509Certificate.GetVersion: Int32;
begin
  Result := FCertificateStructure.Version;
end;

function TX509Certificate.GetSerialNumber: TBigInteger;
begin
  Result := FCertificateStructure.SerialNumber.Value;
end;

function TX509Certificate.GetIssuerDN: IX509Name;
begin
  Result := FCertificateStructure.Issuer;
end;

function TX509Certificate.GetSubjectDN: IX509Name;
begin
  Result := FCertificateStructure.Subject;
end;

function TX509Certificate.GetNotBefore: TDateTime;
begin
  Result := FCertificateStructure.StartDate.ToDateTime();
end;

function TX509Certificate.GetNotAfter: TDateTime;
begin
  Result := FCertificateStructure.EndDate.ToDateTime();
end;

function TX509Certificate.GetTbsCertificate: ITbsCertificateStructure;
begin
  Result := FCertificateStructure.TbsCertificate;
end;

function TX509Certificate.GetTbsCertificateEncoded: TCryptoLibByteArray;
begin
  Result := FCertificateStructure.TbsCertificate.GetDerEncoded();
end;

function TX509Certificate.GetSignature: TCryptoLibByteArray;
begin
  Result := FCertificateStructure.GetSignatureOctets();
end;

function TX509Certificate.GetSigAlgName: String;
begin
  if FSigAlgName = '' then
  begin
    FSigAlgName := TX509SignatureUtilities.GetSignatureName(SignatureAlgorithm);
  end;
  Result := FSigAlgName;
end;

function TX509Certificate.GetIsCritical: Boolean;
begin
  raise ENotSupportedCryptoLibException.Create('GetIsCritical not applicable to X509Certificate');
end;

function TX509Certificate.GetValue: IAsn1OctetString;
begin
  raise ENotSupportedCryptoLibException.Create('GetValue not applicable to X509Certificate');
end;

function TX509Certificate.GetParsedValue: IAsn1Object;
begin
  raise ENotSupportedCryptoLibException.Create('GetParsedValue not applicable to X509Certificate');
end;

function TX509Certificate.GetSigAlgOid: String;
begin
  Result := FCertificateStructure.SignatureAlgorithm.Algorithm.Id;
end;

function TX509Certificate.GetSigAlgParams: TCryptoLibByteArray;
begin
  Result := TArrayUtils.Clone(FSigAlgParams);
end;

function TX509Certificate.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FCertificateStructure.SignatureAlgorithm;
end;

function TX509Certificate.GetIssuerUniqueID: IDerBitString;
begin
  Result := FCertificateStructure.IssuerUniqueID;
end;

function TX509Certificate.GetSubjectUniqueID: IDerBitString;
begin
  Result := FCertificateStructure.SubjectUniqueID;
end;

function TX509Certificate.GetKeyUsage: TCryptoLibBooleanArray;
begin
  Result := TArrayUtils.Clone<Boolean>(FKeyUsage);
end;

function TX509Certificate.GetExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
var
  LSeq: IAsn1Sequence;
  LResult: TList<IDerObjectIdentifier>;
  I: Int32;
begin
  try
    LSeq := TX509ExtensionUtilities.GetExtension<IAsn1Sequence>(GetX509Extensions(),
      TX509Extensions.ExtendedKeyUsage,
      function(AOctets: TCryptoLibByteArray): IAsn1Sequence
      begin
        Result := TAsn1Sequence.GetInstance(AOctets);
      end);
    if LSeq = nil then
    begin
      Result := nil;
      Exit;
    end;

    LResult := TList<IDerObjectIdentifier>.Create();
    try
      for I := 0 to LSeq.Count - 1 do
      begin
        LResult.Add(TDerObjectIdentifier.GetInstance(LSeq[I]));
      end;
      Result := LResult.ToArray();
    finally
      LResult.Free;
    end;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('error processing extended key usage extension: ' + E.Message);
  end;
end;

function TX509Certificate.GetBasicConstraints: Int32;
begin
  if (FBasicConstraints = nil) or (not FBasicConstraints.IsCA()) then
  begin
    Result := -1;
    Exit;
  end;

  if FBasicConstraints.PathLenConstraint.IsInitialized then
    Result := FBasicConstraints.PathLenConstraint.Int32ValueExact
  else
    Result := MaxInt;
end;

function TX509Certificate.GetIssuerAlternativeNameExtension: IGeneralNames;
begin
  Result := GetAlternativeNameExtension(TX509Extensions.IssuerAlternativeName);
end;

function TX509Certificate.GetSubjectAlternativeNameExtension: IGeneralNames;
begin
  Result := GetAlternativeNameExtension(TX509Extensions.SubjectAlternativeName);
end;

function TX509Certificate.GetIssuerAlternativeNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
begin
  Result := GetAlternativeNames(TX509Extensions.IssuerAlternativeName);
end;

function TX509Certificate.GetSubjectAlternativeNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
begin
  Result := GetAlternativeNames(TX509Extensions.SubjectAlternativeName);
end;

function TX509Certificate.GetAlternativeNameExtension(const AOid: IDerObjectIdentifier): IGeneralNames;
begin
  Result := TX509ExtensionUtilities.GetExtension<IGeneralNames>(GetX509Extensions(), AOid,
    function(AOctets: TCryptoLibByteArray): IGeneralNames
    begin
      Result := TGeneralNames.GetInstance(TAsn1Object.FromByteArray(AOctets));
    end);
end;

function TX509Certificate.GetAlternativeNames(const AOid: IDerObjectIdentifier): TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
var
  LGeneralNames: IGeneralNames;
  LGns: TCryptoLibGenericArray<IGeneralName>;
  LResult: TList<TCryptoLibGenericArray<TValue>>;
  LEntry: TList<TValue>;
  LGn: IGeneralName;
  I: Int32;
  LName: IAsn1Encodable;
  LAsn1String: IAsn1String;
  LNameObj: IX509Name;
  LOid: IDerObjectIdentifier;
  LOctetString: IAsn1OctetString;
  LIPAddr: String;
begin
  LGeneralNames := GetAlternativeNameExtension(AOid);
  if LGeneralNames = nil then
  begin
    Result := nil;
    Exit;
  end;

  LGns := LGeneralNames.GetNames();
  LResult := TList<TCryptoLibGenericArray<TValue>>.Create();
  try
    for I := 0 to System.Length(LGns) - 1 do
    begin
      LGn := LGns[I];
      LEntry := TList<TValue>.Create();
      try
        LEntry.Add(TValue.From<Int32>(LGn.TagNo));

        case LGn.TagNo of
          TGeneralName.EdiPartyName,
          TGeneralName.X400Address,
          TGeneralName.OtherName:
            begin
              LEntry.Add(TValue.From<TCryptoLibByteArray>(LGn.GetEncoded()));
            end;
          TGeneralName.DirectoryName:
            begin
              LName := LGn.Name;
              if Supports(LName, IX509Name, LNameObj) then
                LEntry.Add(TValue.From<String>(LNameObj.ToString()))
              else
                LEntry.Add(TValue.From<String>(TX509Name.GetInstance(LName).ToString()));
            end;
          TGeneralName.DnsName,
          TGeneralName.Rfc822Name,
          TGeneralName.UniformResourceIdentifier:
            begin
              if Supports(LGn.Name, IAsn1String, LAsn1String) then
                LEntry.Add(TValue.From<String>(LAsn1String.GetString()));
            end;
          TGeneralName.RegisteredID:
            begin
              LOid := TDerObjectIdentifier.GetInstance(LGn.Name);
              LEntry.Add(TValue.From<String>(LOid.Id));
            end;
          TGeneralName.IPAddress:
            begin
              LOctetString := TAsn1OctetString.GetInstance(LGn.Name);
              LIPAddr := IPAddressToString(LOctetString.GetOctets());
              LEntry.Add(TValue.From<String>(LIPAddr));
            end;
        else
          raise EIOCryptoLibException.CreateFmt('Bad tag number: %d', [LGn.TagNo]);
        end;

        LResult.Add(LEntry.ToArray());
      finally
        LEntry.Free;
      end;
    end;
    Result := LResult.ToArray();
  finally
    LResult.Free;
  end;
end;

function TX509Certificate.IPAddressToString(const AAddrBytes: TCryptoLibByteArray): String;
var
  I: Int32;
  LAddr: String;
  LWord: Word;
begin
  if System.Length(AAddrBytes) = 4 then
  begin
    // IPv4
    LAddr := IntToStr(AAddrBytes[0] and $FF);
    for I := 1 to 3 do
    begin
      LAddr := LAddr + '.' + IntToStr(AAddrBytes[I] and $FF);
    end;
    Result := LAddr;
  end
  else if System.Length(AAddrBytes) = 16 then
  begin
    // IPv6 - format as 8 groups of 4 hex digits
    LWord := (AAddrBytes[0] shl 8) or AAddrBytes[1];
    LAddr := IntToHex(LWord, 4);
    for I := 1 to 7 do
    begin
      LWord := (AAddrBytes[I * 2] shl 8) or AAddrBytes[I * 2 + 1];
      LAddr := LAddr + ':' + IntToHex(LWord, 4);
    end;
    Result := LAddr;
  end
  else
  begin
    // Unknown format, return hex
    Result := THex.Encode(AAddrBytes);
  end;
end;

function TX509Certificate.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FCertificateStructure.SubjectPublicKeyInfo;
end;

function TX509Certificate.GetPublicKey: IAsymmetricKeyParameter;
begin
  // Cache the public key to support repeated-use optimizations
  if FPublicKeyValue = nil then
  begin
    FPublicKeyValue := CreatePublicKey(FCertificateStructure);
  end;
  Result := FPublicKeyValue;
end;

function TX509Certificate.CreatePublicKey(const ACert: IX509CertificateStructure): IAsymmetricKeyParameter;
begin
  Result := TPublicKeyFactory.CreateKey(ACert.SubjectPublicKeyInfo);
end;

function TX509Certificate.GetEncoded: TCryptoLibByteArray;
begin
  Result := TArrayUtils.Clone(GetCachedEncoding().GetEncoded());
end;

function TX509Certificate.GetCachedEncoding: ICachedEncoding;
begin
  if FCachedEncoding = nil then
  begin
    FCachedEncoding := CreateCachedEncoding(FCertificateStructure);
  end;
  Result := FCachedEncoding;
end;

function TX509Certificate.CreateCachedEncoding(const ACert: IX509CertificateStructure): ICachedEncoding;
var
  LEncoding: TCryptoLibByteArray;
  LException: Exception;
begin
  LEncoding := nil;
  LException := nil;
  try
    LEncoding := ACert.GetEncoded(TAsn1Encodable.Der);
  except
    on E: Exception do
    begin
      LException := EIOCryptoLibException.Create('Failed to DER-encode certificate: ' + E.Message);
    end;
  end;
  Result := TCachedEncoding.Create(LEncoding, LException);
end;

function TX509Certificate.Equals(AObj: TObject): Boolean;
var
  LThatCert: IX509Certificate;
  LThat: TX509Certificate;
  LThisEncoding, LThatEncoding: TCryptoLibByteArray;
  LSignature: IDerBitString;
begin
  if Self = AObj then
  begin
    Result := True;
    Exit;
  end;

  if not Supports(AObj, IX509Certificate, LThatCert) then
  begin
    Result := False;
    Exit;
  end;

  LThat := AObj as TX509Certificate;

  if FHashValueSet and LThat.FHashValueSet then
  begin
    if FHashValue <> LThat.FHashValue then
    begin
      Result := False;
      Exit;
    end;
  end
  else if (FCachedEncoding = nil) or (LThat.FCachedEncoding = nil) then
  begin
    LSignature := FCertificateStructure.Signature;
    if (LSignature <> nil) and (not LSignature.Equals(LThat.FCertificateStructure.Signature)) then
    begin
      Result := False;
      Exit;
    end;
  end;

  LThisEncoding := GetCachedEncoding().GetEncoding();
  LThatEncoding := LThat.GetCachedEncoding().GetEncoding();

  if (LThisEncoding <> nil) and (LThatEncoding <> nil) then
    Result := TArrayUtils.AreEqual(LThisEncoding, LThatEncoding)
  else
    Result := False;
end;

function TX509Certificate.GetHashCode: Int32;
var
  LEncoding: TCryptoLibByteArray;
begin
  if not FHashValueSet then
  begin
    LEncoding := GetCachedEncoding().GetEncoding();
    FHashValue := TArrayUtils.GetArrayHashCode(LEncoding);
    FHashValueSet := True;
  end;
  Result := FHashValue;
end;

function TX509Certificate.ToString: String;
var
  LBuf: TStringBuilder;
  LSig: TCryptoLibByteArray;
  I, LLen: Int32;
  LExtensions: IX509Extensions;
  LOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LExt: IX509Extension;
  LOid: IDerObjectIdentifier;
  LObj: IAsn1Object;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.Append('  [0]         Version: ').Append(Version).AppendLine();
    LBuf.Append('         SerialNumber: ').Append(SerialNumber.ToString()).AppendLine();
    LBuf.Append('             IssuerDN: ').Append(IssuerDN.ToString()).AppendLine();
    LBuf.Append('           Start Date: ').Append(DateTimeToStr(NotBefore)).AppendLine();
    LBuf.Append('           Final Date: ').Append(DateTimeToStr(NotAfter)).AppendLine();
    LBuf.Append('            SubjectDN: ').Append(SubjectDN.ToString()).AppendLine();
    LBuf.Append('           Public Key: ').Append('[Public Key]').AppendLine();
    LBuf.Append('  Signature Algorithm: ').Append(GetSigAlgName()).AppendLine();

    LSig := GetSignature();
    LLen := System.Math.Min(20, System.Length(LSig));
    LBuf.Append('            Signature: ').AppendLine(THex.Encode(TArrayUtils.CopyOfRange(LSig, 0, LLen)));

    I := 20;
    while I < System.Length(LSig) do
    begin
      LLen := Math.Min(20, System.Length(LSig) - I);
      LBuf.Append('                       ').AppendLine(THex.Encode(TArrayUtils.CopyOfRange(LSig, I, I + LLen)));
      System.Inc(I, 20);
    end;

    LExtensions := FCertificateStructure.Extensions;
    if LExtensions <> nil then
    begin
      LOids := LExtensions.GetExtensionOids;
      if System.Length(LOids) > 0 then
      begin
        LBuf.AppendLine('       Extensions:');
        for LOid in LOids do
        begin
          LExt := LExtensions.GetExtension(LOid);
          if (LExt <> nil) and (LExt.Value <> nil) then
          begin
            try
              LObj := TX509ExtensionUtilities.FromExtensionValue(LExt.Value);
              LBuf.Append('                       critical(').Append(BoolToStr(LExt.IsCritical, True)).Append(') ');
              try
                if LOid.Equals(TX509Extensions.BasicConstraints) then
                begin
                  LBuf.Append(TBasicConstraints.GetInstance(LObj).ToString());
                end
                else if LOid.Equals(TX509Extensions.KeyUsage) then
                begin
                  LBuf.Append(TKeyUsage.GetInstance(LObj).ToString());
                end
                else
                begin
                  LBuf.Append(LOid.Id);
                  LBuf.Append(' value = ').Append(TAsn1Dumper.DumpAsString(LObj));
                end;
              except
                on E: Exception do
                begin
                  LBuf.Append(LOid.Id);
                  LBuf.Append(' value = *****');
                end;
              end;
            except
              // Ignore parsing errors
            end;
            LBuf.AppendLine();
          end;
        end;
      end;
    end;

    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

function TX509Certificate.IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean;
begin
  Result := CheckSignatureValid(TAsn1VerifierFactory.Create(FCertificateStructure.SignatureAlgorithm, AKey) as IVerifierFactory);
end;

function TX509Certificate.IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
begin
  Result := CheckSignatureValid(AVerifierProvider.CreateVerifierFactory(FCertificateStructure.SignatureAlgorithm));
end;

function TX509Certificate.IsAlternativeSignatureValid(const APublicKey: IAsymmetricKeyParameter): Boolean;
begin
  Result := IsAlternativeSignatureValid(TAsn1VerifierFactoryProvider.Create(APublicKey) as IVerifierFactoryProvider);
end;

function TX509Certificate.IsAlternativeSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
var
  LTbsCertificate: ITbsCertificateStructure;
  LExtensions: IX509Extensions;
  LAltSigAlg: IAltSignatureAlgorithm;
  LAltSigValue: IAltSignatureValue;
  LVerifier: IVerifierFactory;
  LTbsSeq: IAsn1Sequence;
  LV: IAsn1EncodableVector;
  I: Int32;
  LTagged: IDerTaggedObject;
begin
  LTbsCertificate := FCertificateStructure.TbsCertificate;
  LExtensions := LTbsCertificate.Extensions;

  LAltSigAlg := TAltSignatureAlgorithm.FromExtensions(LExtensions);
  LAltSigValue := TAltSignatureValue.FromExtensions(LExtensions);

  LVerifier := AVerifierProvider.CreateVerifierFactory(LAltSigAlg.Algorithm);

  LTbsSeq := TAsn1Sequence.GetInstance(LTbsCertificate.ToAsn1Object());
  LV := TAsn1EncodableVector.Create();

  for I := 0 to LTbsSeq.Count - 2 do
  begin
    if I <> 2 then // signature field - must be ver 3 so version always present
    begin
      LV.Add(LTbsSeq[I]);
    end;
  end;

    LTagged := TDerTaggedObject.Create(True, 3, LExtensions.ToAsn1ObjectTrimmed());
  LV.Add(LTagged);

  Result := TX509Utilities.VerifySignature(LVerifier, TDerSequence.Create(LV) as IDerSequence, LAltSigValue.Signature);
end;

procedure TX509Certificate.Verify(const AKey: IAsymmetricKeyParameter);
begin
  CheckSignature(TAsn1VerifierFactory.Create(FCertificateStructure.SignatureAlgorithm, AKey));
end;

procedure TX509Certificate.Verify(const AVerifierProvider: IVerifierFactoryProvider);
begin
  CheckSignature(AVerifierProvider.CreateVerifierFactory(FCertificateStructure.SignatureAlgorithm));
end;

procedure TX509Certificate.VerifyAltSignature(const AVerifierProvider: IVerifierFactoryProvider);
begin
  if not IsAlternativeSignatureValid(AVerifierProvider) then
    raise EInvalidKeyCryptoLibException.Create('Public key presented not for certificate alternative signature');
end;

procedure TX509Certificate.CheckSignature(const AVerifier: IVerifierFactory);
begin
  if not CheckSignatureValid(AVerifier) then
    raise EInvalidKeyCryptoLibException.Create('Public key presented not for certificate signature');
end;

function TX509Certificate.CheckSignatureValid(const AVerifier: IVerifierFactory): Boolean;
var
  LTbsCertificate: ITbsCertificateStructure;
begin
  LTbsCertificate := FCertificateStructure.TbsCertificate;

  if not TX509Certificate.AreEquivalentAlgorithms(FCertificateStructure.SignatureAlgorithm, LTbsCertificate.Signature) then
    raise EArgumentCryptoLibException.Create('signature algorithm in TBS cert not same as outer cert');

  Result := TX509Certificate.VerifySignature(AVerifier, LTbsCertificate, FCertificateStructure.Signature);
end;

class function TX509Certificate.AreEquivalentAlgorithms(const AId1, AId2: IAlgorithmIdentifier): Boolean;
var
  LParams1, LParams2: IAsn1Encodable;
begin
  if not AId1.Algorithm.Equals(AId2.Algorithm) then
  begin
    Result := False;
    Exit;
  end;

  // Check if both have absent parameters (null or DerNull)
  LParams1 := AId1.Parameters;
  LParams2 := AId2.Parameters;
  if ((LParams1 = nil) or TDerNull.Instance.Equals(LParams1)) and
     ((LParams2 = nil) or TDerNull.Instance.Equals(LParams2)) then
  begin
    Result := True;
    Exit;
  end;

  // Compare parameters
  if LParams1 = nil then
    Result := (LParams2 = nil) or TDerNull.Instance.Equals(LParams2)
  else if LParams2 = nil then
    Result := TDerNull.Instance.Equals(LParams1)
  else
    Result := LParams1.Equals(LParams2);
end;

class function TX509Certificate.VerifySignature(const AVerifierFactory: IVerifierFactory;
  const AAsn1Encodable: IAsn1Encodable; const ASignature: IDerBitString): Boolean;
var
  LCalculator: IStreamCalculator<IVerifier>;
  LStream: TStream;
  LResult: IVerifier;
begin
  LCalculator := AVerifierFactory.CreateCalculator();
  LStream := LCalculator.Stream;
  AAsn1Encodable.EncodeTo(LStream, TAsn1Encodable.Der);
  LResult := LCalculator.GetResult();
  Result := LResult.IsVerified(ASignature.GetOctets());
end;

end.
