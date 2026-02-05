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

unit ClpX509Crl;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  Generics.Collections,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactory,
  ClpIVerifierFactoryProvider,
  ClpIX509Crl,
  ClpIX509CrlEntry,
  ClpIX509Certificate,
  ClpIX509Extension,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509CrlEntry,
  ClpX509ExtensionBase,
  ClpX509ExtensionUtilities,
  ClpX509SignatureUtilities,
  ClpX509Utilities,
  ClpAsn1VerifierFactory,
  ClpAsn1Dumper,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpBigInteger,
  ClpNullable,
  ClpEncoders,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TX509Crl = class(TX509ExtensionBase, IX509Crl)
  strict private
  type
    ICachedEncoding = interface(IInterface)
      ['{A2B3C4D5-E6F7-8901-BCDE-F23456789012}']
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
      FCertificateList: ICertificateList;
      FSigAlgParams: TCryptoLibByteArray;
      FIsIndirect: Boolean;
      FSigAlgName: String;
      FCachedEncoding: ICachedEncoding;
      FHashValueSet: Boolean;
      FHashValue: Int32;

    function GetCachedEncoding: ICachedEncoding;
    function CreateCachedEncoding(const ACertList: ICertificateList): ICachedEncoding;
    function GetIsIndirectCrl: Boolean;
    function LoadCrlEntries: TCryptoLibGenericArray<IX509CrlEntry>;
    procedure CheckSignature(const AVerifier: IVerifierFactory);
    function CheckSignatureValid(const AVerifier: IVerifierFactory): Boolean;

  strict protected
    function GetX509Extensions: IX509Extensions; override;

  public
    constructor Create(const AEncoding: TCryptoLibByteArray); overload;
    constructor Create(const ACertificateList: ICertificateList); overload;

    function GetCertificateList: ICertificateList;
    function GetVersion: Int32;
    function GetIssuerDN: IX509Name;
    function GetThisUpdate: TDateTime;
    function GetNextUpdate: TNullable<TDateTime>;
    function GetRevokedCertificate(const ASerialNumber: TBigInteger): IX509CrlEntry;
    function GetRevokedCertificates: TCryptoLibGenericArray<IX509CrlEntry>;
    function GetTbsCertList: TCryptoLibByteArray;
    function GetSignature: TCryptoLibByteArray;
    function GetSigAlgName: String;
    function GetSigAlgOid: String;
    function GetSigAlgParams: TCryptoLibByteArray;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetEncoded: TCryptoLibByteArray;

    function IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function IsAlternativeSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
    procedure Verify(const AKey: IAsymmetricKeyParameter); overload;
    procedure Verify(const AVerifierProvider: IVerifierFactoryProvider); overload;
    procedure VerifyAltSignature(const AVerifierProvider: IVerifierFactoryProvider);

    function IsRevoked(const ACert: IX509Certificate): Boolean;
    function Equals(const AOther: TObject): Boolean; reintroduce;
    function GetHashCode: Int32; reintroduce;
    function ToString: String; override;
  end;

implementation

{ TX509Crl.TCachedEncoding }

constructor TX509Crl.TCachedEncoding.Create(const AEncoding: TCryptoLibByteArray; const AException: Exception);
begin
  inherited Create();
  FEncoding := AEncoding;
  FException := AException;
end;

function TX509Crl.TCachedEncoding.GetEncoding: TCryptoLibByteArray;
begin
  Result := FEncoding;
end;

function TX509Crl.TCachedEncoding.GetEncoded: TCryptoLibByteArray;
begin
  if FException <> nil then
    raise FException;
  if FEncoding = nil then
    raise ECrlCryptoLibException.Create('CRL encoding is null');
  Result := FEncoding;
end;

{ TX509Crl }

constructor TX509Crl.Create(const AEncoding: TCryptoLibByteArray);
begin
  Create(TCertificateList.GetInstance(AEncoding));
end;

constructor TX509Crl.Create(const ACertificateList: ICertificateList);
var
  LParameters: IAsn1Encodable;
begin
  inherited Create();
  if ACertificateList = nil then
    raise EArgumentNilCryptoLibException.Create('certificateList');

  FCertificateList := ACertificateList;

  try
    LParameters := ACertificateList.SignatureAlgorithm.Parameters;
    if LParameters <> nil then
      FSigAlgParams := LParameters.GetEncoded(TAsn1Encodable.Der)
    else
      FSigAlgParams := nil;
    FIsIndirect := GetIsIndirectCrl;
  except
    on E: Exception do
      raise ECrlCryptoLibException.Create('CRL contents invalid: ' + E.ToString);
  end;
end;

function TX509Crl.GetX509Extensions: IX509Extensions;
begin
  if FCertificateList.Version >= 2 then
    Result := FCertificateList.TbsCertList.Extensions
  else
    Result := nil;
end;

function TX509Crl.GetIsIndirectCrl: Boolean;
var
  LObj: IAsn1Object;
  LIdp: IIssuingDistributionPoint;
begin
  try
    LObj := GetExtensionParsedValue(TX509Extensions.IssuingDistributionPoint);
    if LObj = nil then
    begin
      Result := False;
      Exit;
    end;
    LIdp := TIssuingDistributionPoint.GetInstance(LObj as IAsn1Convertible);
    Result := (LIdp <> nil) and LIdp.IsIndirectCrl;
  except
    on E: Exception do
      raise ECrlCryptoLibException.Create('Exception reading IssuingDistributionPoint' + E.ToString);
  end;
end;

function TX509Crl.GetCachedEncoding: ICachedEncoding;
begin
  if FCachedEncoding = nil then
    FCachedEncoding := CreateCachedEncoding(FCertificateList);
  Result := FCachedEncoding;
end;

function TX509Crl.CreateCachedEncoding(const ACertList: ICertificateList): ICachedEncoding;
var
  LEncoding: TCryptoLibByteArray;
  LException: Exception;
begin
  LEncoding := nil;
  LException := nil;
  try
    LEncoding := ACertList.GetDerEncoded();
  except
    on E: EIOCryptoLibException do
      LException := ECrlCryptoLibException.Create('Failed to DER-encode CRL: ' + E.Message);
  end;
  Result := TCachedEncoding.Create(LEncoding, LException);
end;

function TX509Crl.GetCertificateList: ICertificateList;
begin
  Result := FCertificateList;
end;

function TX509Crl.GetVersion: Int32;
begin
  Result := FCertificateList.Version;
end;

function TX509Crl.GetIssuerDN: IX509Name;
begin
  Result := FCertificateList.Issuer;
end;

function TX509Crl.GetThisUpdate: TDateTime;
begin
  Result := FCertificateList.ThisUpdate.ToDateTime();
end;

function TX509Crl.GetNextUpdate: TNullable<TDateTime>;
var
  LNext: ITime;
begin
  LNext := FCertificateList.TbsCertList.NextUpdate;
  if LNext = nil then
    Result := TNullable<TDateTime>.None
  else
    Result := TNullable<TDateTime>.Some(LNext.ToDateTime());
end;

function TX509Crl.LoadCrlEntries: TCryptoLibGenericArray<IX509CrlEntry>;
var
  LRevoked: TCryptoLibGenericArray<ICrlEntry>;
  LList: TList<IX509CrlEntry>;
  I: Int32;
  LPreviousIssuer: IX509Name;
  LEntry: IX509CrlEntry;
begin
  LRevoked := FCertificateList.GetRevokedCertificates();
  if (LRevoked = nil) or (System.Length(LRevoked) = 0) then
  begin
    Result := nil;
    Exit;
  end;

  LList := TList<IX509CrlEntry>.Create();
  try
    LPreviousIssuer := GetIssuerDN();
    for I := 0 to System.High(LRevoked) do
    begin
      LEntry := TX509CrlEntry.Create(LRevoked[I], FIsIndirect, LPreviousIssuer);
      LList.Add(LEntry);
      LPreviousIssuer := LEntry.GetCertificateIssuer();
    end;
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
end;

function TX509Crl.GetRevokedCertificate(const ASerialNumber: TBigInteger): IX509CrlEntry;
var
  LRevoked: TCryptoLibGenericArray<ICrlEntry>;
  LPreviousIssuer: IX509Name;
  I: Int32;
  LEntry: IX509CrlEntry;
begin
  LRevoked := FCertificateList.GetRevokedCertificates();
  if LRevoked = nil then
  begin
    Result := nil;
    Exit;
  end;

  LPreviousIssuer := GetIssuerDN();
  for I := 0 to System.High(LRevoked) do
  begin
    LEntry := TX509CrlEntry.Create(LRevoked[I], FIsIndirect, LPreviousIssuer);
    if LRevoked[I].UserCertificate.Value.Equals(ASerialNumber) then
    begin
      Result := LEntry;
      Exit;
    end;
    LPreviousIssuer := LEntry.GetCertificateIssuer();
  end;
  Result := nil;
end;

function TX509Crl.GetRevokedCertificates: TCryptoLibGenericArray<IX509CrlEntry>;
var
  LEntries: TCryptoLibGenericArray<IX509CrlEntry>;
begin
  LEntries := LoadCrlEntries();
  if (LEntries = nil) or (System.Length(LEntries) = 0) then
    Result := nil
  else
    Result := LEntries;
end;

function TX509Crl.GetTbsCertList: TCryptoLibByteArray;
begin
  try
    Result := FCertificateList.TbsCertList.GetDerEncoded();
  except
    on E: Exception do
      raise ECrlCryptoLibException.Create(E.ToString);
  end;
end;

function TX509Crl.GetSignature: TCryptoLibByteArray;
begin
  Result := FCertificateList.GetSignatureOctets();
end;

function TX509Crl.GetSigAlgName: String;
begin
  if FSigAlgName = '' then
    FSigAlgName := TX509SignatureUtilities.GetSignatureName(GetSignatureAlgorithm());
  Result := FSigAlgName;
end;

function TX509Crl.GetSigAlgOid: String;
begin
  Result := FCertificateList.SignatureAlgorithm.Algorithm.Id;
end;

function TX509Crl.GetSigAlgParams: TCryptoLibByteArray;
begin
  if FSigAlgParams = nil then
    Result := nil
  else
    Result := System.Copy(FSigAlgParams);
end;

function TX509Crl.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FCertificateList.SignatureAlgorithm;
end;

function TX509Crl.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(GetCachedEncoding().GetEncoded());
end;

function TX509Crl.IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean;
begin
  Result := CheckSignatureValid(TAsn1VerifierFactory.Create(FCertificateList.SignatureAlgorithm, AKey) as IVerifierFactory);
end;

function TX509Crl.IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
begin
  Result := CheckSignatureValid(AVerifierProvider.CreateVerifierFactory(FCertificateList.SignatureAlgorithm));
end;

function TX509Crl.IsAlternativeSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
var
  LTbsCertList: ITbsCertificateList;
  LExtensions: IX509Extensions;
  LAltSigAlg: IAltSignatureAlgorithm;
  LAltSigValue: IAltSignatureValue;
  LVerifier: IVerifierFactory;
  LTbsSeq: IAsn1Sequence;
  LV: IAsn1EncodableVector;
  LStart, I: Int32;
  LVersion: IDerInteger;
  LTagged: IDerTaggedObject;
begin
  LTbsCertList := FCertificateList.TbsCertList;
  LExtensions := LTbsCertList.Extensions;
  LAltSigAlg := TAltSignatureAlgorithm.FromExtensions(LExtensions);
  LAltSigValue := TAltSignatureValue.FromExtensions(LExtensions);
  LVerifier := AVerifierProvider.CreateVerifierFactory(LAltSigAlg.Algorithm);
  LTbsSeq := TAsn1Sequence.GetInstance(LTbsCertList.ToAsn1Object());
  LV := TAsn1EncodableVector.Create();
  LStart := 1;
  if (LTbsSeq.Count > 0) and Supports(LTbsSeq[0], IDerInteger, LVersion) then
  begin
    LV.Add(LTbsSeq[0] as IAsn1Encodable);
    LStart := 2;
  end;
  for I := LStart to LTbsSeq.Count - 2 do
    LV.Add(LTbsSeq[I] as IAsn1Encodable);
  LTagged := TDerTaggedObject.Create(True, 0, LExtensions.ToAsn1ObjectTrimmed() as IAsn1Encodable);
  LV.Add(LTagged as IAsn1Encodable);
  Result := TX509Utilities.VerifySignature(LVerifier, TDerSequence.Create(LV) as IAsn1Encodable, LAltSigValue.Signature);
end;

procedure TX509Crl.Verify(const AKey: IAsymmetricKeyParameter);
begin
  CheckSignature(TAsn1VerifierFactory.Create(FCertificateList.SignatureAlgorithm, AKey) as IVerifierFactory);
end;

procedure TX509Crl.Verify(const AVerifierProvider: IVerifierFactoryProvider);
begin
  CheckSignature(AVerifierProvider.CreateVerifierFactory(FCertificateList.SignatureAlgorithm));
end;

procedure TX509Crl.VerifyAltSignature(const AVerifierProvider: IVerifierFactoryProvider);
begin
  if not IsAlternativeSignatureValid(AVerifierProvider) then
    raise EInvalidKeyCryptoLibException.Create('CRL alternative signature does not verify with supplied public key.');
end;

procedure TX509Crl.CheckSignature(const AVerifier: IVerifierFactory);
begin
  if not CheckSignatureValid(AVerifier) then
    raise EInvalidKeyCryptoLibException.Create('CRL does not verify with supplied public key.');
end;

function TX509Crl.CheckSignatureValid(const AVerifier: IVerifierFactory): Boolean;
var
  LTbsCertList: ITbsCertificateList;
begin
  LTbsCertList := FCertificateList.TbsCertList;
  if not TX509Utilities.AreEquivalentAlgorithms(FCertificateList.SignatureAlgorithm, LTbsCertList.Signature) then
    raise ECrlCryptoLibException.Create('Signature algorithm on CertificateList does not match TbsCertList.');
  Result := TX509Utilities.VerifySignature(AVerifier, LTbsCertList as IAsn1Encodable, FCertificateList.Signature);
end;

function TX509Crl.IsRevoked(const ACert: IX509Certificate): Boolean;
var
  LRevoked: TCryptoLibGenericArray<ICrlEntry>;
  LSerial: TBigInteger;
  I: Int32;
begin
  LRevoked := FCertificateList.GetRevokedCertificates();
  if LRevoked <> nil then
  begin
    LSerial := ACert.GetSerialNumber();
    for I := 0 to System.High(LRevoked) do
      if LRevoked[I].UserCertificate.Value.Equals(LSerial) then
      begin
        Result := True;
        Exit;
      end;
  end;
  Result := False;
end;

function TX509Crl.Equals(const AOther: TObject): Boolean;
var
  LThat: IX509Crl;
  LThisEncoding, LThatEncoding: TCryptoLibByteArray;
  LThatObj: TX509Crl;
begin
  if Self = AOther then
  begin
    Result := True;
    Exit;
  end;

  if not Supports(AOther, IX509Crl, LThat) then
  begin
    Result := False;
    Exit;
  end;

  LThatObj := AOther as TX509Crl;
  if FHashValueSet and LThatObj.FHashValueSet then
  begin
    if FHashValue <> LThatObj.FHashValue then
    begin
      Result := False;
      Exit;
    end;
  end
  else if (FCachedEncoding = nil) or (LThatObj.FCachedEncoding = nil) then
  begin
    if (FCertificateList.Signature <> nil) and (not FCertificateList.Signature.Equals(LThat.CertificateList.Signature)) then
    begin
      Result := False;
      Exit;
    end;
  end;

  LThisEncoding := GetCachedEncoding().GetEncoding();
  LThatEncoding := LThatObj.GetCachedEncoding().GetEncoding();
  Result := (LThisEncoding <> nil) and (LThatEncoding <> nil) and TArrayUtilities.AreEqual<Byte>(LThisEncoding, LThatEncoding);
end;

function TX509Crl.GetHashCode: Int32;
var
  LEncoding: TCryptoLibByteArray;
begin
  if not FHashValueSet then
  begin
    LEncoding := GetCachedEncoding().GetEncoding();
    FHashValue := TArrayUtilities.GetArrayHashCode(LEncoding);
    FHashValueSet := True;
  end;
  Result := FHashValue;
end;

function TX509Crl.ToString: String;
var
  LBuf: TStringBuilder;
  LSig: TCryptoLibByteArray;
  I, LCount: Int32;
  LNext: TNullable<TDateTime>;
  LExtensions: IX509Extensions;
  LOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
  LObj: IAsn1Object;
  LDerInt: IDerInteger;
  LEntries: TCryptoLibGenericArray<IX509CrlEntry>;
  LEntry: IX509CrlEntry;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.Append('              Version: ').Append(GetVersion()).AppendLine();
    LBuf.Append('             IssuerDN: ').Append(GetIssuerDN().ToString()).AppendLine();
    LBuf.Append('          This update: ').Append(DateTimeToStr(GetThisUpdate())).AppendLine();
    LNext := GetNextUpdate();
    if LNext.HasValue then
      LBuf.Append('          Next update: ').Append(DateTimeToStr(LNext.Value)).AppendLine()
    else
      LBuf.Append('          Next update: null').AppendLine();
    LBuf.Append('  Signature Algorithm: ').Append(GetSigAlgName()).AppendLine();

    LSig := GetSignature();
    LBuf.Append('            Signature: ');
    LCount := Math.Min(20, System.Length(LSig));
    LBuf.AppendLine(THex.Encode(TArrayUtilities.CopyOfRange<Byte>(LSig, 0, LCount)));
    I := 20;
    while I < System.Length(LSig) do
    begin
      LCount := Math.Min(20, System.Length(LSig) - I);
      LBuf.Append('                       ').AppendLine(THex.Encode(TArrayUtilities.CopyOfRange<Byte>(LSig, I, I + LCount)));
      System.Inc(I, 20);
    end;

    LExtensions := FCertificateList.TbsCertList.Extensions;
    if LExtensions <> nil then
    begin
      LOids := LExtensions.GetExtensionOids();
      if System.Length(LOids) > 0 then
      begin
        LBuf.AppendLine('           Extensions:');
        for LOid in LOids do
        begin
          LExt := LExtensions.GetExtension(LOid);
          if (LExt <> nil) and (LExt.Value <> nil) then
          begin
            LObj := TX509ExtensionUtilities.FromExtensionValue(LExt.Value);
            LBuf.Append('                       critical(').Append(BoolToStr(LExt.IsCritical, True)).Append(') ');
            try
              if LOid.Equals(TX509Extensions.CrlNumber) then
              begin
                LDerInt := TDerInteger.GetInstance(LObj);
                LBuf.Append(LDerInt.PositiveValue.ToString()).AppendLine();
              end
              else if LOid.Equals(TX509Extensions.DeltaCrlIndicator) then
              begin
                LDerInt := TDerInteger.GetInstance(LObj);
                LBuf.Append('Base CRL: ').Append(LDerInt.PositiveValue.ToString()).AppendLine();
              end
              else if LOid.Equals(TX509Extensions.IssuingDistributionPoint) then
                LBuf.Append(TIssuingDistributionPoint.GetInstance(LObj as IAsn1Sequence).ToString()).AppendLine()
              else if LOid.Equals(TX509Extensions.CrlDistributionPoints) then
                LBuf.Append(TCrlDistPoint.GetInstance(LObj as IAsn1Sequence).ToString()).AppendLine()
              else if LOid.Equals(TX509Extensions.FreshestCrl) then
                LBuf.Append(TCrlDistPoint.GetInstance(LObj as IAsn1Sequence).ToString()).AppendLine()
              else
              begin
                LBuf.Append(LOid.Id);
                LBuf.Append(' value = ').Append(TAsn1Dumper.DumpAsString(LObj)).AppendLine();
              end;
            except
              LBuf.Append(LOid.Id);
              LBuf.Append(' value = *****').AppendLine();
            end;
          end
          else
            LBuf.AppendLine();
        end;
      end;
    end;

    LEntries := GetRevokedCertificates();
    if LEntries <> nil then
      for LEntry in LEntries do
      begin
        LBuf.Append(LEntry.ToString());
        LBuf.AppendLine();
      end;

    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

end.
