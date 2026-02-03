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

unit ClpX509V2AttributeCertificate;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  Generics.Collections,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIX509Attribute,
  ClpIX509V2AttributeCertificate,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactory,
  ClpIVerifierFactoryProvider,
  ClpX509ExtensionBase,
  ClpX509Attribute,
  ClpIAttributeCertificateHolder,
  ClpAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer,
  ClpAttributeCertificateIssuer,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpX509Asn1Objects,
  ClpX509Utilities,
  ClpAsn1VerifierFactory,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Implementation of X.509 V2 Attribute Certificate.
  /// </summary>
  TX509V2AttributeCertificate = class(TX509ExtensionBase, IX509V2AttributeCertificate)

  strict private
    FCert: IAttributeCertificate;
    FNotBefore: TDateTime;
    FNotAfter: TDateTime;

    class function GetObject(const AInput: TStream): IAttributeCertificate; static;
    function CheckSignatureValid(const AVerifier: IVerifierFactory): Boolean;
    procedure CheckSignature(const AVerifier: IVerifierFactory);

  strict protected
    function GetX509Extensions: IX509Extensions; override;
    function GetIsCritical: Boolean;
    function GetValue: IAsn1OctetString;
    function GetParsedValue: IAsn1Object;

  public
    constructor Create(const AEncIn: TStream); overload;
    constructor Create(const AEncoded: TCryptoLibByteArray); overload;
    constructor Create(const ACert: IAttributeCertificate); overload;

    function GetAttributeCertificate: IAttributeCertificate;
    function GetVersion: Int32;
    function GetSerialNumber: TBigInteger;
    function GetHolder: IAttributeCertificateHolder;
    function GetIssuer: IAttributeCertificateIssuer;
    function GetNotBefore: TDateTime;
    function GetNotAfter: TDateTime;

    function GetIssuerUniqueID: TCryptoLibBooleanArray;
    function IsValidNow: Boolean;
    function IsValid(const ADate: TDateTime): Boolean;
    procedure CheckValidity; overload;
    procedure CheckValidity(const ADate: TDateTime); overload;

    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: TCryptoLibByteArray;

    function IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    procedure Verify(const AKey: IAsymmetricKeyParameter); overload;
    procedure Verify(const AVerifierProvider: IVerifierFactoryProvider); overload;

    function GetEncoded: TCryptoLibByteArray;
    function GetAttributes: TCryptoLibGenericArray<IX509Attribute>; overload;
    function GetAttributes(const AOid: String): TCryptoLibGenericArray<IX509Attribute>; overload;

    function Equals(const AOther: IX509V2AttributeCertificate): Boolean;
    function GetHashCode: Int32; override;
  end;

implementation

{ TX509V2AttributeCertificate }

class function TX509V2AttributeCertificate.GetObject(const AInput: TStream)
  : IAttributeCertificate;
var
  LObj: IAsn1Object;
begin
  try
    LObj := TAsn1Object.FromStream(AInput);
    Result := TAttributeCertificate.GetInstance(LObj);
  except
    on E: EIOCryptoLibException do
      raise;
    on E: Exception do
      raise EIOCryptoLibException.Create('exception decoding certificate structure: ' + E.Message);
  end;
end;

constructor TX509V2AttributeCertificate.Create(const AEncIn: TStream);
begin
  Create(GetObject(AEncIn));
end;

constructor TX509V2AttributeCertificate.Create(const AEncoded: TCryptoLibByteArray);
var
  LStream: TMemoryStream;
begin
  LStream := TMemoryStream.Create;
  try
    if System.Length(AEncoded) > 0 then
      LStream.WriteBuffer(AEncoded[0], System.Length(AEncoded));
    LStream.Position := 0;
    Create(LStream);
  finally
    LStream.Free;
  end;
end;

constructor TX509V2AttributeCertificate.Create(const ACert: IAttributeCertificate);
begin
  inherited Create();
  FCert := ACert;
  try
    FNotBefore := ACert.ACInfo.AttrCertValidityPeriod.NotBeforeTime.ToDateTime;
    FNotAfter := ACert.ACInfo.AttrCertValidityPeriod.NotAfterTime.ToDateTime;
  except
    on E: Exception do
      raise EIOCryptoLibException.Create('invalid data structure in certificate!: ' + E.Message);
  end;
end;

function TX509V2AttributeCertificate.GetX509Extensions: IX509Extensions;
begin
  Result := FCert.ACInfo.Extensions;
end;

function TX509V2AttributeCertificate.GetIsCritical: Boolean;
begin
  raise ENotSupportedCryptoLibException.Create
    ('GetIsCritical not applicable to X509V2AttributeCertificate');
end;

function TX509V2AttributeCertificate.GetValue: IAsn1OctetString;
begin
  raise ENotSupportedCryptoLibException.Create
    ('GetValue not applicable to X509V2AttributeCertificate');
end;

function TX509V2AttributeCertificate.GetParsedValue: IAsn1Object;
begin
  raise ENotSupportedCryptoLibException.Create
    ('GetParsedValue not applicable to X509V2AttributeCertificate');
end;

function TX509V2AttributeCertificate.GetAttributeCertificate: IAttributeCertificate;
begin
  Result := FCert;
end;

function TX509V2AttributeCertificate.GetVersion: Int32;
begin
  Result := FCert.ACInfo.Version.IntValueExact + 1;
end;

function TX509V2AttributeCertificate.GetSerialNumber: TBigInteger;
begin
  Result := FCert.ACInfo.SerialNumber.Value;
end;

function TX509V2AttributeCertificate.GetHolder: IAttributeCertificateHolder;
var
  LSeq: IAsn1Sequence;
begin
  LSeq := TAsn1Sequence.GetInstance(FCert.ACInfo.Holder.ToAsn1Object);
  Result := TAttributeCertificateHolder.Create(LSeq);
end;

function TX509V2AttributeCertificate.GetIssuer: IAttributeCertificateIssuer;
begin
  Result := TAttributeCertificateIssuer.Create(FCert.ACInfo.Issuer);
end;

function TX509V2AttributeCertificate.GetNotBefore: TDateTime;
begin
  Result := FNotBefore;
end;

function TX509V2AttributeCertificate.GetNotAfter: TDateTime;
begin
  Result := FNotAfter;
end;

function TX509V2AttributeCertificate.GetIssuerUniqueID: TCryptoLibBooleanArray;
var
  LId: IDerBitString;
  LBytes: TCryptoLibByteArray;
  LLen, I: Int32;
begin
  LId := FCert.ACInfo.IssuerUniqueID;
  if LId = nil then
  begin
    Result := nil;
    Exit;
  end;
  LBytes := LId.GetOctets;
  LLen := System.Length(LBytes) * 8 - LId.PadBits;
  SetLength(Result, LLen);
  for I := 0 to LLen - 1 do
    Result[I] := (LBytes[I shr 3] and ($80 shr (I and 7))) <> 0;
end;

function TX509V2AttributeCertificate.IsValidNow: Boolean;
begin
  Result := IsValid(Now);
end;

function TX509V2AttributeCertificate.IsValid(const ADate: TDateTime): Boolean;
begin
  Result := (ADate >= FNotBefore) and (ADate <= FNotAfter);
end;

procedure TX509V2AttributeCertificate.CheckValidity;
begin
  CheckValidity(Now);
end;

procedure TX509V2AttributeCertificate.CheckValidity(const ADate: TDateTime);
begin
  if ADate > FNotAfter then
    raise EArgumentCryptoLibException.CreateFmt('certificate expired on %s',
      [DateToStr(FNotAfter)]);
  if ADate < FNotBefore then
    raise EArgumentCryptoLibException.CreateFmt('certificate not valid until %s',
      [DateToStr(FNotBefore)]);
end;

function TX509V2AttributeCertificate.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FCert.SignatureAlgorithm;
end;

function TX509V2AttributeCertificate.GetSignature: TCryptoLibByteArray;
begin
  Result := FCert.GetSignatureOctets;
end;

function TX509V2AttributeCertificate.CheckSignatureValid(const AVerifier
  : IVerifierFactory): Boolean;
begin
  if not TX509Utilities.AreEquivalentAlgorithms(FCert.SignatureAlgorithm,
    FCert.ACInfo.Signature) then
    raise ECertificateCryptoLibException.Create
      ('Signature algorithm in certificate info not same as outer certificate');
  Result := TX509Utilities.VerifySignature(AVerifier, FCert.ACInfo,
    FCert.SignatureValue);
end;

procedure TX509V2AttributeCertificate.CheckSignature(const AVerifier
  : IVerifierFactory);
begin
  if not CheckSignatureValid(AVerifier) then
    raise EInvalidKeyCryptoLibException.Create
      ('Public key presented not for certificate signature');
end;

function TX509V2AttributeCertificate.IsSignatureValid(const AKey
  : IAsymmetricKeyParameter): Boolean;
begin
  Result := CheckSignatureValid(TAsn1VerifierFactory.Create(FCert.SignatureAlgorithm, AKey) as IVerifierFactory);
end;

function TX509V2AttributeCertificate.IsSignatureValid(const AVerifierProvider
  : IVerifierFactoryProvider): Boolean;
begin
  Result := CheckSignatureValid(AVerifierProvider.CreateVerifierFactory(FCert.SignatureAlgorithm));
end;

procedure TX509V2AttributeCertificate.Verify(const AKey: IAsymmetricKeyParameter);
begin
  CheckSignature(TAsn1VerifierFactory.Create(FCert.SignatureAlgorithm, AKey) as IVerifierFactory);
end;

procedure TX509V2AttributeCertificate.Verify(const AVerifierProvider
  : IVerifierFactoryProvider);
begin
  CheckSignature(AVerifierProvider.CreateVerifierFactory(FCert.SignatureAlgorithm));
end;

function TX509V2AttributeCertificate.GetEncoded: TCryptoLibByteArray;
begin
  Result := FCert.ToAsn1Object.GetEncoded;
end;

function TX509V2AttributeCertificate.GetAttributes
  : TCryptoLibGenericArray<IX509Attribute>;
var
  LSeq: IAsn1Sequence;
  LList: TList<IX509Attribute>;
  I: Int32;
begin
  LSeq := FCert.ACInfo.Attributes;
  LList := TList<IX509Attribute>.Create;
  try
    for I := 0 to LSeq.Count - 1 do
      LList.Add(TX509Attribute.Create(LSeq[I]) as IX509Attribute);
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TX509V2AttributeCertificate.GetAttributes(const AOid: String)
  : TCryptoLibGenericArray<IX509Attribute>;
var
  LSeq: IAsn1Sequence;
  LList: TList<IX509Attribute>;
  I: Int32;
  LAttr: IX509Attribute;
begin
  LSeq := FCert.ACInfo.Attributes;
  LList := TList<IX509Attribute>.Create;
  try
    for I := 0 to LSeq.Count - 1 do
    begin
      LAttr := TX509Attribute.Create(LSeq[I]);
      if LAttr.Oid = AOid then
        LList.Add(LAttr);
    end;
    if LList.Count < 1 then
      Result := nil
    else
      Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TX509V2AttributeCertificate.Equals(const AOther: IX509V2AttributeCertificate): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if Self = (AOther as TX509V2AttributeCertificate) then
  begin
    Result := True;
    Exit;
  end;
  Result := FCert.ToAsn1Object.Equals(AOther.AttributeCertificate.ToAsn1Object);
end;

function TX509V2AttributeCertificate.GetHashCode: Int32;
begin
  Result := FCert.ToAsn1Object.GetHashCode;
end;

end.
