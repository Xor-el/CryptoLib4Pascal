{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpPkixCertPath;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIPkixTypes,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpAsn1Streams,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpICmsAsn1Objects,
  ClpCmsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpX509CertificateParser,
  ClpIPemObject,
  ClpPemObject,
  ClpPemWriter,
  ClpCryptoLibTypes;

resourcestring
  SPkiPathNotSequence = 'input stream does not contain an ASN.1 SEQUENCE while reading a PkiPath encoded path';
  SUnsupportedCertPathEncoding = 'unsupported encoding: %s';
  SCertPathDecodeFailed = 'failed to decode certification path: %s';
  SCertPathEncodeFailed = 'failed to encode certification path: %s';

type
  /// <summary>
  /// An immutable certification path of X.509 certificates, ordered from the target certificate
  /// towards (but excluding) the trust anchor.
  /// </summary>
  TPkixCertPath = class(TInterfacedObject, IPkixCertPath)

  strict private
  const
    PkiPathEncoding = 'PkiPath';
    PemEncoding = 'PEM';
    Pkcs7Encoding = 'PKCS7';

  var
    FCertificates: TCryptoLibGenericArray<IX509Certificate>;

    class function SortCerts(const ACerts: TCryptoLibGenericArray<IX509Certificate>)
      : TCryptoLibGenericArray<IX509Certificate>; static;
    class function ReadPkiPath(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>; static;
    class function ToAsn1Object(const ACert: IX509Certificate): IAsn1Object; static;
    class function ToDerEncoded(const AObj: IAsn1Encodable): TCryptoLibByteArray; static;

    function EncodePkiPath: TCryptoLibByteArray;
    function EncodePkcs7: TCryptoLibByteArray;
    function EncodePem: TCryptoLibByteArray;

  strict protected
    function GetCertificates: TCryptoLibGenericArray<IX509Certificate>;

  public
    constructor Create(const ACertificates: TCryptoLibGenericArray<IX509Certificate>); overload;
    constructor Create(const AInStream: TStream); overload;
    constructor Create(const AInStream: TStream; const AEncoding: String); overload;

    function GetEncodings: TCryptoLibStringArray;
    function GetEncoded: TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String): TCryptoLibByteArray; overload;

    function Equals(const AOther: IPkixCertPath): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
  end;

implementation

{ TPkixCertPath }

constructor TPkixCertPath.Create(const ACertificates: TCryptoLibGenericArray<IX509Certificate>);
begin
  inherited Create();
  FCertificates := SortCerts(System.Copy(ACertificates));
end;

constructor TPkixCertPath.Create(const AInStream: TStream);
begin
  Create(AInStream, PkiPathEncoding);
end;

constructor TPkixCertPath.Create(const AInStream: TStream; const AEncoding: String);
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LParser: TX509CertificateParser;
begin
  inherited Create();
  try
    if SameText(PkiPathEncoding, AEncoding) then
    begin
      LCerts := ReadPkiPath(AInStream);
    end
    else if SameText(PemEncoding, AEncoding) or SameText(Pkcs7Encoding, AEncoding) then
    begin
      LParser := TX509CertificateParser.Create();
      try
        LCerts := LParser.ReadCertificates(AInStream);
      finally
        LParser.Free;
      end;
    end
    else
    begin
      raise ECertificateCryptoLibException.CreateResFmt(@SUnsupportedCertPathEncoding, [AEncoding]);
    end;
  except
    on E: ECertificateCryptoLibException do
      raise;
    on E: Exception do
      raise ECertificateCryptoLibException.CreateResFmt(@SCertPathDecodeFailed, [E.Message]);
  end;

  FCertificates := SortCerts(LCerts);
end;

class function TPkixCertPath.ReadPkiPath(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>;
var
  LAsn1In: TAsn1InputStream;
  LObj: IAsn1Object;
  LSeq: IAsn1Sequence;
  LCount, LIdx: Int32;
begin
  LAsn1In := TAsn1InputStream.Create(AInStream, True);
  try
    LObj := LAsn1In.ReadObject();
  finally
    LAsn1In.Free;
  end;

  LSeq := TAsn1Sequence.GetOptional(LObj);
  if LSeq = nil then
    raise ECertificateCryptoLibException.CreateRes(@SPkiPathNotSequence);

  // a PkiPath is ordered trust-anchor-first, the reverse of a certification path
  LCount := LSeq.Count;
  System.SetLength(Result, LCount);
  for LIdx := 0 to LCount - 1 do
  begin
    Result[LCount - 1 - LIdx] := TX509Certificate.Create
      (TX509CertificateStructure.GetInstance(LSeq[LIdx].ToAsn1Object()));
  end;
end;

class function TPkixCertPath.SortCerts(const ACerts: TCryptoLibGenericArray<IX509Certificate>)
  : TCryptoLibGenericArray<IX509Certificate>;
var
  LCount, LIdx, LInner, LResultCount, LRemaining: Int32;
  LIssuer, LSubject: IX509Name;
  LOkay, LFound: Boolean;
  LPool, LOrdered: TCryptoLibGenericArray<IX509Certificate>;
begin
  LCount := System.Length(ACerts);
  if LCount < 2 then
  begin
    Result := ACerts;
    Exit;
  end;

  LIssuer := ACerts[0].IssuerDN;
  LOkay := True;
  for LIdx := 1 to LCount - 1 do
  begin
    if LIssuer.Equivalent(ACerts[LIdx].SubjectDN, True) then
      LIssuer := ACerts[LIdx].IssuerDN
    else
    begin
      LOkay := False;
      Break;
    end;
  end;

  if LOkay then
  begin
    Result := ACerts;
    Exit;
  end;

  // nil entries in LPool mark certificates already placed in LOrdered
  LPool := System.Copy(ACerts);
  System.SetLength(LOrdered, LCount);
  LResultCount := 0;

  // the end-entity certificate is the one no other certificate was issued by
  for LIdx := 0 to LCount - 1 do
  begin
    LSubject := ACerts[LIdx].SubjectDN;
    LFound := False;
    for LInner := 0 to LCount - 1 do
    begin
      if ACerts[LInner].IssuerDN.Equivalent(LSubject, True) then
      begin
        LFound := True;
        Break;
      end;
    end;

    if not LFound then
    begin
      if LResultCount > 0 then
      begin
        // more than one end-entity certificate, the input is not a single path
        Result := ACerts;
        Exit;
      end;
      LOrdered[LResultCount] := ACerts[LIdx];
      System.Inc(LResultCount);
      LPool[LIdx] := nil;
    end;
  end;

  if LResultCount = 0 then
  begin
    Result := ACerts;
    Exit;
  end;

  LIdx := 0;
  while LIdx < LResultCount do
  begin
    LIssuer := LOrdered[LIdx].IssuerDN;
    for LInner := 0 to LCount - 1 do
    begin
      if (LPool[LInner] <> nil) and LIssuer.Equivalent(LPool[LInner].SubjectDN, True) then
      begin
        LOrdered[LResultCount] := LPool[LInner];
        System.Inc(LResultCount);
        LPool[LInner] := nil;
        Break;
      end;
    end;
    System.Inc(LIdx);
  end;

  LRemaining := 0;
  for LIdx := 0 to LCount - 1 do
  begin
    if LPool[LIdx] <> nil then
      System.Inc(LRemaining);
  end;

  // some certificates could not be chained, leave the input order alone
  if LRemaining > 0 then
  begin
    Result := ACerts;
    Exit;
  end;

  Result := LOrdered;
end;

function TPkixCertPath.GetCertificates: TCryptoLibGenericArray<IX509Certificate>;
begin
  Result := System.Copy(FCertificates);
end;

function TPkixCertPath.GetEncodings: TCryptoLibStringArray;
begin
  Result := TCryptoLibStringArray.Create(PkiPathEncoding, PemEncoding, Pkcs7Encoding);
end;

class function TPkixCertPath.ToAsn1Object(const ACert: IX509Certificate): IAsn1Object;
begin
  try
    Result := ACert.CertificateStructure.ToAsn1Object();
  except
    on E: Exception do
      raise ECertificateCryptoLibException.CreateResFmt(@SCertPathEncodeFailed, [E.Message]);
  end;
end;

class function TPkixCertPath.ToDerEncoded(const AObj: IAsn1Encodable): TCryptoLibByteArray;
begin
  try
    Result := AObj.GetEncoded(TAsn1Encodable.Der);
  except
    on E: Exception do
      raise ECertificateCryptoLibException.CreateResFmt(@SCertPathEncodeFailed, [E.Message]);
  end;
end;

function TPkixCertPath.EncodePkiPath: TCryptoLibByteArray;
var
  LVector: IAsn1EncodableVector;
  LIdx: Int32;
begin
  LVector := TAsn1EncodableVector.Create(System.Length(FCertificates));
  for LIdx := System.High(FCertificates) downto 0 do
  begin
    LVector.Add(ToAsn1Object(FCertificates[LIdx]));
  end;
  Result := ToDerEncoded(TDerSequence.Create(LVector) as IAsn1Encodable);
end;

function TPkixCertPath.EncodePkcs7: TCryptoLibByteArray;
var
  LVector: IAsn1EncodableVector;
  LIdx: Int32;
  LEncInfo: ICmsContentInfo;
  LSignedData: ICmsSignedData;
begin
  LEncInfo := TCmsContentInfo.Create(TPkcsObjectIdentifiers.Data, nil);

  LVector := TAsn1EncodableVector.Create(System.Length(FCertificates));
  for LIdx := 0 to System.High(FCertificates) do
  begin
    LVector.Add(ToAsn1Object(FCertificates[LIdx]));
  end;

  LSignedData := TCmsSignedData.Create(TDerSet.Create() as IAsn1Set, LEncInfo,
    TDerSet.Create(LVector) as IAsn1Set, nil, TDerSet.Create() as IAsn1Set);

  Result := ToDerEncoded(TCmsContentInfo.Create(TPkcsObjectIdentifiers.SignedData, LSignedData)
    as IAsn1Encodable);
end;

function TPkixCertPath.EncodePem: TCryptoLibByteArray;
var
  LOutput: TMemoryStream;
  LWriter: TPemWriter;
  LIdx: Int32;
begin
  LOutput := TMemoryStream.Create();
  try
    LWriter := TPemWriter.Create(LOutput);
    try
      for LIdx := 0 to System.High(FCertificates) do
      begin
        LWriter.WriteObject(TPemObject.Create('CERTIFICATE', FCertificates[LIdx].GetEncoded())
          as IPemObjectGenerator);
      end;
    finally
      LWriter.Free;
    end;
    System.SetLength(Result, LOutput.Size);
    if LOutput.Size > 0 then
    begin
      LOutput.Position := 0;
      LOutput.ReadBuffer(Result[0], LOutput.Size);
    end;
  finally
    LOutput.Free;
  end;
end;

function TPkixCertPath.GetEncoded: TCryptoLibByteArray;
begin
  Result := GetEncoded(PkiPathEncoding);
end;

function TPkixCertPath.GetEncoded(const AEncoding: String): TCryptoLibByteArray;
begin
  if SameText(AEncoding, PkiPathEncoding) then
    Result := EncodePkiPath()
  else if SameText(AEncoding, Pkcs7Encoding) then
    Result := EncodePkcs7()
  else if SameText(AEncoding, PemEncoding) then
    Result := EncodePem()
  else
    raise ECertificateCryptoLibException.CreateResFmt(@SUnsupportedCertPathEncoding, [AEncoding]);
end;

function TPkixCertPath.Equals(const AOther: IPkixCertPath): Boolean;
var
  LOtherCerts: TCryptoLibGenericArray<IX509Certificate>;
  LIdx: Int32;
begin
  Result := False;

  if AOther = nil then
    Exit;

  if (Self as IPkixCertPath) = AOther then
  begin
    Result := True;
    Exit;
  end;

  LOtherCerts := AOther.Certificates;
  if System.Length(LOtherCerts) <> System.Length(FCertificates) then
    Exit;

  for LIdx := 0 to System.High(FCertificates) do
  begin
    if not FCertificates[LIdx].Equals(LOtherCerts[LIdx]) then
      Exit;
  end;

  Result := True;
end;

function TPkixCertPath.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
var
  LIdx: Int32;
  LHash: Int32;
begin
  LHash := System.Length(FCertificates) + 1;
  for LIdx := 0 to System.High(FCertificates) do
  begin
    LHash := (LHash * 257) xor FCertificates[LIdx].GetHashCode;
  end;
  Result := LHash;
end;

end.
