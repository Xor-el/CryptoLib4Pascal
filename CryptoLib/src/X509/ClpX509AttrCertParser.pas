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

unit ClpX509AttrCertParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIX509AttrCertParser,
  ClpIX509V2AttributeCertificate,
  ClpX509V2AttributeCertificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpPemObjects,
  ClpIPemObjects,
  ClpAsn1Streams,
  ClpAsn1Utilities,
  ClpCryptoLibTypes,
  ClpStreams,
  ClpStreamUtilities,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers;

type
  /// <summary>
  /// Class for dealing with X509 Attribute Certificates.
  /// At the moment this will deal with "-----BEGIN ATTRIBUTE CERTIFICATE-----" to
  /// "-----END ATTRIBUTE CERTIFICATE-----" base 64 encoded attribute certs, as well
  /// as the BER binaries of attribute certificates and some classes of PKCS#7 objects.
  /// </summary>
  TX509AttrCertParser = class sealed(TInterfacedObject, IX509AttrCertParser)
  strict private
  class var
    FPemAttrCertParser: IPemParser;

  var
    FSData: IAsn1Set;
    FSDataObjectCount: Int32;
    FCurrentStream: TStream;

    class constructor Create();
    class procedure Boot();

    function ReadDerCertificate(const ADIn: TAsn1InputStream): IX509V2AttributeCertificate;
    function ReadPemCertificate(const AInStream: TStream): IX509V2AttributeCertificate;
    function GetCertificate(): IX509V2AttributeCertificate;

  public
    constructor Create();
    destructor Destroy(); override;

    function ReadAttrCert(const AInput: TCryptoLibByteArray): IX509V2AttributeCertificate; overload;
    function ReadAttrCerts(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509V2AttributeCertificate>; overload;
    function ReadAttrCert(const AInStream: TStream): IX509V2AttributeCertificate; overload;
    function ReadAttrCerts(const AInStream: TStream): TCryptoLibGenericArray<IX509V2AttributeCertificate>; overload;
    function ParseAttrCerts(const AInStream: TStream): TCryptoLibGenericArray<IX509V2AttributeCertificate>;
  end;

implementation

{ TX509AttrCertParser }

class constructor TX509AttrCertParser.Create();
begin
  Boot();
end;

class procedure TX509AttrCertParser.Boot();
begin
  FPemAttrCertParser := TPemParser.Create('ATTRIBUTE CERTIFICATE');
end;

constructor TX509AttrCertParser.Create();
begin
  inherited Create();
  FSData := nil;
  FSDataObjectCount := 0;
  FCurrentStream := nil;
end;

destructor TX509AttrCertParser.Destroy();
begin
  inherited Destroy();
end;

function TX509AttrCertParser.ReadDerCertificate(const ADIn: TAsn1InputStream): IX509V2AttributeCertificate;
var
  LSeq: IAsn1Sequence;
  LContentType: IDerObjectIdentifier;
  LSignedData: IPkcsSignedData;
begin
  LSeq := ADIn.ReadObject() as IAsn1Sequence;

  if (LSeq.Count > 1) and Supports(LSeq[0], IDerObjectIdentifier, LContentType) then
  begin
    if LContentType.Equals(TPkcsObjectIdentifiers.SignedData) then
    begin
      if TAsn1Utilities.TryGetOptionalContextTagged<Boolean, IPkcsSignedData>(
        LSeq[1], 0, True, LSignedData,
        function(ATagged: IAsn1TaggedObject; AState: Boolean): IPkcsSignedData
        begin
          Result := TPkcsSignedData.GetTagged(ATagged, AState);
        end) then
      begin
        FSData := LSignedData.Certificates;
        if FSData <> nil then
        begin
          FSDataObjectCount := 0;
          Result := GetCertificate();
          Exit;
        end;
      end;
    end;
  end;

  Result := TX509V2AttributeCertificate.Create(TAttributeCertificate.GetInstance(LSeq));
end;

function TX509AttrCertParser.ReadPemCertificate(const AInStream: TStream): IX509V2AttributeCertificate;
var
  LSeq: IAsn1Sequence;
begin
  LSeq := FPemAttrCertParser.ReadPemObject(AInStream);

  if LSeq = nil then
    Result := nil
  else
    Result := TX509V2AttributeCertificate.Create(TAttributeCertificate.GetInstance(LSeq));
end;

function TX509AttrCertParser.GetCertificate(): IX509V2AttributeCertificate;
var
  LAttributeCertificate: IAttributeCertificate;
  LElement: IAsn1Encodable;
begin
  if FSData <> nil then
  begin
    while FSDataObjectCount < FSData.Count do
    begin
      LElement := FSData[FSDataObjectCount];
      System.Inc(FSDataObjectCount);
      if TAsn1Utilities.TryGetOptionalContextTagged<Boolean, IAttributeCertificate>(
        LElement, 2, False, LAttributeCertificate,
        function(ATagged: IAsn1TaggedObject; AState: Boolean): IAttributeCertificate
        begin
          Result := TAttributeCertificate.GetTagged(ATagged, AState);
        end) then
      begin
        Result := TX509V2AttributeCertificate.Create(LAttributeCertificate);
        Exit;
      end;
    end;
  end;

  Result := nil;
end;

function TX509AttrCertParser.ReadAttrCert(const AInput: TCryptoLibByteArray): IX509V2AttributeCertificate;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadAttrCert(LInStream);
  finally
    LInStream.Free();
  end;
end;

function TX509AttrCertParser.ReadAttrCerts(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509V2AttributeCertificate>;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadAttrCerts(LInStream);
  finally
    LInStream.Free();
  end;
end;

function TX509AttrCertParser.ReadAttrCert(const AInStream: TStream): IX509V2AttributeCertificate;

  function ReadDerCertificateFromStream(const AStream: TStream): IX509V2AttributeCertificate;
  var
    LAsn1In: TAsn1InputStream;
  begin
    LAsn1In := TAsn1InputStream.Create(AStream, Int32.MaxValue, True);
    try
      Result := ReadDerCertificate(LAsn1In);
    finally
      LAsn1In.Free();
    end;
  end;

var
  LTag: Int32;
  LByte: Byte;
  LPushbackStream: TPushbackStream;
  LStreamToUse: TStream;
begin
  if AInStream = nil then
    raise EArgumentNilCryptoLibException.Create('inStream');

  if not AInStream.CanRead then
    raise EArgumentCryptoLibException.Create('Stream must be read-able');

  if FCurrentStream = nil then
  begin
    FCurrentStream := AInStream;
    FSData := nil;
    FSDataObjectCount := 0;
  end
  else if FCurrentStream <> AInStream then
  begin
    FCurrentStream := AInStream;
    FSData := nil;
    FSDataObjectCount := 0;
  end;

  try
    if FSData <> nil then
    begin
      if FSDataObjectCount <> FSData.Count then
      begin
        Result := GetCertificate();
        Exit;
      end;

      FSData := nil;
      FSDataObjectCount := 0;
      Result := nil;
      Exit;
    end;

    LTag := AInStream.ReadByte();
    if LTag < 0 then
    begin
      Result := nil;
      Exit;
    end;

    if AInStream.CanSeek then
    begin
      AInStream.Seek(-1, TSeekOrigin.soCurrent);
      LStreamToUse := AInStream;
    end
    else
    begin
      LPushbackStream := TPushbackStream.Create(AInStream);
      try
        LByte := Byte(LTag);
        LPushbackStream.UnRead(Int32(LByte));
        LStreamToUse := LPushbackStream;

        if LTag <> $30 then
        begin
          Result := ReadPemCertificate(LStreamToUse);
          Exit;
        end;

        Result := ReadDerCertificateFromStream(LStreamToUse);
      finally
        LPushbackStream.Free();
      end;
      Exit;
    end;

    if LTag <> $30 then
    begin
      Result := ReadPemCertificate(LStreamToUse);
      Exit;
    end;

    Result := ReadDerCertificateFromStream(LStreamToUse);
  except
    on E: ECertificateCryptoLibException do
      raise;
    on E: Exception do
      raise ECertificateCryptoLibException.Create('Failed to read attribute certificate: ' + E.Message);
  end;
end;

function TX509AttrCertParser.ReadAttrCerts(const AInStream: TStream): TCryptoLibGenericArray<IX509V2AttributeCertificate>;
begin
  Result := ParseAttrCerts(AInStream);
end;

function TX509AttrCertParser.ParseAttrCerts(const AInStream: TStream): TCryptoLibGenericArray<IX509V2AttributeCertificate>;
var
  LAttrCerts: TList<IX509V2AttributeCertificate>;
  LAttrCert: IX509V2AttributeCertificate;
begin
  LAttrCerts := TList<IX509V2AttributeCertificate>.Create();
  try
    LAttrCert := ReadAttrCert(AInStream);
    while LAttrCert <> nil do
    begin
      LAttrCerts.Add(LAttrCert);
      LAttrCert := ReadAttrCert(AInStream);
    end;
    Result := LAttrCerts.ToArray();
  finally
    LAttrCerts.Free();
  end;
end;

end.
