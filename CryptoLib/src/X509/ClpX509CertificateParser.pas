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

unit ClpX509CertificateParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIX509CertificateParser,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpPemObjects,
  ClpIPemObjects,
  ClpAsn1Streams,
  ClpAsn1Utilities,
  ClpCryptoLibTypes,
  ClpStreams,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers;

type
  /// <summary>
  /// Class for dealing with X509 certificates.
  /// At the moment this will deal with "-----BEGIN CERTIFICATE-----" to "-----END CERTIFICATE-----"
  /// base 64 encoded certs, as well as the BER binaries of certificates and some classes of PKCS#7
  /// objects.
  /// </summary>
  TX509CertificateParser = class sealed(TInterfacedObject, IX509CertificateParser)
  strict private
  class var
    FPemCertParser: IPemParser;

  var
    FSData: IAsn1Set;
    FSDataObjectCount: Int32;
    FCurrentStream: TStream;

    class constructor Boot();
    class procedure InitializePemCertParser();

    function ReadDerCertificate(const ADIn: TAsn1InputStream): IX509Certificate;
    function ReadPemCertificate(const AInStream: TStream): IX509Certificate;
    function GetCertificate(): IX509Certificate;

  public
    constructor Create();
    destructor Destroy(); override;

    function ReadCertificate(const AInput: TCryptoLibByteArray): IX509Certificate; overload;
    function ReadCertificates(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509Certificate>; overload;
    function ReadCertificate(const AInStream: TStream): IX509Certificate; overload;
    function ReadCertificates(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>; overload;
    function ParseCertificates(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>;
  end;

implementation

{ TX509CertificateParser }

class constructor TX509CertificateParser.Boot();
begin
  InitializePemCertParser();
end;

class procedure TX509CertificateParser.InitializePemCertParser();
begin
  FPemCertParser := TPemParser.Create('CERTIFICATE');
end;

constructor TX509CertificateParser.Create();
begin
  Inherited Create();
  FSData := nil;
  FSDataObjectCount := 0;
  FCurrentStream := nil;
end;

destructor TX509CertificateParser.Destroy();
begin
  Inherited Destroy();
end;

function TX509CertificateParser.ReadDerCertificate(const ADIn: TAsn1InputStream): IX509Certificate;
var
  LSeq: IAsn1Sequence;
  LContentType: IDerObjectIdentifier;
  LSignedData: ISignedData;
begin
  LSeq := ADIn.ReadObject() as IAsn1Sequence;

  if (LSeq.Count > 1) and Supports(LSeq[0], IDerObjectIdentifier, LContentType) then
  begin
    if LContentType.Equals(TPkcsObjectIdentifiers.SignedData) then
    begin
      if TAsn1Utilities.TryGetOptionalContextTagged<Boolean, ISignedData>(
        LSeq[1], 0, True, LSignedData,
        function(ATagged: IAsn1TaggedObject; AState: Boolean): ISignedData
        begin
          Result := TSignedData.GetTagged(ATagged, AState);
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

  Result := TX509Certificate.Create(TX509CertificateStructure.GetInstance(LSeq));
end;

function TX509CertificateParser.ReadPemCertificate(const AInStream: TStream): IX509Certificate;
var
  LSeq: IAsn1Sequence;
begin
  LSeq := FPemCertParser.ReadPemObject(AInStream);

  if LSeq = nil then
    Result := nil
  else
    Result := TX509Certificate.Create(TX509CertificateStructure.GetInstance(LSeq));
end;

function TX509CertificateParser.GetCertificate(): IX509Certificate;
var
  LCertificate: IX509CertificateStructure;
begin
  if FSData <> nil then
  begin
    while FSDataObjectCount < FSData.Count do
    begin
      LCertificate := TX509CertificateStructure.GetOptional(FSData[FSDataObjectCount]);
      System.Inc(FSDataObjectCount);
      if LCertificate <> nil then
      begin
        Result := TX509Certificate.Create(LCertificate);
        Exit;
      end;
    end;
  end;

  Result := nil;
end;

function TX509CertificateParser.ReadCertificate(const AInput: TCryptoLibByteArray): IX509Certificate;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadCertificate(LInStream);
  finally
    LInStream.Free();
  end;
end;

function TX509CertificateParser.ReadCertificates(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509Certificate>;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadCertificates(LInStream);
  finally
    LInStream.Free();
  end;
end;

function TX509CertificateParser.ReadCertificate(const AInStream: TStream): IX509Certificate;

  function ReadDerCertificateFromStream(const AStream: TStream): IX509Certificate;
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
  LPushbackStream := nil;
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
  else if FCurrentStream <> AInStream then // reset if input stream has changed
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
      // TODO[api] Consider removing this and continuing directly
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

        if LTag <> $30 then // assume ascii PEM encoded.
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

    if LTag <> $30 then // assume ascii PEM encoded.
    begin
      Result := ReadPemCertificate(LStreamToUse);
      Exit;
    end;

    Result := ReadDerCertificateFromStream(LStreamToUse);
  except
    on E: ECertificateCryptoLibException do
      raise;
    on E: Exception do
      raise ECertificateCryptoLibException.Create('Failed to read certificate: ' + E.Message);
  end;
end;

function TX509CertificateParser.ReadCertificates(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>;
var
  LCerts: TList<IX509Certificate>;
  LCert: IX509Certificate;
begin
  LCerts := TList<IX509Certificate>.Create();
  try
    LCert := ReadCertificate(AInStream);
    while LCert <> nil do
    begin
      LCerts.Add(LCert);
      LCert := ReadCertificate(AInStream);
    end;
    Result := LCerts.ToArray();
  finally
    LCerts.Free();
  end;
end;

function TX509CertificateParser.ParseCertificates(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>;
begin
  Result := ReadCertificates(AInStream);
end;

end.
