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

unit ClpX509CrlParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIX509CrlParser,
  ClpIX509Crl,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509Crl,
  ClpPemObjects,
  ClpIPemObjects,
  ClpAsn1Streams,
  ClpAsn1Utilities,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpStreams,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

type
  TX509CrlParser = class sealed(TInterfacedObject, IX509CrlParser)
  strict private
  class var
    FPemCrlParser: IPemParser;

  var
    FSCrlData: IAsn1Set;
    FSCrlDataObjectCount: Int32;
    FCurrentCrlStream: TStream;

  class constructor Create();
  class procedure Boot();

  function ReadDerCrl(const ADIn: TAsn1InputStream): IX509Crl;
  function ReadPemCrl(const AInStream: TStream): IX509Crl;
  function GetCrl(): IX509Crl;

  public
    constructor Create();
    destructor Destroy(); override;

    function ReadCrl(const AInput: TCryptoLibByteArray): IX509Crl; overload;
    function ReadCrls(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509Crl>; overload;
    function ReadCrl(const AInStream: TStream): IX509Crl; overload;
    function ReadCrls(const AInStream: TStream): TCryptoLibGenericArray<IX509Crl>; overload;
    function ParseCrls(const AInStream: TStream): TCryptoLibGenericArray<IX509Crl>;
  end;

implementation

{ TX509CrlParser }

class constructor TX509CrlParser.Create();
begin
  Boot();
end;

class procedure TX509CrlParser.Boot();
begin
  FPemCrlParser := TPemParser.Create('CRL');
end;

constructor TX509CrlParser.Create();
begin
  inherited Create();
  FSCrlData := nil;
  FSCrlDataObjectCount := 0;
  FCurrentCrlStream := nil;
end;

destructor TX509CrlParser.Destroy();
begin
  inherited Destroy();
end;

function TX509CrlParser.ReadDerCrl(const ADIn: TAsn1InputStream): IX509Crl;
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
        FSCrlData := LSignedData.Crls;
        FSCrlDataObjectCount := 0;
        Result := GetCrl();
        Exit;
      end;
    end;
  end;

  Result := TX509Crl.Create(TCertificateList.GetInstance(LSeq));
end;

function TX509CrlParser.ReadPemCrl(const AInStream: TStream): IX509Crl;
var
  LSeq: IAsn1Sequence;
begin
  LSeq := FPemCrlParser.ReadPemObject(AInStream);

  if LSeq = nil then
    Result := nil
  else
    Result := TX509Crl.Create(TCertificateList.GetInstance(LSeq));
end;

function TX509CrlParser.GetCrl(): IX509Crl;
var
  LCertList: ICertificateList;
begin
  if (FSCrlData = nil) or (FSCrlDataObjectCount >= FSCrlData.Count) then
  begin
    Result := nil;
    Exit;
  end;

  LCertList := TCertificateList.GetInstance(FSCrlData[FSCrlDataObjectCount]);
  System.Inc(FSCrlDataObjectCount);
  Result := TX509Crl.Create(LCertList);
end;

function TX509CrlParser.ReadCrl(const AInput: TCryptoLibByteArray): IX509Crl;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadCrl(LInStream);
  finally
    LInStream.Free();
  end;
end;

function TX509CrlParser.ReadCrls(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509Crl>;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadCrls(LInStream);
  finally
    LInStream.Free();
  end;
end;

function TX509CrlParser.ReadCrl(const AInStream: TStream): IX509Crl;

  function ReadDerCrlFromStream(const AStream: TStream): IX509Crl;
  var
    LAsn1In: TAsn1InputStream;
  begin
    LAsn1In := TAsn1InputStream.Create(AStream, Int32.MaxValue, True);
    try
      Result := ReadDerCrl(LAsn1In);
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

  if FCurrentCrlStream = nil then
  begin
    FCurrentCrlStream := AInStream;
    FSCrlData := nil;
    FSCrlDataObjectCount := 0;
  end
  else if FCurrentCrlStream <> AInStream then
  begin
    FCurrentCrlStream := AInStream;
    FSCrlData := nil;
    FSCrlDataObjectCount := 0;
  end;

  try
    if FSCrlData <> nil then
    begin
      if FSCrlDataObjectCount <> FSCrlData.Count then
      begin
        Result := GetCrl();
        Exit;
      end;

      FSCrlData := nil;
      FSCrlDataObjectCount := 0;
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
          Result := ReadPemCrl(LStreamToUse);
          Exit;
        end;

        Result := ReadDerCrlFromStream(LStreamToUse);
      finally
        LPushbackStream.Free();
      end;
      Exit;
    end;

    if LTag <> $30 then
    begin
      Result := ReadPemCrl(LStreamToUse);
      Exit;
    end;

    Result := ReadDerCrlFromStream(LStreamToUse);
  except
    on E: ECrlCryptoLibException do
      raise;
    on E: Exception do
      raise ECrlCryptoLibException.Create('Failed to read CRL: ' + E.Message);
  end;
end;

function TX509CrlParser.ReadCrls(const AInStream: TStream): TCryptoLibGenericArray<IX509Crl>;
begin
  Result := ParseCrls(AInStream);
end;

function TX509CrlParser.ParseCrls(const AInStream: TStream): TCryptoLibGenericArray<IX509Crl>;
var
  LCrls: TList<IX509Crl>;
  LCrl: IX509Crl;
begin
  LCrls := TList<IX509Crl>.Create();
  try
    LCrl := ReadCrl(AInStream);
    while LCrl <> nil do
    begin
      LCrls.Add(LCrl);
      LCrl := ReadCrl(AInStream);
    end;
    Result := LCrls.ToArray();
  finally
    LCrls.Free();
  end;
end;

end.
