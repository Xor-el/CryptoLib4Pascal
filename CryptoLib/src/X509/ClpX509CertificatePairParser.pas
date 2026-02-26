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

unit ClpX509CertificatePairParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIX509CertificatePairParser,
  ClpIX509CertificatePair,
  ClpX509CertificatePair,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpAsn1Streams,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpStreams,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

type
  TX509CertificatePairParser = class sealed(TInterfacedObject, IX509CertificatePairParser)
  strict private
  var
    FCurrentStream: TStream;

    function ReadDerCrossCertificatePair(const AInStream: TStream): IX509CertificatePair;

  public
    constructor Create();
    destructor Destroy(); override;

    function ReadCertificatePair(const AInput: TCryptoLibByteArray): IX509CertificatePair; overload;
    function ReadCertificatePairs(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509CertificatePair>; overload;
    function ReadCertificatePair(const AInStream: TStream): IX509CertificatePair; overload;
    function ReadCertificatePairs(const AInStream: TStream): TCryptoLibGenericArray<IX509CertificatePair>; overload;
  end;

implementation

{ TX509CertificatePairParser }

constructor TX509CertificatePairParser.Create();
begin
  inherited Create();
  FCurrentStream := nil;
end;

destructor TX509CertificatePairParser.Destroy();
begin
  FCurrentStream := nil;
  inherited Destroy();
end;

function TX509CertificatePairParser.ReadDerCrossCertificatePair(const AInStream: TStream): IX509CertificatePair;
var
  LAsn1In: TAsn1InputStream;
  LObj: IAsn1Object;
  LPair: ICertificatePair;
begin
  LAsn1In := TAsn1InputStream.Create(AInStream, Int32.MaxValue, True);
  try
    LObj := LAsn1In.ReadObject();
    if LObj = nil then
      Result := nil
    else
    begin
      LPair := TCertificatePair.GetInstance(LObj);
      if LPair = nil then
        Result := nil
      else
        Result := TX509CertificatePair.Create(LPair);
    end;
  finally
    LAsn1In.Free;
  end;
end;

function TX509CertificatePairParser.ReadCertificatePair(const AInput: TCryptoLibByteArray): IX509CertificatePair;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadCertificatePair(LInStream);
  finally
    LInStream.Free;
    FCurrentStream := nil;
  end;
end;

function TX509CertificatePairParser.ReadCertificatePairs(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509CertificatePair>;
var
  LInStream: TMemoryStream;
begin
  LInStream := TMemoryStream.Create();
  try
    if System.Length(AInput) > 0 then
      LInStream.Write(AInput[0], System.Length(AInput));
    LInStream.Position := 0;
    Result := ReadCertificatePairs(LInStream);
  finally
    LInStream.Free;
    FCurrentStream := nil;
  end;
end;

function TX509CertificatePairParser.ReadCertificatePair(const AInStream: TStream): IX509CertificatePair;
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
    FCurrentStream := AInStream
  else if FCurrentStream <> AInStream then
    FCurrentStream := AInStream;

  try
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
      Result := ReadDerCrossCertificatePair(LStreamToUse);
    end
    else
    begin
      LPushbackStream := TPushbackStream.Create(AInStream);
      try
        LByte := Byte(LTag);
        LPushbackStream.UnRead(Int32(LByte));
        LStreamToUse := LPushbackStream;
        Result := ReadDerCrossCertificatePair(LStreamToUse);
      finally
        LPushbackStream.Free;
      end;
    end;
  except
    on E: ECertificateCryptoLibException do
      raise;
    on E: Exception do
      raise ECertificateCryptoLibException.Create('Failed to read certificate pair: ' + E.Message);
  end;
end;

function TX509CertificatePairParser.ReadCertificatePairs(const AInStream: TStream): TCryptoLibGenericArray<IX509CertificatePair>;
var
  LCertPairs: TList<IX509CertificatePair>;
  LCertPair: IX509CertificatePair;
begin
  LCertPairs := TList<IX509CertificatePair>.Create();
  try
    LCertPair := ReadCertificatePair(AInStream);
    while LCertPair <> nil do
    begin
      LCertPairs.Add(LCertPair);
      LCertPair := ReadCertificatePair(AInStream);
    end;
    Result := LCertPairs.ToArray();
  finally
    LCertPairs.Free;
  end;
end;

end.
