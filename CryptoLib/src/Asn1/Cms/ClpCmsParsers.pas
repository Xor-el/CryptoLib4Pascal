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

unit ClpCmsParsers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Tags,
  ClpAsn1Objects,
  ClpAsn1Utilities,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Parsers,
  ClpICmsParsers,
  ClpPlatformUtilities,
  ClpCryptoLibExceptions;

resourcestring
  SCmsUnknownObjectEncountered = 'unknown object encountered: %s';
  SCmsGetCertsNotCalled = 'GetCerts() has not been called';
  SCmsGetCertsOrGetCrlsNotCalled = 'GetCerts() and/or GetCrls() has not been called';
  SSeqNil = 'seq cannot be nil';
  SCmsContentInfoParserExpectedContentType = 'ContentInfoParser: expected DerObjectIdentifier for content type';
  SObjNil = 'ASN.1 object cannot be nil';
  SCmsSignedDataParserExpectedVersion = 'SignedDataParser: expected DerInteger for version';
  SCmsSignedDataParserExpectedDigestAlgorithms = 'SignedDataParser: expected Asn1SetParser for digest algorithms';
  SCmsSignedDataParserExpectedEncapContentInfo = 'SignedDataParser: expected Asn1SequenceParser for encapsulated content info';
  SCmsSignedDataParserExpectedSignerInfos = 'SignedDataParser: expected Asn1SetParser for signer infos';


type

  /// <summary>
  /// CMS ContentInfo parser.
  /// </summary>
  TCmsContentInfoParser = class sealed(TInterfacedObject, ICmsContentInfoParser)
  strict private
  var
    FContentType: IDerObjectIdentifier;
    FContent: IAsn1TaggedObjectParser;

  strict protected
    function GetContentType: IDerObjectIdentifier;

  public
    constructor Create(const ASeq: IAsn1SequenceParser);

    function GetContent(ATag: Int32): IAsn1Convertible;

    property ContentType: IDerObjectIdentifier read GetContentType;
  end;

  /// <summary>
  /// CMS SignedData parser.
  /// </summary>
  TCmsSignedDataParser = class sealed(TInterfacedObject, ICmsSignedDataParser)
  strict private
  var
    FSeq: IAsn1SequenceParser;
    FVersion: IDerInteger;
    FNextObject: IAsn1Convertible;
    FCertsCalled: Boolean;
    FCrlsCalled: Boolean;

  strict protected
    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1SetParser;
    function GetEncapContentInfo: ICmsContentInfoParser;
    function GetCertificates: IAsn1SetParser;
    function GetCrls: IAsn1SetParser;
    function GetSignerInfos: IAsn1SetParser;

  public
    class function GetInstance(const AObj: TObject): ICmsSignedDataParser; static;

    constructor Create(const ASeq: IAsn1SequenceParser);

    property Version: IDerInteger read GetVersion;
  end;

implementation

{ TCmsContentInfoParser }

constructor TCmsContentInfoParser.Create(const ASeq: IAsn1SequenceParser);
var
  LObj: IAsn1Convertible;
  LTagged: IAsn1TaggedObjectParser;
begin
  Inherited Create();
  if ASeq = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSeqNil);

  LObj := ASeq.ReadObject();
  if not Supports(LObj, IDerObjectIdentifier, FContentType) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsContentInfoParserExpectedContentType);

  LObj := ASeq.ReadObject();
  if Supports(LObj, IAsn1TaggedObjectParser, LTagged) then
    FContent := LTagged
  else
    FContent := nil;
end;

function TCmsContentInfoParser.GetContentType: IDerObjectIdentifier;
begin
  Result := FContentType;
end;

function TCmsContentInfoParser.GetContent(ATag: Int32): IAsn1Convertible;
begin
  if FContent = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := TAsn1Utilities.ParseExplicitContextBaseObject(FContent, 0);
end;

{ TCmsSignedDataParser }

class function TCmsSignedDataParser.GetInstance(const AObj: TObject): ICmsSignedDataParser;
var
  LSeqParser: IAsn1SequenceParser;
  LSeq: IAsn1Sequence;
  LObj: IAsn1Convertible;
begin
  if AObj = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SObjNil);

  if Supports(AObj, IAsn1SequenceParser, LSeqParser) then
    Exit(TCmsSignedDataParser.Create(LSeqParser));

  if Supports(AObj, IAsn1Sequence, LSeq) then
    Exit(TCmsSignedDataParser.Create(LSeq.Parser));

  if Supports(AObj, IAsn1Convertible, LObj) then
  begin
    LSeq := TAsn1Sequence.GetInstance(LObj);
    if LSeq <> nil then
      Exit(TCmsSignedDataParser.Create(LSeq.Parser));
  end;

  raise EStreamCryptoLibException.CreateResFmt(@SCmsUnknownObjectEncountered,
    [TPlatformUtilities.GetTypeName(AObj)]);
end;

constructor TCmsSignedDataParser.Create(const ASeq: IAsn1SequenceParser);
var
  LObj: IAsn1Convertible;
begin
  Inherited Create();
  if ASeq = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSeqNil);
  FSeq := ASeq;
  LObj := ASeq.ReadObject();
  if not Supports(LObj, IDerInteger, FVersion) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsSignedDataParserExpectedVersion);
  FNextObject := nil;
  FCertsCalled := False;
  FCrlsCalled := False;
end;

function TCmsSignedDataParser.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TCmsSignedDataParser.GetDigestAlgorithms: IAsn1SetParser;
var
  LObj: IAsn1Convertible;
  LSetParser: IAsn1SetParser;
begin
  LObj := FSeq.ReadObject();
  if not Supports(LObj, IAsn1SetParser, LSetParser) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsSignedDataParserExpectedDigestAlgorithms);
  Result := LSetParser;
end;

function TCmsSignedDataParser.GetEncapContentInfo: ICmsContentInfoParser;
var
  LObj: IAsn1Convertible;
  LSeqParser: IAsn1SequenceParser;
begin
  LObj := FSeq.ReadObject();
  if not Supports(LObj, IAsn1SequenceParser, LSeqParser) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsSignedDataParserExpectedEncapContentInfo);
  Result := TCmsContentInfoParser.Create(LSeqParser);
end;

function TCmsSignedDataParser.GetCertificates: IAsn1SetParser;
var
  LTagged: IAsn1TaggedObjectParser;
  LSetParser: IAsn1SetParser;
  LObj: IAsn1Convertible;
begin
  FCertsCalled := True;
  if FNextObject = nil then
    FNextObject := FSeq.ReadObject();

  if Supports(FNextObject, IAsn1TaggedObjectParser, LTagged) and LTagged.HasContextTag(0) then
  begin
    LObj := LTagged.ParseBaseUniversal(False, TAsn1Tags.SetOf);
    if Supports(LObj, IAsn1SetParser, LSetParser) then
    begin
      FNextObject := nil;
      Result := LSetParser;
      Exit;
    end;
  end;
  Result := nil;
end;

function TCmsSignedDataParser.GetCrls: IAsn1SetParser;
var
  LTagged: IAsn1TaggedObjectParser;
  LSetParser: IAsn1SetParser;
  LObj: IAsn1Convertible;
begin
  if not FCertsCalled then
    raise EStreamCryptoLibException.CreateRes(@SCmsGetCertsNotCalled);

  FCrlsCalled := True;
  if FNextObject = nil then
    FNextObject := FSeq.ReadObject();

  if Supports(FNextObject, IAsn1TaggedObjectParser, LTagged) and LTagged.HasContextTag(1) then
  begin
    LObj := LTagged.ParseBaseUniversal(False, TAsn1Tags.SetOf);
    if Supports(LObj, IAsn1SetParser, LSetParser) then
    begin
      FNextObject := nil;
      Result := LSetParser;
      Exit;
    end;
  end;
  Result := nil;
end;

function TCmsSignedDataParser.GetSignerInfos: IAsn1SetParser;
var
  LSetParser: IAsn1SetParser;
begin
  if not FCertsCalled or not FCrlsCalled then
    raise EStreamCryptoLibException.CreateRes(@SCmsGetCertsOrGetCrlsNotCalled);

  if FNextObject = nil then
    FNextObject := FSeq.ReadObject();

  if not Supports(FNextObject, IAsn1SetParser, LSetParser) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsSignedDataParserExpectedSignerInfos);
  Result := LSetParser;
end;

end.
