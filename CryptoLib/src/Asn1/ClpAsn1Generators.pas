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

unit ClpAsn1Generators;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIAsn1Generators,
  ClpIAsn1Core,
  ClpAsn1Tags,
  ClpAsn1Core,
  ClpAsn1Streams,
  ClpBitOperations,
  ClpStreamUtilities;

type
  /// <summary>
  /// Abstract base class for ASN.1 generators.
  /// </summary>
  TAsn1Generator = class abstract(TInterfacedObject, IAsn1Generator)
  strict private
    FOut: TStream;
    FClosed: Boolean;
  strict protected
    constructor Create(AOutStream: TStream);
    function GetOut: TStream; inline;
    function GetIsClosed: Boolean; inline;
    property &Out: TStream read GetOut;
    procedure Finish(); virtual; abstract;
    procedure DoClose();
  public
    destructor Destroy(); override;
    procedure AddObject(const AObj: IAsn1Encodable); overload; virtual; abstract;
    procedure AddObject(const AObj: IAsn1Object); overload; virtual; abstract;
    function GetRawOutputStream(): TStream; virtual; abstract;
    procedure Close(); virtual; abstract;
    property IsClosed: Boolean read GetIsClosed;
    class function InheritConstructedFlag(AIntoTag, AFromTag: Int32): Int32; static;
  end;

  /// <summary>
  /// Abstract base class for BER generators.
  /// </summary>
  TBerGenerator = class abstract(TAsn1Generator, IBerGenerator)
  strict private
    FTagged, FIsExplicit: Boolean;
    FTagNo: Int32;
  strict protected
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;

    procedure WriteHdr(ATag: Int32);
    procedure WriteBerHeader(ATag: Int32);
    procedure WriteBerBody(AContentStream: TStream);
    procedure WriteBerEnd();
    procedure Finish(); override;
  public
    procedure AddObject(const AObj: IAsn1Encodable); override;
    procedure AddObject(const AObj: IAsn1Object); override;
    function GetRawOutputStream(): TStream; override;
    procedure Close(); override;
  end;

  /// <summary>
  /// BER sequence generator.
  /// </summary>
  TBerSequenceGenerator = class(TBerGenerator, IBerSequenceGenerator)
  public
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
  end;

  /// <summary>
  /// BER octet string generator.
  /// </summary>
  TBerOctetStringGenerator = class(TBerGenerator, IBerOctetStringGenerator)
  public
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
    function GetOctetOutputStream(): TStream; overload;
    function GetOctetOutputStream(ABufSize: Int32): TStream; overload;
    function GetOctetOutputStream(const ABuf: TCryptoLibByteArray): TStream; overload;
  end;

  /// <summary>
  /// Abstract base class for DER generators.
  /// </summary>
  TDerGenerator = class abstract(TAsn1Generator, IDerGenerator)
  strict private
    FTagged, FIsExplicit: Boolean;
    FTagNo: Int32;
    class procedure WriteLength(const AOutStr: TStream; ALength: Int32); static;
  strict protected
    constructor Create(const AOutStream: TStream); overload;
    constructor Create(const AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
  public
    procedure WriteDerEncoded(ATag: Int32; const ABytes: TCryptoLibByteArray); overload;
    class procedure WriteDerEncoded(const AOutStream: TStream; ATag: Int32; const ABytes: TCryptoLibByteArray); overload; static;
    class procedure WriteDerEncoded(const AOutStr: TStream; ATag: Int32; const AInStr: TStream); overload; static;
  end;

  /// <summary>
  /// DER sequence generator.
  /// </summary>
  TDerSequenceGenerator = class(TDerGenerator, IDerSequenceGenerator)
  strict private
    FBOut: TMemoryStream;
  strict protected
    procedure Finish(); override;
  public
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
    destructor Destroy(); override;
    procedure AddObject(const AObj: IAsn1Encodable); overload; override;
    procedure AddObject(const AObj: IAsn1Object); overload; override;
    function GetRawOutputStream(): TStream; override;
    procedure Close(); override;
  end;

implementation

{ TAsn1Generator }

constructor TAsn1Generator.Create(AOutStream: TStream);
begin
  inherited Create;
  if AOutStream = nil then
    raise EArgumentNilCryptoLibException.Create('outStream');
  FOut := AOutStream;
  FClosed := False;
end;

destructor TAsn1Generator.Destroy;
begin
  DoClose();
  inherited Destroy;
end;

procedure TAsn1Generator.DoClose();
begin
  if (FOut <> nil) and (not FClosed) then
  begin
    FClosed := True;
    try
      Finish();
    finally
      FOut := nil;  // Prevent any further access to the stream
    end;
  end;
end;

function TAsn1Generator.GetIsClosed: Boolean;
begin
  Result := FClosed;
end;

function TAsn1Generator.GetOut: TStream;
begin
  if FOut = nil then
    raise EInvalidOperationCryptoLibException.Create('Stream is null');
  Result := FOut;
end;

class function TAsn1Generator.InheritConstructedFlag(AIntoTag, AFromTag: Int32): Int32;
begin
  if ((AFromTag and TAsn1Tags.Constructed) <> 0) then
    Result := AIntoTag or TAsn1Tags.Constructed
  else
    Result := AIntoTag and (not TAsn1Tags.Constructed);
end;

{ TBerGenerator }

constructor TBerGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
end;

constructor TBerGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream);
  FTagged := True;
  FIsExplicit := AIsExplicit;
  FTagNo := ATagNo;
end;

procedure TBerGenerator.AddObject(const AObj: IAsn1Encodable);
begin
  AObj.EncodeTo(&Out);
end;

procedure TBerGenerator.AddObject(const AObj: IAsn1Object);
begin
  AObj.EncodeTo(&Out);
end;

procedure TBerGenerator.Finish();
begin
  WriteBerEnd();
end;

procedure TBerGenerator.Close();
begin
  DoClose();
end;

function TBerGenerator.GetRawOutputStream(): TStream;
begin
  Result := &Out;
end;

procedure TBerGenerator.WriteBerBody(AContentStream: TStream);
begin
  TStreamUtilities.PipeAll(AContentStream, &Out);
end;

procedure TBerGenerator.WriteBerEnd();
begin
  &Out.WriteByte($00);
  &Out.WriteByte($00);

  if (FTagged and FIsExplicit) then // write extra end for tag header
  begin
    &Out.WriteByte($00);
    &Out.WriteByte($00);
  end;
end;

procedure TBerGenerator.WriteBerHeader(ATag: Int32);
begin
  if not FTagged then
  begin
    WriteHdr(ATag);
  end
  else if FIsExplicit then
  begin
    {
     * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
     * and the contents octets shall be the complete base encoding.
     }
    WriteHdr(FTagNo or TAsn1Tags.ContextSpecific or TAsn1Tags.Constructed);
    WriteHdr(ATag);
  end
  else
  begin
    {
     * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
     * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
     * shall be [..] the contents octets of the base encoding.
     }
    WriteHdr(InheritConstructedFlag(FTagNo or TAsn1Tags.ContextSpecific, ATag));
  end;
end;

procedure TBerGenerator.WriteHdr(ATag: Int32);
begin
  &Out.WriteByte(Byte(ATag));
  &Out.WriteByte($80);
end;

{ TBerSequenceGenerator }

constructor TBerSequenceGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.Sequence);
end;

constructor TBerSequenceGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream, ATagNo, AIsExplicit);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.Sequence);
end;

{ TBerOctetStringGenerator }

constructor TBerOctetStringGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.OctetString);
end;

constructor TBerOctetStringGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream, ATagNo, AIsExplicit);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.OctetString);
end;

function TBerOctetStringGenerator.GetOctetOutputStream(): TStream;
var
  LBuf: TCryptoLibByteArray;
begin
  System.SetLength(LBuf, 1000);
  Result := GetOctetOutputStream(LBuf); // limit for CER encoding.
end;

function TBerOctetStringGenerator.GetOctetOutputStream(ABufSize: Int32): TStream;
var
  LBuf: TCryptoLibByteArray;
begin
  if ABufSize < 1 then
    Result := GetOctetOutputStream()
  else
  begin
    System.SetLength(LBuf, ABufSize);
    Result := GetOctetOutputStream(LBuf);
  end;
end;

function TBerOctetStringGenerator.GetOctetOutputStream(const ABuf: TCryptoLibByteArray): TStream;
begin
  Result := TAsn1BufferedBerOctetStream.Create(GetRawOutputStream(), ABuf);
end;

{ TDerGenerator }

constructor TDerGenerator.Create(const AOutStream: TStream);
begin
  inherited Create(AOutStream);
end;

constructor TDerGenerator.Create(const AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream);
  FTagged := True;
  FIsExplicit := AIsExplicit;
  FTagNo := ATagNo;
end;

class procedure TDerGenerator.WriteDerEncoded(const AOutStream: TStream; ATag: Int32; const ABytes: TCryptoLibByteArray);
begin
  AOutStream.WriteByte(Byte(ATag));
  WriteLength(AOutStream, System.Length(ABytes));
  if System.Length(ABytes) > 0 then
    AOutStream.Write(ABytes[0], System.Length(ABytes));
end;

class procedure TDerGenerator.WriteDerEncoded(const AOutStr: TStream; ATag: Int32; const AInStr: TStream);
begin
  WriteDerEncoded(AOutStr, ATag, TStreamUtilities.ReadAll(AInStr));
end;

class procedure TDerGenerator.WriteLength(const AOutStr: TStream; ALength: Int32);
var
  LSize, LVal, I: Int32;
begin
  if ALength > 127 then
  begin
    LSize := 1;
    LVal := ALength;
    LVal := TBitOperations.Asr32(LVal, 8);
    while LVal <> 0 do
    begin
      System.Inc(LSize);
      LVal := TBitOperations.Asr32(LVal, 8);
    end;
    AOutStr.WriteByte(Byte(LSize or $80));
    I := (LSize - 1) * 8;
    while I >= 0 do
    begin
      AOutStr.WriteByte(Byte(TBitOperations.Asr32(ALength, I)));
      System.Dec(I, 8);
    end;
  end
  else
  begin
    AOutStr.WriteByte(Byte(ALength));
  end;
end;

procedure TDerGenerator.WriteDerEncoded(ATag: Int32; const ABytes: TCryptoLibByteArray);
var
  LBOut: TMemoryStream;
  LTemp: TCryptoLibByteArray;
begin
  if not FTagged then
  begin
    WriteDerEncoded(&Out, ATag, ABytes);
  end
  else if FIsExplicit then
  begin
    {
     * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
     * and the contents octets shall be the complete base encoding.
     }
    LBOut := TMemoryStream.Create();
    try
      WriteDerEncoded(LBOut, ATag, ABytes);
      LBOut.Position := 0;
      System.SetLength(LTemp, LBOut.Size);
      LBOut.Read(LTemp[0], LBOut.Size);
      WriteDerEncoded(&Out, FTagNo or TAsn1Tags.ContextSpecific or TAsn1Tags.Constructed, LTemp);
    finally
      LBOut.Free;
    end;
  end
  else
  begin
    {
     * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
     * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
     * shall be [..] the contents octets of the base encoding.
     }
    WriteDerEncoded(&Out, InheritConstructedFlag(FTagNo or TAsn1Tags.ContextSpecific, ATag), ABytes);
  end;
end;

{ TDerSequenceGenerator }

constructor TDerSequenceGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
  FBOut := TMemoryStream.Create();
end;

constructor TDerSequenceGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream, ATagNo, AIsExplicit);
  FBOut := TMemoryStream.Create();
end;

destructor TDerSequenceGenerator.Destroy;
begin
  FBOut.Free;
  inherited Destroy;
end;

procedure TDerSequenceGenerator.AddObject(const AObj: IAsn1Encodable);
begin
  AObj.EncodeTo(FBOut, TAsn1Encodable.Der);
end;

procedure TDerSequenceGenerator.AddObject(const AObj: IAsn1Object);
begin
  (AObj as IAsn1Encodable).EncodeTo(FBOut, TAsn1Encodable.Der);
end;

function TDerSequenceGenerator.GetRawOutputStream(): TStream;
begin
  Result := FBOut;
end;

procedure TDerSequenceGenerator.Finish();
var
  LTemp: TCryptoLibByteArray;
begin
  FBOut.Position := 0;
  System.SetLength(LTemp, FBOut.Size);
  FBOut.Read(LTemp[0], FBOut.Size);
  WriteDerEncoded(TAsn1Tags.Constructed or TAsn1Tags.Sequence, LTemp);
end;

procedure TDerSequenceGenerator.Close();
begin
  DoClose();
end;

end.
