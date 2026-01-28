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

unit ClpAsn1Encodings;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Math,
  SysUtils,
  ClpCryptoLibTypes,
  ClpIAsn1Encodings;

type

  /// <summary>
  /// Abstract base class for DER encoding.
  /// </summary>
  TDerEncoding = class abstract(TInterfacedObject, IDerEncoding, IAsn1Encoding)
  strict protected
    FTagClass: Int32;
    FTagNo: Int32;

  strict protected
    /// <summary>
    /// Compare length and contents with another DER encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; virtual; abstract;

  public
    /// <summary>
    /// Create a DER encoding.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32);

    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32;
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32;
    /// <summary>
    /// Compare this encoding with another.
    /// </summary>
    function CompareTo(const AOther: IDerEncoding): Int32;

    /// <summary>
    /// Encode to the given stream (must be a TAsn1OutputStream).
    /// </summary>
    procedure Encode(const AOut: TStream); virtual; abstract;

    /// <summary>
    /// Get the length of the encoded data.
    /// </summary>
    function GetLength(): Int32; virtual; abstract;

    property TagClass: Int32 read FTagClass;
    property TagNo: Int32 read FTagNo;
  end;

  /// <summary>
  /// DL (Definite Length) constructed encoding.
  /// </summary>
  TConstructedDLEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElements: TCryptoLibGenericArray<IAsn1Encoding>;
    FContentsLength: Int32;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DL tagged encoding.
  /// </summary>
  TTaggedDLEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElement: IAsn1Encoding;
    FContentsLength: Int32;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElement: IAsn1Encoding);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DER constructed encoding.
  /// </summary>
  TConstructedDerEncoding = class sealed(TDerEncoding, IConstructedDerEncoding)
  strict private
    FContentsElements: TCryptoLibGenericArray<IDerEncoding>;
    FContentsLength: Int32;
  strict protected
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElements: TCryptoLibGenericArray<IDerEncoding>);
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsLength(): Int32;
    function GetContentsElements(): TCryptoLibGenericArray<IDerEncoding>;
  end;

  /// <summary>
  /// DER tagged encoding.
  /// </summary>
  TTaggedDerEncoding = class sealed(TDerEncoding, ITaggedDerEncoding)
  strict private
    FContentsElement: IDerEncoding;
    FContentsLength: Int32;
  strict protected
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElement: IDerEncoding);
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsLength(): Int32;
    function GetContentsElement(): IDerEncoding;
  end;

  /// <summary>
  /// IL (Indefinite Length) constructed encoding.
  /// </summary>
  TConstructedILEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElements: TCryptoLibGenericArray<IAsn1Encoding>;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// IL tagged encoding.
  /// </summary>
  TTaggedILEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElement: IAsn1Encoding;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElement: IAsn1Encoding);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// Primitive encoding.
  /// </summary>
  TPrimitiveEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsOctets: TCryptoLibByteArray;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DER primitive encoding.
  /// </summary>
  TPrimitiveDerEncoding = class sealed(TDerEncoding, IPrimitiveDerEncoding)
  protected
    FContentsOctets: TCryptoLibByteArray;
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray); overload;
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Primitive encoding with suffix.
  /// </summary>
  TPrimitiveEncodingSuffixed = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsOctets: TCryptoLibByteArray;
    FContentsSuffix: Byte;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DER primitive encoding with suffix.
  /// </summary>
  TPrimitiveDerEncodingSuffixed = class sealed(TDerEncoding, IPrimitiveDerEncodingSuffixed)
  protected
    FContentsOctets: TCryptoLibByteArray;
    FContentsSuffix: Byte;
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
    class function CompareSuffixed(const AOctetsA: TCryptoLibByteArray;
      ASuffixA: Byte; const AOctetsB: TCryptoLibByteArray; ASuffixB: Byte): Int32; static;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsOctets(): TCryptoLibByteArray;
    function GetContentsSuffix(): Byte;
  end;

implementation

uses
  ClpAsn1Streams;

const
  // BER/DER constructed flag (bit 6)
  CONSTRUCTED_FLAG = $20;

{ TDerEncoding }

constructor TDerEncoding.Create(ATagClass, ATagNo: Int32);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
end;

function TDerEncoding.GetTagClass(): Int32;
begin
  Result := FTagClass;
end;

function TDerEncoding.GetTagNo(): Int32;
begin
  Result := FTagNo;
end;

function TDerEncoding.CompareTo(const AOther: IDerEncoding): Int32;
begin
  if AOther = nil then
  begin
    Result := 1;
    Exit;
  end;

  if FTagClass <> AOther.TagClass then
  begin
    Result := FTagClass - AOther.TagClass;
    Exit;
  end;

  if FTagNo <> AOther.TagNo then
  begin
    Result := FTagNo - AOther.TagNo;
    Exit;
  end;

  Result := CompareLengthAndContents(AOther);
end;

{ TConstructedDLEncoding }

constructor TConstructedDLEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElements := AContentsElements;
  FContentsLength := TAsn1OutputStream.GetLengthOfContents(AContentsElements);
end;

procedure TConstructedDLEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(CONSTRUCTED_FLAG or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  LAsn1Out.EncodeContents(FContentsElements);
end;

function TConstructedDLEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

{ TTaggedDLEncoding }

constructor TTaggedDLEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElement: IAsn1Encoding);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElement := AContentsElement;
  FContentsLength := AContentsElement.GetLength();
end;

procedure TTaggedDLEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(CONSTRUCTED_FLAG or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  FContentsElement.Encode(AOut);
end;

function TTaggedDLEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

{ TConstructedDerEncoding }

constructor TConstructedDerEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElements: TCryptoLibGenericArray<IDerEncoding>);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsElements = nil then
    raise EArgumentNilCryptoLibException.Create('contentsElements');
  FContentsElements := AContentsElements;
  FContentsLength := TAsn1OutputStream.GetLengthOfContents(TCryptoLibGenericArray<IAsn1Encoding>(AContentsElements));
end;

function TConstructedDerEncoding.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LThat: IConstructedDerEncoding;
  I, LLength: Int32;
begin
  if not Supports(AOther, IConstructedDerEncoding, LThat) then
    raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');

  if FContentsLength <> LThat.ContentsLength then
  begin
    Result := FContentsLength - LThat.ContentsLength;
    Exit;
  end;

  LLength := Math.Min(System.Length(FContentsElements), System.Length(LThat.ContentsElements));
  for I := 0 to LLength - 1 do
  begin
    Result := FContentsElements[I].CompareTo(LThat.ContentsElements[I]);
    if Result <> 0 then
      Exit;
  end;

  Result := System.Length(FContentsElements) - System.Length(LThat.ContentsElements);
end;

procedure TConstructedDerEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(CONSTRUCTED_FLAG or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  LAsn1Out.EncodeContents(TCryptoLibGenericArray<IAsn1Encoding>(FContentsElements));
end;

function TConstructedDerEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

function TConstructedDerEncoding.GetContentsLength(): Int32;
begin
  Result := FContentsLength;
end;

function TConstructedDerEncoding.GetContentsElements(): TCryptoLibGenericArray<IDerEncoding>;
begin
  Result := FContentsElements;
end;

{ TTaggedDerEncoding }

constructor TTaggedDerEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElement: IDerEncoding);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsElement = nil then
    raise EArgumentNilCryptoLibException.Create('contentsElement');
  FContentsElement := AContentsElement;
  FContentsLength := AContentsElement.GetLength();
end;

function TTaggedDerEncoding.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LThat: ITaggedDerEncoding;
begin
  if not Supports(AOther, ITaggedDerEncoding, LThat) then
    raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');

  if FContentsLength <> LThat.ContentsLength then
  begin
    Result := FContentsLength - LThat.ContentsLength;
    Exit;
  end;

  Result := FContentsElement.CompareTo(LThat.ContentsElement);
end;

procedure TTaggedDerEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(CONSTRUCTED_FLAG or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  FContentsElement.Encode(AOut);
end;

function TTaggedDerEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

function TTaggedDerEncoding.GetContentsLength(): Int32;
begin
  Result := FContentsLength;
end;

function TTaggedDerEncoding.GetContentsElement(): IDerEncoding;
begin
  Result := FContentsElement;
end;

{ TConstructedILEncoding }

constructor TConstructedILEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElements := AContentsElements;
end;

procedure TConstructedILEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(CONSTRUCTED_FLAG or FTagClass, FTagNo);
  LAsn1Out.WriteByte($80);
  LAsn1Out.EncodeContents(FContentsElements);
  LAsn1Out.WriteByte($00);
  LAsn1Out.WriteByte($00);
end;

function TConstructedILEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingIL(FTagNo, FContentsElements);
end;

{ TTaggedILEncoding }

constructor TTaggedILEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElement: IAsn1Encoding);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElement := AContentsElement;
end;

procedure TTaggedILEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(CONSTRUCTED_FLAG or FTagClass, FTagNo);
  LAsn1Out.WriteByte($80);
  FContentsElement.Encode(AOut);
  LAsn1Out.WriteByte($00);
  LAsn1Out.WriteByte($00);
end;

function TTaggedILEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingIL(FTagNo, FContentsElement);
end;

{ TPrimitiveEncoding }

constructor TPrimitiveEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsOctets := AContentsOctets;
end;

procedure TPrimitiveEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 0 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets));
end;

function TPrimitiveEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

{ TPrimitiveDerEncoding }

constructor TPrimitiveDerEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsOctets = nil then
    raise EArgumentNilCryptoLibException.Create('contentsOctets');
  FContentsOctets := AContentsOctets;
end;

function TPrimitiveDerEncoding.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LThat: IPrimitiveDerEncoding;
  LSuffixed: IPrimitiveDerEncodingSuffixed;
  I, LLength: Int32;
  LThatOctets: TCryptoLibByteArray;
begin
  if Supports(AOther, IPrimitiveDerEncodingSuffixed, LSuffixed) then
  begin
    // Call the overridden method on the suffixed instance, passing Self
    Result := -LSuffixed.CompareLengthAndContents(Self as IDerEncoding);
    Exit;
  end;

  if not Supports(AOther, IPrimitiveDerEncoding, LThat) then
    raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');

  LThatOctets := LThat.ContentsOctets;
  LLength := System.Length(FContentsOctets);
  if LLength <> System.Length(LThatOctets) then
  begin
    Result := LLength - System.Length(LThatOctets);
    Exit;
  end;

  for I := 0 to LLength - 1 do
  begin
    if FContentsOctets[I] <> LThatOctets[I] then
    begin
      Result := Int32(FContentsOctets[I]) - Int32(LThatOctets[I]);
      Exit;
    end;
  end;

  Result := 0;
end;

procedure TPrimitiveDerEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 0 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets));
end;

function TPrimitiveDerEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

function TPrimitiveDerEncoding.GetContentsOctets(): TCryptoLibByteArray;
begin
  Result := FContentsOctets;
end;

{ TPrimitiveEncodingSuffixed }

constructor TPrimitiveEncodingSuffixed.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsOctets := AContentsOctets;
  FContentsSuffix := AContentsSuffix;
end;

procedure TPrimitiveEncodingSuffixed.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 1 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets) - 1);
  LAsn1Out.WriteByte(FContentsSuffix);
end;

function TPrimitiveEncodingSuffixed.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

{ TPrimitiveDerEncodingSuffixed }

constructor TPrimitiveDerEncodingSuffixed.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsOctets = nil then
    raise EArgumentNilCryptoLibException.Create('contentsOctets');
  if System.Length(AContentsOctets) = 0 then
    raise EArgumentCryptoLibException.Create('contentsOctets length must be > 0');
  FContentsOctets := AContentsOctets;
  FContentsSuffix := AContentsSuffix;
end;

function TPrimitiveDerEncodingSuffixed.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LSuff: IPrimitiveDerEncodingSuffixed;
  LThat: IPrimitiveDerEncoding;
  LThatOctets: TCryptoLibByteArray;
  LLength: Int32;
begin
  if Supports(AOther, IPrimitiveDerEncodingSuffixed, LSuff) then
  begin
    Result := CompareSuffixed(FContentsOctets, FContentsSuffix,
      LSuff.ContentsOctets, LSuff.ContentsSuffix);
    Exit;
  end;

  if Supports(AOther, IPrimitiveDerEncoding, LThat) then
  begin
    LThatOctets := LThat.ContentsOctets;
    LLength := System.Length(LThatOctets);
    if LLength = 0 then
    begin
      Result := System.Length(FContentsOctets);
      Exit;
    end;

    Result := CompareSuffixed(FContentsOctets, FContentsSuffix,
      LThatOctets, LThatOctets[LLength - 1]);
    Exit;
  end;

  raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');
end;

class function TPrimitiveDerEncodingSuffixed.CompareSuffixed(const AOctetsA: TCryptoLibByteArray;
  ASuffixA: Byte; const AOctetsB: TCryptoLibByteArray; ASuffixB: Byte): Int32;
var
  LLength, I, LLast: Int32;
begin
  if (System.Length(AOctetsA) = 0) or (System.Length(AOctetsB) = 0) then
    raise EArgumentCryptoLibException.Create('Octets length must be > 0');

  LLength := System.Length(AOctetsA);
  if LLength <> System.Length(AOctetsB) then
  begin
    Result := LLength - System.Length(AOctetsB);
    Exit;
  end;

  LLast := LLength - 1;
  for I := 0 to LLast - 1 do
  begin
    if AOctetsA[I] <> AOctetsB[I] then
    begin
      Result := Int32(AOctetsA[I]) - Int32(AOctetsB[I]);
      Exit;
    end;
  end;

  Result := Int32(ASuffixA) - Int32(ASuffixB);
end;

procedure TPrimitiveDerEncodingSuffixed.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 1 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets) - 1);
  LAsn1Out.WriteByte(FContentsSuffix);
end;

function TPrimitiveDerEncodingSuffixed.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

function TPrimitiveDerEncodingSuffixed.GetContentsOctets(): TCryptoLibByteArray;
begin
  Result := FContentsOctets;
end;

function TPrimitiveDerEncodingSuffixed.GetContentsSuffix(): Byte;
begin
  Result := FContentsSuffix;
end;

end.

