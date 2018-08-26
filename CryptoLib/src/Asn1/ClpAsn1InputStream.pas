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

unit ClpAsn1InputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Generics.Collections,
{$IFDEF DELPHI}
  ClpIDerNull,
{$ENDIF DELPHI}
  ClpAsn1Tags,
  ClpDefiniteLengthInputStream,
  ClpDerOctetString,
  ClpIndefiniteLengthInputStream,
  ClpAsn1StreamParser,
  ClpIAsn1StreamParser,
  ClpDerBitString,
  ClpDerBmpString,
  // ClpDerGeneralizedTime,
  // ClpDerUtcTime,
  ClpDerGeneralString,
  ClpDerGraphicString,
  ClpDerIA5String,
  ClpDerNumericString,
  ClpDerPrintableString,
  ClpDerT61String,
  ClpDerUniversalString,
  ClpDerUtf8String,
  ClpDerVideotexString,
  ClpDerVisibleString,
  ClpDerBoolean,
  ClpDerEnumerated,
  ClpDerApplicationSpecific,
  ClpDerExternal,
  ClpDerInteger,
  ClpDerNull,
  ClpDerObjectIdentifier,
  ClpBerOctetString,
  ClpIProxiedInterface,
  ClpIDerSequence,
  ClpIDerOctetString,
  ClpIDerSet,
  ClpLimitedInputStream,
  ClpAsn1EncodableVector,
  ClpDerSequence,
  ClpDerSet,
  ClpIAsn1EncodableVector,
  ClpFilterStream,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedStream = 'Corrupted Stream - Invalid High Tag Number Found';
  SEOFFound = 'EOF Found Inside Tag Value';
  SInvalidEnd = 'EOF Found When Length Expected';
  SInvalidDerLength = 'DER Length More Than 4 Bytes: %d';
  SEndOfStream = 'EOF Found Reading Length';
  SNegativeLength = 'Corrupted Stream - Negative Length Found';
  SOutOfBoundsLength = 'Corrupted stream - Out of Bounds Length Found';
  SUnknownTag = 'Unknown Tag " %d " Encountered';
  SEndOfContent = 'Unexpected End-of-Contents Marker';
  SIndefiniteLength = 'Indefinite Length Primitive Encoding Encountered';
  SUnknownBerObject = 'Unknown BER Object Encountered';
  SCorruptedStreamTwo = 'Corrupted Stream Detected: %s';

type

  /// <summary>
  /// a general purpose ASN.1 decoder - note: this class differs from the <br />
  /// others in that it returns null after it has read the last object in <br />
  /// the stream. If an ASN.1 Null is encountered a DerBER Null object is <br />
  /// returned. <br />
  /// </summary>
  TAsn1InputStream = class(TFilterStream)

  strict private

  var
    Flimit: Int32;
    FtmpBuffers: TCryptoLibMatrixByteArray;
    FStream: TStream;

    /// <summary>
    /// build an object given its tag and the number of bytes to construct it
    /// from.
    /// </summary>
    function BuildObject(tag, tagNo, length: Int32): IAsn1Object;

  public

    constructor Create(const inputStream: TStream); overload;

    /// <summary>
    /// Create an ASN1InputStream where no DER object will be longer than
    /// limit.
    /// </summary>
    /// <param name="inputStream">
    /// stream containing ASN.1 encoded data.
    /// </param>
    /// <param name="limit">
    /// maximum size of a DER encoded object.
    /// </param>
    constructor Create(const inputStream: TStream; limit: Int32); overload;

    destructor Destroy(); override;

    /// <summary>
    /// the stream is automatically limited to the length of the input array.
    /// </summary>
    /// <param name="input">
    /// array containing ASN.1 encoded data.
    /// </param>
    constructor Create(const input: TCryptoLibByteArray); overload;

    function ReadObject(): IAsn1Object;

    function BuildEncodableVector(): IAsn1EncodableVector;

    function BuildDerEncodableVector(const dIn: TDefiniteLengthInputStream)
      : IAsn1EncodableVector; virtual;

    function CreateDerSequence(const dIn: TDefiniteLengthInputStream)
      : IDerSequence; virtual;

    function CreateDerSet(const dIn: TDefiniteLengthInputStream)
      : IDerSet; virtual;

    class function FindLimit(const input: TStream): Int32; static;

    class function ReadTagNumber(const s: TStream; tag: Int32): Int32; static;

    class function ReadLength(const s: TStream; limit: Int32): Int32; static;

    class function GetBuffer(const defIn: TDefiniteLengthInputStream;
      const tmpBuffers: TCryptoLibMatrixByteArray): TCryptoLibByteArray;
      static; inline;

    class function CreatePrimitiveDerObject(tagNo: Int32;
      const defIn: TDefiniteLengthInputStream;
      const tmpBuffers: TCryptoLibMatrixByteArray): IAsn1Object; static;
  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpStreamSorter,
  ClpBerOctetStringParser,
  ClpBerSequenceParser,
  ClpBerSetParser,
  ClpDerExternalParser,
  ClpBerApplicationSpecificParser,
  ClpBerTaggedObjectParser,
  ClpIBerOctetStringParser,
  ClpIBerSequenceParser,
  ClpIBerSetParser,
  ClpIDerExternalParser,
  ClpIBerApplicationSpecificParser,
  ClpIBerTaggedObjectParser;

{ TAsn1InputStream }

class function TAsn1InputStream.FindLimit(const input: TStream): Int32;
var
  limitedInputStream: TLimitedInputStream;
  mem: TMemoryStream;
begin
  limitedInputStream := input as TLimitedInputStream;
  if (limitedInputStream <> Nil) then
  begin
    result := limitedInputStream.GetRemaining();
    Exit;
  end
  else if (input is TMemoryStream) then
  begin
    mem := input as TMemoryStream;
    result := Int32(mem.Size - mem.Position);
    Exit;
  end;

  result := System.High(Int32);
end;

class function TAsn1InputStream.GetBuffer(const defIn
  : TDefiniteLengthInputStream; const tmpBuffers: TCryptoLibMatrixByteArray)
  : TCryptoLibByteArray;
var
  len: Int32;
  buf, temp: TCryptoLibByteArray;
begin
  len := defIn.GetRemaining();
  if (len >= System.length(tmpBuffers)) then
  begin
    result := defIn.ToArray();
    Exit;
  end;

  buf := tmpBuffers[len];
  if (buf = Nil) then
  begin
    System.SetLength(temp, len);
    tmpBuffers[len] := temp;
    buf := tmpBuffers[len];
  end;

  defIn.ReadAllIntoByteArray(buf);

  result := buf;
end;

class function TAsn1InputStream.CreatePrimitiveDerObject(tagNo: Int32;
  const defIn: TDefiniteLengthInputStream;
  const tmpBuffers: TCryptoLibMatrixByteArray): IAsn1Object;
var
  bytes: TCryptoLibByteArray;
begin
  case tagNo of
    TAsn1Tags.Boolean:
      begin
        result := TDerBoolean.FromOctetString(GetBuffer(defIn, tmpBuffers));
        Exit;
      end;
    TAsn1Tags.Enumerated:
      begin
        result := TDerEnumerated.FromOctetString(GetBuffer(defIn, tmpBuffers));
        Exit;
      end;
    TAsn1Tags.ObjectIdentifier:
      begin
        result := TDerObjectIdentifier.FromOctetString
          (GetBuffer(defIn, tmpBuffers));
        Exit;
      end;

  end;

  bytes := defIn.ToArray();

  case tagNo of

    TAsn1Tags.BitString:
      begin
        result := TDerBitString.FromAsn1Octets(bytes);
        Exit;
      end;
    TAsn1Tags.BmpString:
      begin
        result := TDerBmpString.Create(bytes);
        Exit;
      end;
    // TAsn1Tags.GeneralizedTime:
    // begin
    // result := TDerGeneralizedTime.Create(bytes);
    // Exit;
    // end;
    TAsn1Tags.GeneralString:
      begin
        result := TDerGeneralString.Create(bytes);
        Exit;
      end;
    TAsn1Tags.GraphicString:
      begin
        result := TDerGraphicString.Create(bytes);
        Exit;
      end;
    TAsn1Tags.IA5String:
      begin
        result := TDerIA5String.Create(bytes);
        Exit;
      end;
    TAsn1Tags.Integer:
      begin
        result := TDerInteger.Create(bytes);
        Exit;
      end;
    TAsn1Tags.Null:
      begin
        // actual content is ignored (enforce 0 length?)
        result := TDerNull.Instance;
        Exit;
      end;
    TAsn1Tags.NumericString:
      begin
        result := TDerNumericString.Create(bytes);
        Exit;
      end;
    TAsn1Tags.OctetString:
      begin
        result := TDerOctetString.Create(bytes);
        Exit;
      end;
    TAsn1Tags.PrintableString:
      begin
        result := TDerPrintableString.Create(bytes);
        Exit;
      end;
    TAsn1Tags.T61String:
      begin
        result := TDerT61String.Create(bytes);
        Exit;
      end;
    TAsn1Tags.UniversalString:
      begin
        result := TDerUniversalString.Create(bytes);
        Exit;
      end;
    // TAsn1Tags.UtcTime:
    // begin
    // result := TDerUtcTime.Create(bytes);
    // Exit;
    // end;
    TAsn1Tags.Utf8String:
      begin
        result := TDerUtf8String.Create(bytes);
        Exit;
      end;
    TAsn1Tags.VideotexString:
      begin
        result := TDerVideotexString.Create(bytes);
        Exit;
      end;
    TAsn1Tags.VisibleString:
      begin
        result := TDerVisibleString.Create(bytes);
        Exit;
      end;
  else
    begin
      raise EIOCryptoLibException.CreateResFmt(@SUnknownTag, [tagNo]);
    end;

  end;
end;

destructor TAsn1InputStream.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

constructor TAsn1InputStream.Create(const inputStream: TStream; limit: Int32);
begin
  Inherited Create(inputStream);
  Flimit := limit;
  System.SetLength(FtmpBuffers, 16);
end;

constructor TAsn1InputStream.Create(const inputStream: TStream);
begin
  Create(inputStream, FindLimit(inputStream));
end;

constructor TAsn1InputStream.Create(const input: TCryptoLibByteArray);
begin
  // used TBytesStream here for one pass creation and population with byte array :)
  FStream := TBytesStream.Create(input);
  Create(FStream, System.length(input));

end;

class function TAsn1InputStream.ReadLength(const s: TStream;
  limit: Int32): Int32;
var
  &length, Size, next, I: Int32;
begin

  length := TStreamSorter.ReadByte(s);

  if (length < 0) then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SInvalidEnd);
  end;

  if (length = $80) then
  begin
    result := -1; // indefinite-length encoding
    Exit;
  end;

  if (length > 127) then
  begin
    Size := length and $7F;

    // Note: The invalid long form "$ff" (see X.690 8.1.3.5c) will be caught here
    if (Size > 4) then
    begin
      raise EIOCryptoLibException.CreateResFmt(@SInvalidDerLength, [Size]);
    end;

    length := 0;
    I := 0;
    while I < Size do
    begin

      next := TStreamSorter.ReadByte(s);

      if (next < 0) then
      begin
        raise EEndOfStreamCryptoLibException.CreateRes(@SEndOfStream);
      end;

      length := (length shl 8) + next;

      System.Inc(I);
    end;

    if (length < 0) then
    begin
      raise EIOCryptoLibException.CreateRes(@SNegativeLength);
    end;

    if (length >= limit) then // after all we must have read at least 1 byte
    begin
      raise EIOCryptoLibException.CreateRes(@SOutOfBoundsLength);
    end;
  end;

  result := length;
end;

function TAsn1InputStream.ReadObject: IAsn1Object;
var
  tag, tagNo, &length: Int32;
  isConstructed: Boolean;
  indIn: TIndefiniteLengthInputStream;
  sp: IAsn1StreamParser;
begin

  tag := ReadByte();

  if (tag <= 0) then
  begin
    if (tag = 0) then
    begin
      raise EIOCryptoLibException.CreateRes(@SEndOfContent);
    end;

    result := Nil;
    Exit;
  end;

  //
  // calculate tag number
  //
  tagNo := ReadTagNumber(Fs, tag);

  isConstructed := (tag and TAsn1Tags.Constructed) <> 0;

  //
  // calculate length
  //
  length := ReadLength(Fs, Flimit);

  if (length < 0) then // indefinite length method
  begin
    if (not isConstructed) then
    begin

      raise EIOCryptoLibException.CreateRes(@SIndefiniteLength);

    end;

    indIn := TIndefiniteLengthInputStream.Create(Fs, Flimit);
    sp := TAsn1StreamParser.Create(indIn, Flimit);

    if ((tag and TAsn1Tags.Application) <> 0) then
    begin
      result := (TBerApplicationSpecificParser.Create(tagNo, sp)
        as IBerApplicationSpecificParser).ToAsn1Object();
      Exit;
    end;

    if ((tag and TAsn1Tags.Tagged) <> 0) then
    begin
      result := (TBerTaggedObjectParser.Create(true, tagNo, sp)
        as IBerTaggedObjectParser).ToAsn1Object();
      Exit;
    end;

    // TODO There are other tags that may be constructed (e.g. BitString)

    case tagNo of
      TAsn1Tags.OctetString:
        begin
          result := (TBerOctetStringParser.Create(sp) as IBerOctetStringParser)
            .ToAsn1Object();
          Exit;
        end;
      TAsn1Tags.Sequence:
        begin
          result := (TBerSequenceParser.Create(sp) as IBerSequenceParser)
            .ToAsn1Object();
          Exit;
        end;
      TAsn1Tags.&Set:
        begin
          result := (TBerSetParser.Create(sp) as IBerSetParser).ToAsn1Object();
          Exit;
        end;
      TAsn1Tags.External:
        begin
          result := (TDerExternalParser.Create(sp) as IDerExternalParser)
            .ToAsn1Object();
          Exit;
        end;
    else
      begin
        raise EIOCryptoLibException.CreateRes(@SUnknownBerObject);
      end;
    end;

  end
  else
  begin
    try
      result := BuildObject(tag, tagNo, length);
    except
      on e: EArgumentCryptoLibException do
      begin
        raise EAsn1CryptoLibException.CreateResFmt(@SCorruptedStreamTwo,
          [e.Message]);
      end;
    end;
  end;
end;

function TAsn1InputStream.BuildDerEncodableVector
  (const dIn: TDefiniteLengthInputStream): IAsn1EncodableVector;
var
  res: TAsn1InputStream;
begin
  res := TAsn1InputStream.Create(dIn);
  try
    result := res.BuildEncodableVector();
  finally
    res.Free;
  end;
end;

function TAsn1InputStream.BuildEncodableVector: IAsn1EncodableVector;
var
  v: IAsn1EncodableVector;
  o: IAsn1Object;
begin
  v := TAsn1EncodableVector.Create();

  o := ReadObject();
  while (o <> Nil) do
  begin
    v.Add([o]);
    o := ReadObject();
  end;

  result := v;
end;

function TAsn1InputStream.BuildObject(tag, tagNo, length: Int32): IAsn1Object;
var
  isConstructed: Boolean;
  defIn: TDefiniteLengthInputStream;
  v: IAsn1EncodableVector;
  strings: TList<IDerOctetString>;
  I: Int32;
begin
  isConstructed := (tag and TAsn1Tags.Constructed) <> 0;
  defIn := TDefiniteLengthInputStream.Create(Fs, length);

  if ((tag and TAsn1Tags.Application) <> 0) then
  begin
    try
      result := TDerApplicationSpecific.Create(isConstructed, tagNo,
        defIn.ToArray());
      Exit;
    finally
      defIn.Free;
    end;
  end;

  if ((tag and TAsn1Tags.Tagged) <> 0) then
  begin

    result := (TAsn1StreamParser.Create(defIn) as IAsn1StreamParser)
      .ReadTaggedObject(isConstructed, tagNo);
    Exit;

  end;

  if (isConstructed) then
  begin
    // TODO There are other tags that may be constructed (e.g. BitString)
    case (tagNo) of

      TAsn1Tags.OctetString:
        //
        // yes, people actually do this...
        //
        begin
          try
            v := BuildDerEncodableVector(defIn);
            strings := TList<IDerOctetString>.Create;
            strings.Capacity := v.Count;

            I := 0;
            while (I <> v.Count) do
            begin
              strings.Add(v[I] as IDerOctetString);
            end;

            result := TBerOctetString.Create(strings);
            Exit;
          finally
            defIn.Free;
          end;
        end;
      TAsn1Tags.Sequence:
        begin
          try
            result := CreateDerSequence(defIn);
            Exit;
          finally
            defIn.Free;
          end;
        end;
      TAsn1Tags.&Set:
        begin
          try
            result := CreateDerSet(defIn);
            Exit;
          finally
            defIn.Free;
          end;
        end;
      TAsn1Tags.External:
        begin
          try
            result := TDerExternal.Create(BuildDerEncodableVector(defIn));
            Exit;
          finally
            defIn.Free;
          end;
        end;
    else
      begin
        defIn.Free; // free the stream incase an unsupported tag is encountered.
        raise EIOCryptoLibException.CreateResFmt(@SUnknownTag, [tagNo]);
      end;

    end;

  end;

  try
    result := CreatePrimitiveDerObject(tagNo, defIn, FtmpBuffers);
  finally
    defIn.Free;
  end;

end;

function TAsn1InputStream.CreateDerSequence
  (const dIn: TDefiniteLengthInputStream): IDerSequence;
begin
  result := TDerSequence.FromVector(BuildDerEncodableVector(dIn));
end;

function TAsn1InputStream.CreateDerSet(const dIn
  : TDefiniteLengthInputStream): IDerSet;
begin
  result := TDerSet.FromVector(BuildDerEncodableVector(dIn), false);
end;

class function TAsn1InputStream.ReadTagNumber(const s: TStream;
  tag: Int32): Int32;
var
  tagNo, b: Int32;
begin
  tagNo := tag and $1F;

  //
  // with tagged object tag number is bottom 5 bits, or stored at the start of the content
  //
  if (tagNo = $1F) then
  begin
    tagNo := 0;

    b := TStreamSorter.ReadByte(s);

    // X.690-0207 8.1.2.4.2
    // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
    if ((b and $7F) = 0) then // Note: -1 will pass
    begin
      raise EIOCryptoLibException.CreateRes(@SCorruptedStream);
    end;

    while ((b >= 0) and ((b and $80) <> 0)) do
    begin
      tagNo := tagNo or (b and $7F);
      tagNo := tagNo shl 7;

      b := TStreamSorter.ReadByte(s);

    end;

    if (b < 0) then
    begin
      raise EEndOfStreamCryptoLibException.CreateRes(@SEOFFound);
    end;
    tagNo := tagNo or (b and $7F);
  end;

  result := tagNo;
end;

end.
