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

unit ClpAsn1StreamParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpAsn1Tags,
  ClpIndefiniteLengthInputStream,
  ClpDerExternalParser,
  ClpBerOctetStringParser,
  ClpBerSequenceParser,
  ClpBerSetParser,
  ClpBerSequence,
  ClpBerApplicationSpecificParser,
  ClpDerSetParser,
  ClpDerSequenceParser,
  ClpDerOctetStringParser,
  ClpDerOctetString,
  ClpBerTaggedObject,
  ClpBerTaggedObjectParser,
  ClpDefiniteLengthInputStream,
  ClpDerTaggedObject,
  ClpDerSequence,
  ClpDerApplicationSpecific,
  ClpAsn1EncodableVector,
  ClpIAsn1EncodableVector,
  ClpIAsn1StreamParser;

resourcestring
  SUnknownObject = 'Unknown BER Object Encountered: $%x';
  SIndefiniteLength = 'Indefinite Length Primitive Encoding Encountered';
  SImplicitTagging = 'Implicit Tagging not Implemented';
  SUnConstructedEncoding =
    'Sequences Must Use Constructed Encoding (see X.690 8.9.1/8.10.1)';
  SUnConstructedEncoding2 =
    'Sets Must Use Constructed Encoding (see X.690 8.11.1/8.12.1)';
  SUnknownTag = 'Unknown Tag " %d " Encountered';
  SCorruptedStream = 'Corrupted Stream Detected: %s';

type
  TAsn1StreamParser = class(TInterfacedObject, IAsn1StreamParser)

  strict private
  var
    F_in: TStream;
    F_limit: Int32;
    FtmpBuffers: TCryptoLibMatrixByteArray;

    procedure Set00Check(enabled: Boolean); inline;

  public
    constructor Create(const inStream: TStream); overload;
    constructor Create(const inStream: TStream; limit: Int32); overload;
    constructor Create(const encoding: TCryptoLibByteArray); overload;

    destructor Destroy; override;

    function ReadIndef(tagValue: Int32): IAsn1Convertible;
    function ReadImplicit(constructed: Boolean; tag: Int32): IAsn1Convertible;

    function ReadTaggedObject(constructed: Boolean; tag: Int32): IAsn1Object;

    function ReadObject(): IAsn1Convertible; virtual;

    function ReadVector(): IAsn1EncodableVector; inline;
  end;

implementation

uses
  ClpStreamSorter,
  ClpAsn1InputStream; // included here to avoid circular dependency :)

{ TAsn1StreamParser }

procedure TAsn1StreamParser.Set00Check(enabled: Boolean);
var
  indefiniteLengthInputStream: TIndefiniteLengthInputStream;
begin
  if (F_in is TIndefiniteLengthInputStream) then
  begin
    indefiniteLengthInputStream := F_in as TIndefiniteLengthInputStream;
    indefiniteLengthInputStream.SetEofOn00(enabled);
  end;
end;

constructor TAsn1StreamParser.Create(const inStream: TStream);
begin
  Create(inStream, TAsn1InputStream.FindLimit(inStream));
end;

constructor TAsn1StreamParser.Create(const inStream: TStream; limit: Int32);
begin
  Inherited Create();
  F_in := inStream;
  F_limit := limit;
  System.SetLength(FtmpBuffers, 16);
end;

constructor TAsn1StreamParser.Create(const encoding: TCryptoLibByteArray);
begin
  // used TBytesStream here for one pass creation and population with byte array :)
  Create(TBytesStream.Create(encoding), System.Length(encoding));

end;

destructor TAsn1StreamParser.Destroy;
begin
  F_in.Free;
  inherited Destroy;
end;

function TAsn1StreamParser.ReadVector: IAsn1EncodableVector;
var
  v: IAsn1EncodableVector;
  obj: IAsn1Convertible;
begin
  v := TAsn1EncodableVector.Create();

  obj := ReadObject();
  while (obj <> Nil) do
  begin
    v.Add([obj.ToAsn1Object()]);
    obj := ReadObject();
  end;

  result := v;
end;

function TAsn1StreamParser.ReadImplicit(constructed: Boolean; tag: Int32)
  : IAsn1Convertible;
begin
  if (F_in is TIndefiniteLengthInputStream) then
  begin
    if (not constructed) then
    begin
      raise EIOCryptoLibException.CreateRes(@SIndefiniteLength);
    end;

    result := ReadIndef(tag);
    Exit;
  end;

  if (constructed) then
  begin
    case tag of

      TAsn1Tags.&Set:
        begin
          result := TDerSetParser.Create(Self as IAsn1StreamParser);
          Exit;
        end;
      TAsn1Tags.Sequence:
        begin
          result := TDerSequenceParser.Create(Self as IAsn1StreamParser);
          Exit;
        end;
      TAsn1Tags.OctetString:
        begin
          result := TBerOctetStringParser.Create(Self as IAsn1StreamParser);
          Exit;
        end;

    end;
  end
  else
  begin
    case tag of

      TAsn1Tags.&Set:
        begin
          raise EAsn1CryptoLibException.CreateRes(@SUnConstructedEncoding);
        end;
      TAsn1Tags.Sequence:
        begin
          raise EAsn1CryptoLibException.CreateRes(@SUnConstructedEncoding2);
        end;
      TAsn1Tags.OctetString:
        begin
          result := TDerOctetStringParser.Create
            (F_in as TDefiniteLengthInputStream);
          Exit;
        end;
    end;

  end;

  raise EAsn1CryptoLibException.CreateRes(@SImplicitTagging);

end;

function TAsn1StreamParser.ReadIndef(tagValue: Int32): IAsn1Convertible;
begin
  // Note: INDEF => CONSTRUCTED

  // TODO There are other tags that may be constructed (e.g. BIT_STRING)
  case tagValue of
    TAsn1Tags.External:
      begin
        result := TDerExternalParser.Create(Self as IAsn1StreamParser);
        Exit;
      end;

    TAsn1Tags.OctetString:
      begin
        result := TBerOctetStringParser.Create(Self as IAsn1StreamParser);
        Exit;
      end;

    TAsn1Tags.Sequence:
      begin
        result := TBerSequenceParser.Create(Self as IAsn1StreamParser);
        Exit;
      end;

    TAsn1Tags.&Set:
      begin
        result := TBerSetParser.Create(Self as IAsn1StreamParser);
        Exit;
      end;

  else
    begin
      raise EAsn1CryptoLibException.CreateResFmt(@SUnknownObject, [tagValue]);
    end;

  end;
end;

function TAsn1StreamParser.ReadObject: IAsn1Convertible;
var
  tag, tagNo, &length: Int32;
  isConstructed: Boolean;
  indIn: TIndefiniteLengthInputStream;
  sp: IAsn1StreamParser;
  defIn: TDefiniteLengthInputStream;
begin
  tag := TStreamSorter.ReadByte(F_in);

  if (tag = -1) then
  begin
    result := Nil;
    Exit;
  end;

  // turn off looking for "00" while we resolve the tag
  Set00Check(false);

  //
  // calculate tag number
  //
  tagNo := TAsn1InputStream.ReadTagNumber(F_in, tag);

  isConstructed := (tag and TAsn1Tags.constructed) <> 0;

  //
  // calculate length
  //
  Length := TAsn1InputStream.ReadLength(F_in, F_limit);

  if (Length < 0) then // indefinite length method
  begin
    if (not isConstructed) then
    begin
      raise EIOCryptoLibException.CreateRes(@SIndefiniteLength);
    end;

    indIn := TIndefiniteLengthInputStream.Create(F_in, F_limit);

    sp := TAsn1StreamParser.Create(indIn, F_limit);

    if ((tag and TAsn1Tags.Application) <> 0) then
    begin

      result := TBerApplicationSpecificParser.Create(tagNo, sp);
      Exit;

    end;

    if ((tag and TAsn1Tags.Tagged) <> 0) then
    begin

      result := TBerTaggedObjectParser.Create(true, tagNo, sp);
      Exit;

    end;

    result := sp.ReadIndef(tagNo);
    Exit;

  end;

  defIn := TDefiniteLengthInputStream.Create(F_in, Length);

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
    result := TBerTaggedObjectParser.Create(isConstructed, tagNo,
      TAsn1StreamParser.Create(defIn) as IAsn1StreamParser);
    Exit;

  end;

  if (isConstructed) then
  begin
    // TODO There are other tags that may be constructed (e.g. BitString)
    case tagNo of

      TAsn1Tags.OctetString:
        begin
          //
          // yes, people actually do this...
          //

          result := TBerOctetStringParser.Create(TAsn1StreamParser.Create(defIn)
            as IAsn1StreamParser);
          Exit;

        end;
      TAsn1Tags.Sequence:
        begin

          result := TDerSequenceParser.Create(TAsn1StreamParser.Create(defIn)
            as IAsn1StreamParser);
          Exit;

        end;
      TAsn1Tags.&Set:
        begin

          result := TDerSetParser.Create(TAsn1StreamParser.Create(defIn)
            as IAsn1StreamParser);
          Exit;

        end;

      TAsn1Tags.External:
        begin

          result := TDerExternalParser.Create(TAsn1StreamParser.Create(defIn)
            as IAsn1StreamParser);
          Exit;

        end;
    else
      begin
        defIn.Free; // free the stream incase an unsupported tag is encountered.
        raise EIOCryptoLibException.CreateResFmt(@SUnknownTag, [tagNo]);
      end;

    end;
  end;

  // Some primitive encodings can be handled by parsers too...
  case tagNo of
    TAsn1Tags.OctetString:
      begin
        result := TDerOctetStringParser.Create(defIn);
        Exit;
      end;
  end;

  try
    try
      result := TAsn1InputStream.CreatePrimitiveDerObject(tagNo, defIn,
        FtmpBuffers);
      Exit;

    except

      on e: EArgumentCryptoLibException do
      begin
        raise EAsn1CryptoLibException.CreateResFmt(@SCorruptedStream,
          [e.Message]);
      end;

    end;
  finally
    defIn.Free;
  end;

end;

function TAsn1StreamParser.ReadTaggedObject(constructed: Boolean; tag: Int32)
  : IAsn1Object;
var
  defIn: TDefiniteLengthInputStream;
  v: IAsn1EncodableVector;
begin
  if (not constructed) then
  begin
    // Note: !CONSTRUCTED => IMPLICIT
    defIn := F_in as TDefiniteLengthInputStream;
    result := TDerTaggedObject.Create(false, tag,
      TDerOctetString.Create(defIn.ToArray()));
    Exit;
  end;

  v := ReadVector();

  if (F_in is TIndefiniteLengthInputStream) then
  begin
    if v.Count = 1 then
    begin
      result := TBerTaggedObject.Create(true, tag, v[0]);
      Exit;
    end
    else
    begin
      result := TBerTaggedObject.Create(false, tag, TBerSequence.FromVector(v));
      Exit;
    end;

  end;

  if v.Count = 1 then
  begin
    result := TDerTaggedObject.Create(true, tag, v[0]);
    Exit;
  end
  else
  begin
    result := TDerTaggedObject.Create(false, tag, TDerSequence.FromVector(v));
    Exit;
  end;

end;

end.
