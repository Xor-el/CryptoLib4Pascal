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

unit ClpStreams;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

resourcestring
  SDataOverflow = 'Data Overflow';

type
  TStreams = class sealed(TObject)

  strict private
  const
    BufferSize = Int32(512);

  public

    class procedure Drain(const inStr: TStream); static;
    class function ReadAll(const inStr: TStream): TCryptoLibByteArray;
      static; inline;
    class function ReadAllLimited(const inStr: TStream; limit: Int32)
      : TCryptoLibByteArray; static; inline;
    class function ReadFully(const inStr: TStream; var buf: TCryptoLibByteArray)
      : Int32; overload; static; inline;
    class function ReadFully(const inStr: TStream; var buf: TCryptoLibByteArray;
      off, len: Int32): Int32; overload; static;
    class procedure PipeAll(const inStr, outStr: TStream); static;
    /// <summary>
    /// Pipe all bytes from <c>inStr</c> to <c>outStr</c>, throwing <c>
    /// EStreamOverflowCryptoLibException</c> if greater than <c>limit</c> bytes in <c>
    /// inStr</c>.
    /// </summary>
    /// <param name="inStr">
    /// Input Stream
    /// </param>
    /// <param name="limit">
    /// Limit
    /// </param>
    /// <param name="outStr">
    /// Output Stream
    /// </param>
    /// <returns>
    /// The number of bytes actually transferred, if not greater than <c>
    /// limit</c>
    /// </returns>
    /// <exception cref="EStreamOverflowCryptoLibException" />
    class function PipeAllLimited(const inStr: TStream; limit: Int64;
      const outStr: TStream): Int64; static;

    class procedure WriteBufTo(const buf: TMemoryStream; const output: TStream);
      overload; static; inline;

    class function WriteBufTo(const buf: TMemoryStream;
      const output: TCryptoLibByteArray; offset: Int32): Int32; overload;
      static; inline;

    class procedure WriteZeroes(const outStr: TStream; count: Int64); static;

  end;

implementation

uses
  ClpStreamSorter; // included here to avoid circular dependency :)

{ TStreams }

class procedure TStreams.Drain(const inStr: TStream);
var
  bs: TCryptoLibByteArray;
begin
  System.SetLength(bs, BufferSize);

  while (TStreamSorter.Read(inStr, bs, 0, System.Length(bs)) > 0) do
  begin
    // do nothing
  end;
end;

class procedure TStreams.PipeAll(const inStr, outStr: TStream);
var
  numRead: Int32;
  bs: TCryptoLibByteArray;
begin
  System.SetLength(bs, BufferSize);

  numRead := TStreamSorter.Read(inStr, bs, 0, System.Length(bs));
  while ((numRead) > 0) do
  begin
    outStr.Write(bs[0], numRead);
    numRead := TStreamSorter.Read(inStr, bs, 0, System.Length(bs));

  end;
end;

class function TStreams.PipeAllLimited(const inStr: TStream; limit: Int64;
  const outStr: TStream): Int64;
var
  bs: TCryptoLibByteArray;
  numRead: Int32;
  total: Int64;
begin
  System.SetLength(bs, BufferSize);
  total := 0;

  numRead := TStreamSorter.Read(inStr, bs, 0, System.Length(bs));
  while ((numRead) > 0) do
  begin
    if ((limit - total) < numRead) then
    begin
      raise EStreamOverflowCryptoLibException.CreateRes(@SDataOverflow);
    end;
    total := total + numRead;
    outStr.Write(bs[0], numRead);
    numRead := TStreamSorter.Read(inStr, bs, 0, System.Length(bs));

  end;
  Result := total;
end;

class function TStreams.ReadAll(const inStr: TStream): TCryptoLibByteArray;
var
  buf: TMemoryStream;
begin
  buf := TMemoryStream.Create();
  try
    PipeAll(inStr, buf);
    System.SetLength(Result, buf.Size);
    buf.Position := 0;
    buf.Read(Result[0], buf.Size);
  finally
    buf.Free;
  end;

end;

class function TStreams.ReadAllLimited(const inStr: TStream; limit: Int32)
  : TCryptoLibByteArray;
var
  buf: TMemoryStream;
begin
  buf := TMemoryStream.Create();
  try
    PipeAllLimited(inStr, limit, buf);
    System.SetLength(Result, buf.Size);
    buf.Position := 0;
    buf.Read(Result[0], buf.Size);
  finally
    buf.Free;
  end;

end;

class function TStreams.ReadFully(const inStr: TStream;
  var buf: TCryptoLibByteArray; off, len: Int32): Int32;
var
  totalRead, numRead: Int32;
begin
  totalRead := 0;

  while (totalRead < len) do
  begin

    numRead := TStreamSorter.Read(inStr, buf, off + totalRead, len - totalRead);
    if (numRead < 1) then
    begin
      break;
    end;
    totalRead := totalRead + numRead;
  end;
  Result := totalRead;
end;

class function TStreams.WriteBufTo(const buf: TMemoryStream;
  const output: TCryptoLibByteArray; offset: Int32): Int32;
var
  bytes: TCryptoLibByteArray;
begin
  buf.Position := 0;
  System.SetLength(bytes, buf.Size);
  buf.Read(bytes[0], buf.Size);
  System.Move(bytes[0], output[offset], System.Length(bytes) *
    System.SizeOf(Byte));
  Result := System.Length(bytes);
end;

class procedure TStreams.WriteZeroes(const outStr: TStream; count: Int64);
var
  zeroes: TCryptoLibByteArray;
begin
  System.SetLength(zeroes, BufferSize);
  while (count > BufferSize) do
  begin
    outStr.Write(zeroes[0], BufferSize);
    count := count - BufferSize;
  end;
  outStr.Write(zeroes[0], Int32(count));
end;

class function TStreams.ReadFully(const inStr: TStream;
  var buf: TCryptoLibByteArray): Int32;
begin
  Result := ReadFully(inStr, buf, 0, System.Length(buf));
end;

class procedure TStreams.WriteBufTo(const buf: TMemoryStream;
  const output: TStream);
begin
  output.CopyFrom(buf, buf.Size);
end;

end.
