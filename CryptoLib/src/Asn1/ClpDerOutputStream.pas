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

unit ClpDerOutputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpBits,
  ClpAsn1Tags,
  ClpCryptoLibTypes,
  ClpIFilterStream,
  ClpIProxiedInterface,
  ClpFilterStream;

type
  TDerOutputStream = class(TFilterStream, IFilterStream, IDerOutputStream)

  strict private
    procedure WriteLength(length: Int32);

  strict protected
    procedure WriteNull();

  public
    constructor Create(const os: TStream);
    procedure WriteEncoded(tag: Int32;
      const bytes: TCryptoLibByteArray); overload;
    procedure WriteEncoded(tag: Int32; first: Byte;
      const bytes: TCryptoLibByteArray); overload;
    procedure WriteEncoded(tag: Int32; const bytes: TCryptoLibByteArray;
      offset, length: Int32); overload;
    procedure WriteEncoded(flags, tagNo: Int32;
      const bytes: TCryptoLibByteArray); overload;
    procedure WriteTag(flags, tagNo: Int32);

    procedure WriteObject(const obj: IAsn1Encodable); overload; virtual;
    procedure WriteObject(const obj: IAsn1Object); overload; virtual;

  end;

implementation

{ TDerOutputStream }

constructor TDerOutputStream.Create(const os: TStream);
begin
  Inherited Create(os);
end;

procedure TDerOutputStream.WriteEncoded(tag: Int32; first: Byte;
  const bytes: TCryptoLibByteArray);
begin
  WriteByte(Byte(tag));
  WriteLength(System.length(bytes) + 1);
  WriteByte(first);
  Write(bytes[0], System.length(bytes));
end;

procedure TDerOutputStream.WriteEncoded(tag: Int32;
  const bytes: TCryptoLibByteArray);
begin
  WriteByte(Byte(tag));
  WriteLength(System.length(bytes));
  Write(bytes[0], System.length(bytes));
end;

procedure TDerOutputStream.WriteEncoded(flags, tagNo: Int32;
  const bytes: TCryptoLibByteArray);
begin
  WriteTag(flags, tagNo);
  WriteLength(System.length(bytes));
  Write(bytes[0], System.length(bytes));
end;

procedure TDerOutputStream.WriteEncoded(tag: Int32;
  const bytes: TCryptoLibByteArray; offset, length: Int32);
begin
  WriteByte(Byte(tag));
  WriteLength(length);
  Write(bytes[offset], length);
end;

procedure TDerOutputStream.WriteLength(length: Int32);
var
  size, i: Int32;
  val: UInt32;
begin
  if (length > 127) then
  begin
    size := 1;
    val := UInt32(length);
    val := val shr 8;
    while (val <> 0) do
    begin
      System.Inc(size);
      val := val shr 8;
    end;

    WriteByte(Byte(size or $80));

    i := (size - 1) * 8;

    while i >= 0 do
    begin
      WriteByte(Byte(TBits.Asr32(length, i)));
      System.Dec(i, 8);
    end;

  end
  else
  begin
    WriteByte(Byte(length));
  end;
end;

procedure TDerOutputStream.WriteNull;
begin
  WriteByte(TAsn1Tags.Null);
  WriteByte($00);
end;

procedure TDerOutputStream.WriteObject(const obj: IAsn1Encodable);
var
  asn1: IAsn1Object;
begin
  if (obj = Nil) then
  begin
    WriteNull();
  end
  else
  begin
    asn1 := obj.ToAsn1Object();
    asn1.Encode(Self);
  end;
end;

procedure TDerOutputStream.WriteObject(const obj: IAsn1Object);
begin
  if (obj = Nil) then
  begin
    WriteNull();
  end
  else
  begin
    obj.Encode(Self);
  end;
end;

procedure TDerOutputStream.WriteTag(flags, tagNo: Int32);
var
  stack: TCryptoLibByteArray;
  pos: Int32;
begin
  if (tagNo < 31) then
  begin
    WriteByte(Byte(flags or tagNo));
  end
  else
  begin
    WriteByte(Byte(flags or $1F));
    if (tagNo < 128) then
    begin
      WriteByte(Byte(tagNo));
    end
    else
    begin
      System.SetLength(stack, 5);
      pos := System.length(stack);

      System.Dec(pos);
      stack[pos] := Byte(tagNo and $7F);

      repeat
        tagNo := TBits.Asr32(tagNo, 7);
        System.Dec(pos);
        stack[pos] := Byte(tagNo and $7F or $80);
      until (not(tagNo > 127));

      Write(stack[pos], System.length(stack) - pos);
    end;
  end;
end;

end.
