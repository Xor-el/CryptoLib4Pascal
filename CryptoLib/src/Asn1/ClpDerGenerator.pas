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

unit ClpDerGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpBits,
  ClpCryptoLibTypes,
  ClpStreams,
  ClpStreamHelper,
  ClpAsn1Tags,
  ClpAsn1Generator,
  ClpIDerGenerator;

type
  TDerGenerator = class abstract(TAsn1Generator, IDerGenerator)

  strict private
  var
    F_tagged, F_isExplicit: Boolean;
    F_tagNo: Int32;

    class procedure WriteLength(const outStr: TStream; length: Int32); static;

  strict protected
    constructor Create(const outStream: TStream); overload;
    constructor Create(const outStream: TStream; tagNo: Int32;
      isExplicit: Boolean); overload;

  public
    procedure WriteDerEncoded(tag: Int32;
      const bytes: TCryptoLibByteArray); overload;
    class procedure WriteDerEncoded(const outStream: TStream; tag: Int32;
      const bytes: TCryptoLibByteArray); overload; static;

    class procedure WriteDerEncoded(const outStr: TStream; tag: Int32;
      const inStr: TStream); overload; static;

  end;

implementation

{ TDerGenerator }

constructor TDerGenerator.Create(const outStream: TStream);
begin
  Inherited Create(outStream);
end;

constructor TDerGenerator.Create(const outStream: TStream; tagNo: Int32;
  isExplicit: Boolean);
begin
  Inherited Create(outStream);
  F_tagged := true;
  F_isExplicit := isExplicit;
  F_tagNo := tagNo;
end;

class procedure TDerGenerator.WriteDerEncoded(const outStream: TStream;
  tag: Int32; const bytes: TCryptoLibByteArray);
begin
  outStream.WriteByte(Byte(tag));
  WriteLength(outStream, System.length(bytes));
  outStream.Write(bytes[0], System.length(bytes));
end;

procedure TDerGenerator.WriteDerEncoded(tag: Int32;
  const bytes: TCryptoLibByteArray);
var
  tagNum, newTag: Int32;
  bOut: TMemoryStream;
  temp: TCryptoLibByteArray;
begin
  if (F_tagged) then
  begin
    tagNum := F_tagNo or TAsn1Tags.Tagged;

    if (F_isExplicit) then
    begin
      newTag := F_tagNo or TAsn1Tags.Constructed or TAsn1Tags.Tagged;
      bOut := TMemoryStream.Create();
      try
        WriteDerEncoded(bOut, tag, bytes);
        bOut.Position := 0;
        System.SetLength(temp, bOut.Size);
        bOut.Read(temp[0], bOut.Size);
        WriteDerEncoded(&Out, newTag, temp);
      finally
        bOut.Free;
      end;
    end
    else
    begin
      if ((tag and TAsn1Tags.Constructed) <> 0) then
      begin
        tagNum := tagNum or TAsn1Tags.Constructed;
      end;

      WriteDerEncoded(&Out, tagNum, bytes);
    end;
  end
  else
  begin
    WriteDerEncoded(&Out, tag, bytes);
  end;
end;

class procedure TDerGenerator.WriteDerEncoded(const outStr: TStream; tag: Int32;
  const inStr: TStream);
begin
  WriteDerEncoded(outStr, tag, TStreams.ReadAll(inStr));
end;

class procedure TDerGenerator.WriteLength(const outStr: TStream; length: Int32);
var
  Size, val, i: Int32;
begin
  if (length > 127) then
  begin
    Size := 1;
    val := length;

    val := TBits.Asr32(val, 8);
    while (val <> 0) do
    begin
      System.Inc(Size);
      val := TBits.Asr32(val, 8);
    end;

    outStr.WriteByte(Byte(Size or $80));

    i := (Size - 1) * 8;

    while i >= 0 do
    begin
      outStr.WriteByte(Byte(TBits.Asr32(length, i)));
      System.Dec(i, 8);
    end;
  end
  else
  begin
    outStr.WriteByte(Byte(length));
  end;
end;

end.
