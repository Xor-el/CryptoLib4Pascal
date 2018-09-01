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

unit ClpBaseInputStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

type
  TBaseInputStream = class abstract(TStream)

{$IFDEF DELPHI}
  private

    function GetPosition: Int64; inline;
    procedure SetPosition(const Pos: Int64); inline;
    procedure SetSize64(const NewSize: Int64); inline;
{$ENDIF DELPHI}
  protected

{$IFDEF FPC}
    function GetPosition: Int64; override;
    procedure SetPosition(const Pos: Int64); override;
    procedure SetSize64(const NewSize: Int64); override;
{$ENDIF FPC}
    function GetSize: Int64; override;
    procedure SetSize(NewSize: LongInt); overload; override;
    procedure SetSize(const NewSize: Int64); overload; override;

    function QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult; {$IFDEF MSWINDOWS} stdcall
{$ELSE} cdecl {$ENDIF MSWINDOWS};
    function _AddRef: Integer; {$IFDEF MSWINDOWS} stdcall {$ELSE} cdecl
{$ENDIF MSWINDOWS};
    function _Release: Integer; {$IFDEF MSWINDOWS} stdcall {$ELSE} cdecl
{$ENDIF MSWINDOWS};
  public
    function ReadByte: Int32; virtual;

    function Read(var Buffer; Count: LongInt): LongInt; overload; override;
    function Write(const Buffer; Count: LongInt): LongInt; overload; override;

    function Read(Buffer: TCryptoLibByteArray; Offset, Count: LongInt)
      : Int32; overload;
{$IFDEF SUPPORT_TSTREAM_READ_BYTEARRAY_OVERLOAD} override {$ELSE} virtual
{$ENDIF SUPPORT_TSTREAM_READ_BYTEARRAY_OVERLOAD};

    function Write(const Buffer: TCryptoLibByteArray; Offset, Count: LongInt)
      : Int32; overload;
{$IFDEF SUPPORT_TSTREAM_WRITE_BYTEARRAY_OVERLOAD} override {$ELSE} virtual
{$ENDIF SUPPORT_TSTREAM_WRITE_BYTEARRAY_OVERLOAD};

    function Seek(Offset: LongInt; Origin: Word): LongInt; overload; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
      overload; override;

{$IFNDEF _FIXINSIGHT_}
    property Size: Int64 read GetSize write SetSize64;
{$ENDIF}
    property Position: Int64 read GetPosition write SetPosition;
  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpStreamSorter;

{ TBaseInputStream }

function TBaseInputStream.GetPosition: Int64;
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

function TBaseInputStream.GetSize: Int64;
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

function TBaseInputStream.QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult;
begin
  if GetInterface(IID, Obj) then
    result := 0
  else
    result := E_NOINTERFACE;
end;

{$IFNDEF _FIXINSIGHT_}

function TBaseInputStream.Read(var Buffer; Count: LongInt): LongInt;
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

function TBaseInputStream.Write(const Buffer; Count: LongInt): LongInt;
begin
  raise ENotSupportedCryptoLibException.Create('');
end;
{$ENDIF}

function TBaseInputStream.ReadByte: Int32;
var
  Buffer: TCryptoLibByteArray;
begin
  System.SetLength(Buffer, 1);

  // if (Read(Buffer, 0, 1) = 0) then
  if (TStreamSorter.Read(Self, Buffer, 0, 1) = 0) then
  begin
    result := -1;
  end
  else
  begin
    result := Int32(Buffer[0]);
  end;
end;

function TBaseInputStream.Seek(Offset: LongInt; Origin: Word): LongInt;
begin
  result := Seek(Int64(Offset), TSeekOrigin(Origin));
end;

{$IFNDEF _FIXINSIGHT_}

function TBaseInputStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

procedure TBaseInputStream.SetPosition(const Pos: Int64);
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

{$ENDIF}

procedure TBaseInputStream.SetSize(const NewSize: Int64);
begin
  SetSize(LongInt(NewSize));
end;

procedure TBaseInputStream.SetSize(NewSize: LongInt);
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

procedure TBaseInputStream.SetSize64(const NewSize: Int64);
begin
  SetSize(NewSize);
end;

function TBaseInputStream.Read(Buffer: TCryptoLibByteArray;
  Offset, Count: LongInt): Int32;
var
  &pos, endPoint, b: Int32;

begin
  Pos := Offset;
  try
    endPoint := Offset + Count;
    while (Pos < endPoint) do
    begin
      b := ReadByte();
      if (b = -1) then
      begin
        break;
      end;
      Buffer[Pos] := Byte(b);
      System.Inc(Pos);
    end;
  except
    on e: EIOCryptoLibException do
    begin
      if (Pos = Offset) then
        raise;
    end;

  end;

  result := Pos - Offset;
end;

{$IFNDEF _FIXINSIGHT_}

function TBaseInputStream.Write(const Buffer: TCryptoLibByteArray;
  Offset, Count: LongInt): Int32;
begin
  raise ENotSupportedCryptoLibException.Create('');
end;

{$ENDIF}

function TBaseInputStream._AddRef: Integer;
begin
  result := -1;
end;

function TBaseInputStream._Release: Integer;
begin
  result := -1;
end;

end.
