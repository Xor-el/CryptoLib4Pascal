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
  ClpCryptoLibTypes,
  ClpIBaseInputStream;

type
  TBaseInputStream = class abstract(TStream, IBaseInputStream)

  strict protected
    function QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult; {$IFDEF MSWINDOWS} stdcall
{$ELSE} cdecl {$ENDIF MSWINDOWS};
    function _AddRef: Integer; {$IFDEF MSWINDOWS} stdcall {$ELSE} cdecl
{$ENDIF MSWINDOWS};
    function _Release: Integer; {$IFDEF MSWINDOWS} stdcall {$ELSE} cdecl
{$ENDIF MSWINDOWS};
  public
    function ReadByte: Int32; virtual;
    function Read(Buffer: TCryptoLibByteArray; Offset, Count: Longint): Int32;
{$IFDEF SUPPORT_TSTREAM_READ_BYTEARRAY_OVERLOAD} override {$ELSE} virtual
{$ENDIF SUPPORT_TSTREAM_READ_BYTEARRAY_OVERLOAD};
  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpStreamSorter;

{ TBaseInputStream }

function TBaseInputStream.QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult;
begin
  if GetInterface(IID, Obj) then
    result := 0
  else
    result := E_NOINTERFACE;
end;

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

function TBaseInputStream.Read(Buffer: TCryptoLibByteArray;
  Offset, Count: Longint): Int32;
var
  &pos, endPoint, b: Int32;

begin
  pos := Offset;
  try
    endPoint := Offset + Count;
    while (pos < endPoint) do
    begin
      b := ReadByte();
      if (b = -1) then
      begin
        break;
      end;
      Buffer[pos] := Byte(b);
      System.Inc(pos);
    end;
  except
    on e: EIOCryptoLibException do
    begin
      if (pos = Offset) then
        raise;
    end;

  end;

  result := pos - Offset;
end;

function TBaseInputStream._AddRef: Integer;
begin
  result := -1;
end;

function TBaseInputStream._Release: Integer;
begin
  result := -1;
end;

end.
