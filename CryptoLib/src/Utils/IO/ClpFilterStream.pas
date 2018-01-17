{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpFilterStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpStreamHelper,
  ClpDefiniteLengthInputStream,
  ClpIFilterStream;

type
  TFilterStream = class(TStream, IFilterStream)

  strict private

    function GetPosition: Int64;
    procedure SetPosition(const Value: Int64);

  strict protected
  var
    Fs: TStream;

    function GetSize: Int64; override;

    function QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult; stdcall;
    function _AddRef: Integer; stdcall;
    function _Release: Integer; stdcall;

  public
    constructor Create(s: TStream);

    property Size: Int64 read GetSize;
    property Position: Int64 read GetPosition write SetPosition;

    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
    function Read(var Buffer; Count: Int32): Int32; override;
    function Write(const Buffer; Count: Int32): Int32; override;

    function ReadByte(): Int32; inline;
    procedure WriteByte(Value: Byte); inline;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpStreamSorter;

{ TFilterStream }

constructor TFilterStream.Create(s: TStream);
begin
  inherited Create();
  Fs := s;
end;

function TFilterStream.GetPosition: Int64;
begin
  Result := Fs.Position;
end;

procedure TFilterStream.SetPosition(const Value: Int64);
begin
  Fs.Position := Value;
end;

function TFilterStream.Write(const Buffer; Count: Int32): Int32;
begin
  Result := Fs.Write(PByte(Buffer), Count);
end;

procedure TFilterStream.WriteByte(Value: Byte);
begin
  Fs.WriteByte(Value);
end;

function TFilterStream._AddRef: Integer;
begin
  Result := -1;
end;

function TFilterStream._Release: Integer;
begin
  Result := -1;
end;

function TFilterStream.GetSize: Int64;
begin
  Result := Fs.Size;
end;

function TFilterStream.QueryInterface({$IFDEF FPC}constref {$ELSE}const
{$ENDIF FPC} IID: TGUID; out Obj): HResult;
begin
  if GetInterface(IID, Obj) then
    Result := 0
  else
    Result := E_NOINTERFACE;
end;

function TFilterStream.Read(var Buffer; Count: Int32): Int32;
begin
  Result := Fs.Read(PByte(Buffer), Count);
end;

function TFilterStream.ReadByte: Int32;
begin

  Result := TStreamSorter.ReadByte(Fs);

end;

function TFilterStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  Result := Fs.Seek(Offset, Origin);
end;

end.
