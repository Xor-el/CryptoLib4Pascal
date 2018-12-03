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

unit ClpFilterStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpStreamHelper,
  ClpDefiniteLengthInputStream;

type
  TFilterStream = class(TStream)

  protected
  var
    Fs: TStream;

    function GetPosition: Int64; {$IFDEF FPC} override; {$ENDIF FPC}
    procedure SetPosition(const Value: Int64); {$IFDEF FPC} override;
{$ENDIF FPC}
    function GetSize: Int64; override;

  public
    constructor Create(const s: TStream);

    property Size: Int64 read GetSize;
    property Position: Int64 read GetPosition write SetPosition;

    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
    function Read(var Buffer; Count: LongInt): LongInt; override;
    function Write(const Buffer; Count: LongInt): LongInt; override;

    function ReadByte(): Int32;
    procedure WriteByte(Value: Byte);

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpStreamSorter;

{ TFilterStream }

constructor TFilterStream.Create(const s: TStream);
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

function TFilterStream.Write(const Buffer; Count: LongInt): LongInt;
begin
  Result := Fs.Write(PByte(Buffer), Count);
end;

procedure TFilterStream.WriteByte(Value: Byte);
begin
  Fs.WriteByte(Value);
end;

function TFilterStream.GetSize: Int64;
begin
  Result := Fs.Size;
end;

function TFilterStream.Read(var Buffer; Count: LongInt): LongInt;
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
