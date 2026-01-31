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

unit ClpNat576;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpPack,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TNat576 = class sealed
  public
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class function Create64(): TCryptoLibUInt64Array; static;
    class function CreateExt64(): TCryptoLibUInt64Array; static;
    class function Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean; static;
    class function IsOne64(const AX: TCryptoLibUInt64Array): Boolean; static;
    class function IsZero64(const AX: TCryptoLibUInt64Array): Boolean; static;
    class function ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger; static;
  end;

implementation

{ TNat576 }

class procedure TNat576.Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
begin
  System.Move(AX[0], AZ[0], 9 * System.SizeOf(UInt64));
end;

class procedure TNat576.Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 9 * System.SizeOf(UInt64));
end;

class function TNat576.Create64(): TCryptoLibUInt64Array;
begin
  System.SetLength(Result, 9);
end;

class function TNat576.CreateExt64(): TCryptoLibUInt64Array;
begin
  System.SetLength(Result, 18);
end;

class function TNat576.Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  for LI := 8 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat576.IsOne64(const AX: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> UInt64(1) then
  begin
    Result := False;
    Exit;
  end;

  for LI := 1 to 8 do
  begin
    if AX[LI] <> UInt64(0) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

class function TNat576.IsZero64(const AX: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to 8 do
  begin
    if AX[LI] <> UInt64(0) then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat576.ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger;
var
  LBs: TBytes;
  LI: Int32;
  LXI: UInt64;
begin
  System.SetLength(LBs, 72);
  for LI := 0 to 8 do
  begin
    LXI := AX[LI];
    if LXI <> UInt64(0) then
    begin
      TPack.UInt64_To_BE(LXI, LBs, (8 - LI) shl 3);
    end;
  end;
  Result := TBigInteger.Create(1, LBs);
end;

end.
