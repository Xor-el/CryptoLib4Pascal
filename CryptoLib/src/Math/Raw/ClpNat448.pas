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

unit ClpNat448;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpNat,
  ClpNat224,
  ClpPack,
  ClpBigInteger,
  ClpBitUtilities,
  ClpCryptoLibTypes;

type
  TNat448 = class sealed
  public
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;

    class function Create64(): TCryptoLibUInt64Array; static;
    class function CreateExt64(): TCryptoLibUInt64Array; static;

    class function Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean; static;
    class function IsOne64(const AX: TCryptoLibUInt64Array): Boolean; static;
    class function IsZero64(const AX: TCryptoLibUInt64Array): Boolean; static;

    class procedure Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;

    class procedure Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;

    class function ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger; static;
  end;

implementation

{ TNat448 }

class procedure TNat448.Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
begin
  System.Move(AX[0], AZ[0], 7 * System.SizeOf(UInt64));
end;

class procedure TNat448.Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array;
  AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 7 * System.SizeOf(UInt64));
end;

class function TNat448.Create64(): TCryptoLibUInt64Array;
begin
  System.SetLength(Result, 7);
end;

class function TNat448.CreateExt64(): TCryptoLibUInt64Array;
begin
  System.SetLength(Result, 14);
end;

class function TNat448.Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  for LI := 6 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat448.IsOne64(const AX: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> UInt64(1) then
  begin
    Result := False;
    Exit;
  end;

  for LI := 1 to 6 do
  begin
    if AX[LI] <> UInt64(0) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

class function TNat448.IsZero64(const AX: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to 6 do
  begin
    if AX[LI] <> UInt64(0) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

class procedure TNat448.Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array;
  AZz: TCryptoLibUInt32Array);
var
  LC21, LC14: UInt32;
  LDx, LDy, LTt: TCryptoLibUInt32Array;
  LNeg: Boolean;
begin
  TNat224.Mul(AX, AY, AZz);
  TNat224.Mul(AX, 7, AY, 7, AZz, 14);

  LC21 := TNat224.AddToEachOther(AZz, 7, AZz, 14);
  LC14 := LC21 + TNat224.AddTo(AZz, 0, AZz, 7, UInt32(0));
  LC21 := LC21 + TNat224.AddTo(AZz, 21, AZz, 14, LC14);

  LDx := TNat224.Create();
  LDy := TNat224.Create();
  LNeg := (TNat224.Diff(AX, 7, AX, 0, LDx, 0) <> TNat224.Diff(AY, 7, AY, 0, LDy, 0));

  LTt := TNat224.CreateExt();
  TNat224.Mul(LDx, LDy, LTt);

  if LNeg then
  begin
    LC21 := LC21 + TNat.AddTo(14, LTt, 0, AZz, 7);
  end
  else
  begin
    LC21 := LC21 + UInt32(TNat.SubFrom(14, LTt, 0, AZz, 7));
  end;

  TNat.AddWordAt(28, LC21, AZz, 21);
end;

class procedure TNat448.Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LC21, LC14: UInt32;
  LDx, LTt: TCryptoLibUInt32Array;
begin
  TNat224.Square(AX, AZz);
  TNat224.Square(AX, 7, AZz, 14);

  LC21 := TNat224.AddToEachOther(AZz, 7, AZz, 14);
  LC14 := LC21 + TNat224.AddTo(AZz, 0, AZz, 7, UInt32(0));
  LC21 := LC21 + TNat224.AddTo(AZz, 21, AZz, 14, LC14);

  LDx := TNat224.Create();
  TNat224.Diff(AX, 7, AX, 0, LDx, 0);

  LTt := TNat224.CreateExt();
  TNat224.Square(LDx, LTt);

  LC21 := LC21 + UInt32(TNat.SubFrom(14, LTt, 0, AZz, 7));
  TNat.AddWordAt(28, LC21, AZz, 21);
end;

class function TNat448.ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LI: Int32;
  LXi: UInt64;
begin
  System.SetLength(LBs, 56);
  for LI := 0 to 6 do
  begin
    LXi := AX[LI];
    if LXi <> UInt64(0) then
    begin
      TPack.UInt64_To_BE(LXi, LBs, (6 - LI) shl 3);
    end;
  end;

  Result := TBigInteger.Create(1, LBs);
end;

end.
