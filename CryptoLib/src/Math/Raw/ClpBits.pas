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

unit ClpBits;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils;

type
  TBits = class sealed
  public
    class function BitPermuteStep(AX: UInt32; AM: UInt32; &AS: Int32): UInt32; overload; static;
    class function BitPermuteStep(AX: UInt64; AM: UInt64; &AS: Int32): UInt64; overload; static;

    class procedure BitPermuteStep2(var AHi: UInt32; var ALo: UInt32; AM: UInt32; &AS: Int32); overload; static;
    class procedure BitPermuteStep2(var AHi: UInt64; var ALo: UInt64; AM: UInt64; &AS: Int32); overload; static;

    class function BitPermuteStepSimple(AX: UInt32; AM: UInt32; &AS: Int32): UInt32; overload; static;
    class function BitPermuteStepSimple(AX: UInt64; AM: UInt64; &AS: Int32): UInt64; overload; static;
  end;

implementation

{ TBits }

class function TBits.BitPermuteStep(AX: UInt32; AM: UInt32; &AS: Int32): UInt32;
var
  LT: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((AM and (AM shl &AS)) = 0);
  System.Assert(((AM shl &AS) shr &AS) = AM);
  {$ENDIF}

  LT := (AX xor (AX shr &AS)) and AM;
  Result := LT xor (LT shl &AS) xor AX;
end;

class function TBits.BitPermuteStep(AX: UInt64; AM: UInt64; &AS: Int32): UInt64;
var
  LT: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((AM and (AM shl &AS)) = 0);
  System.Assert(((AM shl &AS) shr &AS) = AM);
  {$ENDIF}

  LT := (AX xor (AX shr &AS)) and AM;
  Result := LT xor (LT shl &AS) xor AX;
end;

class procedure TBits.BitPermuteStep2(var AHi: UInt32; var ALo: UInt32; AM: UInt32; &AS: Int32);
var
  LT: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert(((AM shl &AS) shr &AS) = AM);
  {$ENDIF}

  LT := ((ALo shr &AS) xor AHi) and AM;
  ALo := ALo xor (LT shl &AS);
  AHi := AHi xor LT;
end;

class procedure TBits.BitPermuteStep2(var AHi: UInt64; var ALo: UInt64; AM: UInt64; &AS: Int32);
var
  LT: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(((AM shl &AS) shr &AS) = AM);
  {$ENDIF}

  LT := ((ALo shr &AS) xor AHi) and AM;
  ALo := ALo xor (LT shl &AS);
  AHi := AHi xor LT;
end;

class function TBits.BitPermuteStepSimple(AX: UInt32; AM: UInt32; &AS: Int32): UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((AM shl &AS) = not AM);
  System.Assert((AM and (not AM)) = 0);
  {$ENDIF}

  Result := ((AX and AM) shl &AS) or ((AX shr &AS) and AM);
end;

class function TBits.BitPermuteStepSimple(AX: UInt64; AM: UInt64; &AS: Int32): UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((AM shl &AS) = not AM);
  System.Assert((AM and (not AM)) = 0);
  {$ENDIF}

  Result := ((AX and AM) shl &AS) or ((AX shr &AS) and AM);
end;

end.
