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

unit ClpNat384;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpNat,
  ClpNat192,
  ClpPack,
  ClpBigInteger,
  ClpBitUtilities,
  ClpCryptoLibTypes;

type
  TNat384 = class sealed
  public
    class procedure Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;

    class procedure Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;
  end;

implementation

{ TNat384 }

class procedure TNat384.Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array;
  AZz: TCryptoLibUInt32Array);
var
  LC18, LC12: UInt32;
  LDx, LDy, LTt: TCryptoLibUInt32Array;
  LNeg: Boolean;
begin
  TNat192.Mul(AX, AY, AZz);
  TNat192.Mul(AX, 6, AY, 6, AZz, 12);

  LC18 := TNat192.AddToEachOther(AZz, 6, AZz, 12);
  LC12 := LC18 + TNat192.AddTo(AZz, 0, AZz, 6, 0);
  LC18 := LC18 + TNat192.AddTo(AZz, 18, AZz, 12, LC12);

  LDx := TNat192.Create();
  LDy := TNat192.Create();
  LNeg := (TNat192.Diff(AX, 6, AX, 0, LDx, 0) <> TNat192.Diff(AY, 6, AY, 0, LDy, 0));

  LTt := TNat192.CreateExt();
  TNat192.Mul(LDx, LDy, LTt);

  if LNeg then
  begin
    LC18 := LC18 + TNat.AddTo(12, LTt, 0, AZz, 6);
  end
  else
  begin
    LC18 := LC18 + UInt32(TNat.SubFrom(12, LTt, 0, AZz, 6));
  end;

  TNat.AddWordAt(24, LC18, AZz, 18);
end;

class procedure TNat384.Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LC18, LC12: UInt32;
  LDx, LM: TCryptoLibUInt32Array;
begin
  TNat192.Square(AX, AZz);
  TNat192.Square(AX, 6, AZz, 12);

  LC18 := TNat192.AddToEachOther(AZz, 6, AZz, 12);
  LC12 := LC18 + TNat192.AddTo(AZz, 0, AZz, 6, 0);
  LC18 := LC18 + TNat192.AddTo(AZz, 18, AZz, 12, LC12);

  LDx := TNat192.Create();
  TNat192.Diff(AX, 6, AX, 0, LDx, 0);

  LM := TNat192.CreateExt();
  TNat192.Square(LDx, LM);

  LC18 := LC18 + UInt32(TNat.SubFrom(12, LM, 0, AZz, 6));
  TNat.AddWordAt(24, LC18, AZz, 18);
end;

end.
