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

unit ClpMod;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpISecureRandom,
  ClpPack,
  ClpNat,
  ClpBitUtilities,
  ClpCryptoLibTypes;

type
   /// <summary>
  /// Modular inversion as implemented in this class is based on the paper "Fast constant-time gcd computation and
  /// modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
  /// </summary>
  /// <remarks>
  /// In some cases (when it is faster) we use the "half delta" variant of safegcd based on
  /// <a href="https://github.com/sipa/safegcd-bounds">hddivsteps</a>.
  /// </remarks>
  TMod = class sealed
  private
    const M30: Int32 = $3FFFFFFF;
    const M32UL: UInt64 = UInt64($FFFFFFFF);

    class function Add30(ALen30: Int32; const AD: TCryptoLibInt32Array; const AM: TCryptoLibInt32Array): Int32; static;
    class procedure CNegate30(ALen30: Int32; ACond: Int32; const AD: TCryptoLibInt32Array); static;
    class procedure CNormalize30(ALen30: Int32; ACondNegate: Int32; const AD: TCryptoLibInt32Array;
      const AM: TCryptoLibInt32Array); static;

    class procedure Decode30(ABits: Int32; const AX: TCryptoLibInt32Array; const AZ: TCryptoLibUInt32Array); static;
    class function Divsteps30Var(AEta: Int32; AF0: Int32; AG0: Int32; const AT: TCryptoLibInt32Array): Int32; static;
    class procedure Encode30(ABits: Int32; const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibInt32Array); static;

    class function EqualTo(ALen: Int32; const AX: TCryptoLibInt32Array; AY: Int32): Int32; static;
    class function EqualToVar(ALen: Int32; const AX: TCryptoLibInt32Array; AY: Int32): Boolean; static;

    class function GetMaximumDivsteps(ABits: Int32): Int32; static;
    class function GetMaximumHDDivsteps(ABits: Int32): Int32; static;

    class function HDDivsteps30(ATheta: Int32; AF0: Int32; AG0: Int32; const AT: TCryptoLibInt32Array): Int32; static;

    class function Negate30(ALen30: Int32; const AD: TCryptoLibInt32Array): Int32; static;
    class function TrimFG30Var(ALen30: Int32; const AF: TCryptoLibInt32Array; const AG: TCryptoLibInt32Array): Int32; static;

    class procedure UpdateDE30(ALen30: Int32; const AD: TCryptoLibInt32Array; const AE: TCryptoLibInt32Array;
      const AT: TCryptoLibInt32Array; AM0Inv32: Int32; const AM: TCryptoLibInt32Array); static;

    class procedure UpdateFG30(ALen30: Int32; const AF: TCryptoLibInt32Array; const AG: TCryptoLibInt32Array;
      const AT: TCryptoLibInt32Array); static;

  public
    class procedure CheckedModOddInverse(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibUInt32Array); static;

    class procedure CheckedModOddInverseVar(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibUInt32Array); static;

    class function Inverse32(AD: UInt32): UInt32; static;
    class function Inverse64(AD: UInt64): UInt64; static;

    class function ModOddInverse(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibUInt32Array): UInt32; static;

    class function ModOddInverseVar(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibUInt32Array): Boolean; static;

    class function ModOddIsCoprime(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array): UInt32; static;
    class function ModOddIsCoprimeVar(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array): Boolean; static;

    class function Random(const ARandom: ISecureRandom; const AP: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
  end;

implementation

{ TMod }

class procedure TMod.CheckedModOddInverse(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibUInt32Array);
begin
  if ModOddInverse(AM, AX, AZ) = 0 then
    raise EArithmeticCryptoLibException.Create('Inverse does not exist.');
end;

class procedure TMod.CheckedModOddInverseVar(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibUInt32Array);
begin
  if not ModOddInverseVar(AM, AX, AZ) then
    raise EArithmeticCryptoLibException.Create('Inverse does not exist.');
end;

class function TMod.Inverse32(AD: UInt32): UInt32;
var
  LX: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((AD and 1) = 1);
  {$ENDIF}

  LX := AD;
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  {$IFDEF DEBUG}
  System.Assert(AD * LX = 1);
  {$ENDIF}
  Result := LX;
end;

class function TMod.Inverse64(AD: UInt64): UInt64;
var
  LX: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((AD and 1) = 1);
  {$ENDIF}

  LX := AD;
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  LX := LX * (2 - AD * LX);
  {$IFDEF DEBUG}
  System.Assert(AD * LX = 1);
  {$ENDIF}
  Result := LX;
end;

class function TMod.ModOddInverse(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibUInt32Array): UInt32;
var
  LLen32, LBits, LLen30, LAllocSize: Int32;
  LT, LD, LE, LF, LG, LM: TCryptoLibInt32Array;
  LTheta, LM0Inv32, LMaxDivsteps, LSignF: Int32;
  LDivSteps: Int32;
begin
  LLen32 := System.Length(AM);
  {$IFDEF DEBUG}
  System.Assert(LLen32 > 0);
  System.Assert((AM[0] and 1) <> 0);
  System.Assert(AM[LLen32 - 1] <> 0);
  {$ENDIF}

  LBits := (LLen32 shl 5) - TBitUtilities.NumberOfLeadingZeros32(AM[LLen32 - 1]);
  LLen30 := (LBits + 29) div 30;

  SetLength(LT, 4);
  SetLength(LD, LLen30);
  SetLength(LE, LLen30);
  SetLength(LF, LLen30);
  SetLength(LG, LLen30);
  SetLength(LM, LLen30);

  LE[0] := 1;
  Encode30(LBits, AX, LG);
  Encode30(LBits, AM, LM);

  System.Move(LM[0], LF[0], LLen30 * SizeOf(Int32));

  LTheta := 0;
  LM0Inv32 := Int32(Inverse32(UInt32(LM[0])));
  LMaxDivsteps := GetMaximumHDDivsteps(LBits);

  LDivSteps := 0;
  while LDivSteps < LMaxDivsteps do
  begin
    LTheta := HDDivsteps30(LTheta, LF[0], LG[0], LT);
    UpdateDE30(LLen30, LD, LE, LT, LM0Inv32, LM);
    UpdateFG30(LLen30, LF, LG, LT);
    Inc(LDivSteps, 30);
  end;

  LSignF := TBitUtilities.Asr32(LF[LLen30 - 1], 31);
  CNegate30(LLen30, LSignF, LF);

  CNormalize30(LLen30, LSignF, LD, LM);

  Decode30(LBits, LD, AZ);

  {$IFDEF DEBUG}
  System.Assert(TNat.LessThan(LLen32, AZ, AM) <> 0);
  {$ENDIF}

  Result := UInt32(EqualTo(LLen30, LF, 1) and EqualTo(LLen30, LG, 0));
end;

class function TMod.ModOddInverseVar(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibUInt32Array): Boolean;
var
  LLen32, LBits, LLen30, LClz: Int32;
  LT, LD, LE, LF, LG, LM: TCryptoLibInt32Array;
  LEta, LLenDE, LLenFG, LM0Inv32, LMaxDivsteps: Int32;
  LDivsteps: Int32;
  LSignF, LSignD: Int32;
begin
  LLen32 := System.Length(AM);
  {$IFDEF DEBUG}
  System.Assert(LLen32 > 0);
  System.Assert((AM[0] and 1) <> 0);
  System.Assert(AM[LLen32 - 1] <> 0);
  {$ENDIF}

  LBits := (LLen32 shl 5) - TBitUtilities.NumberOfLeadingZeros32(AM[LLen32 - 1]);
  LLen30 := (LBits + 29) div 30;

  LClz := LBits - TNat.GetBitLength(LLen32, AX);
  {$IFDEF DEBUG}
  System.Assert(LClz >= 0);
  {$ENDIF}

  SetLength(LT, 4);
  SetLength(LD, LLen30);
  SetLength(LE, LLen30);
  SetLength(LF, LLen30);
  SetLength(LG, LLen30);
  SetLength(LM, LLen30);

  LE[0] := 1;
  Encode30(LBits, AX, LG);
  Encode30(LBits, AM, LM);
  System.Move(LM[0], LF[0], LLen30 * SizeOf(Int32));

  // We use the original safegcd here, with eta == 1 - delta
  // For shorter x, configure as if low zeros of x had been shifted away by divsteps
  LEta := -LClz;
  LLenDE := LLen30;
  LLenFG := LLen30;
  LM0Inv32 := Int32(Inverse32(UInt32(LM[0])));
  LMaxDivsteps := GetMaximumDivsteps(LBits);

  LDivsteps := LClz;
  while not EqualToVar(LLenFG, LG, 0) do
  begin
    if LDivsteps >= LMaxDivsteps then
      Exit(False);

    Inc(LDivsteps, 30);

    LEta := Divsteps30Var(LEta, LF[0], LG[0], LT);
    UpdateDE30(LLenDE, LD, LE, LT, LM0Inv32, LM);
    UpdateFG30(LLenFG, LF, LG, LT);
    LLenFG := TrimFG30Var(LLenFG, LF, LG);
  end;

  LSignF := TBitUtilities.Asr32(LF[LLenFG - 1], 31);

  // D is in the range (-2.M, M) ...
  LSignD := TBitUtilities.Asr32(LD[LLenDE - 1], 31);
  if LSignD < 0 then
    LSignD := Add30(LLenDE, LD, LM);

  if LSignF < 0 then
  begin
    LSignD := Negate30(LLenDE, LD);
    LSignF := Negate30(LLenFG, LF);
  end;

  {$IFDEF DEBUG}
  System.Assert(LSignF = 0);
  {$ENDIF}

  if not EqualToVar(LLenFG, LF, 1) then
    Exit(False);

  if LSignD < 0 then
    LSignD := Add30(LLenDE, LD, LM);

  {$IFDEF DEBUG}
  System.Assert(LSignD = 0);
  {$ENDIF}

  Decode30(LBits, LD, AZ);

  {$IFDEF DEBUG}
  System.Assert(not TNat.Gte(LLen32, AZ, AM));
  {$ENDIF}

  Result := True;
end;

class function TMod.ModOddIsCoprime(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array): UInt32;
var
  LLen32, LBits, LLen30: Int32;
  LT, LF, LG, LM: TCryptoLibInt32Array;
  LTheta, LMaxDivsteps, LDivSteps, LSignF: Int32;
begin
  LLen32 := System.Length(AM);
  {$IFDEF DEBUG}
  System.Assert(LLen32 > 0);
  System.Assert((AM[0] and 1) <> 0);
  System.Assert(AM[LLen32 - 1] <> 0);
  {$ENDIF}

  LBits := (LLen32 shl 5) - TBitUtilities.NumberOfLeadingZeros32(AM[LLen32 - 1]);
  LLen30 := (LBits + 29) div 30;

  SetLength(LT, 4);
  SetLength(LF, LLen30);
  SetLength(LG, LLen30);
  SetLength(LM, LLen30);

  Encode30(LBits, AX, LG);
  Encode30(LBits, AM, LM);
  System.Move(LM[0], LF[0], LLen30 * SizeOf(Int32));

  LTheta := 0;
  LMaxDivsteps := GetMaximumHDDivsteps(LBits);

  LDivSteps := 0;
  while LDivSteps < LMaxDivsteps do
  begin
    LTheta := HDDivsteps30(LTheta, LF[0], LG[0], LT);
    UpdateFG30(LLen30, LF, LG, LT);
    Inc(LDivSteps, 30);
  end;

  LSignF := TBitUtilities.Asr32(LF[LLen30 - 1], 31);
  CNegate30(LLen30, LSignF, LF);

  Result := UInt32(EqualTo(LLen30, LF, 1) and EqualTo(LLen30, LG, 0));
end;

class function TMod.ModOddIsCoprimeVar(const AM: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array): Boolean;
var
  LLen32, LBits, LLen30, LClz: Int32;
  LT, LF, LG, LM: TCryptoLibInt32Array;
  LEta, LLenFG, LMaxDivsteps, LDivsteps, LSignF: Int32;
begin
  LLen32 := System.Length(AM);
  {$IFDEF DEBUG}
  System.Assert(LLen32 > 0);
  System.Assert((AM[0] and 1) <> 0);
  System.Assert(AM[LLen32 - 1] <> 0);
  {$ENDIF}

  LBits := (LLen32 shl 5) - TBitUtilities.NumberOfLeadingZeros32(AM[LLen32 - 1]);
  LLen30 := (LBits + 29) div 30;

  LClz := LBits - TNat.GetBitLength(LLen32, AX);
  {$IFDEF DEBUG}
  System.Assert(LClz >= 0);
  {$ENDIF}

  SetLength(LT, 4);
  SetLength(LF, LLen30);
  SetLength(LG, LLen30);
  SetLength(LM, LLen30);

  Encode30(LBits, AX, LG);
  Encode30(LBits, AM, LM);
  System.Move(LM[0], LF[0], LLen30 * SizeOf(Int32));

  // We use the original safegcd here, with eta == 1 - delta
  // For shorter x, configure as if low zeros of x had been shifted away by divsteps
  LEta := -LClz;
  LLenFG := LLen30;
  LMaxDivsteps := GetMaximumDivsteps(LBits);

  LDivsteps := LClz;
  while not EqualToVar(LLenFG, LG, 0) do
  begin
    if LDivsteps >= LMaxDivsteps then
      Exit(False);

    Inc(LDivsteps, 30);

    LEta := Divsteps30Var(LEta, LF[0], LG[0], LT);
    UpdateFG30(LLenFG, LF, LG, LT);
    LLenFG := TrimFG30Var(LLenFG, LF, LG);
  end;

  LSignF := TBitUtilities.Asr32(LF[LLenFG - 1], 31);
  if LSignF < 0 then
  begin
    LSignF := Negate30(LLenFG, LF);
  end;

  {$IFDEF DEBUG}
  System.Assert(LSignF = 0);
  {$ENDIF}

  Result := EqualToVar(LLenFG, LF, 1);
end;

class function TMod.Random(const ARandom: ISecureRandom; const AP: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  LLen: Integer;
  LS: TCryptoLibUInt32Array;
  LM: UInt32;
  LBytes: TCryptoLibByteArray;
begin
  LLen := Length(AP);

  LS := TNat.Create(LLen);

  LM := AP[LLen - 1];
  LM := LM or (LM shr 1);
  LM := LM or (LM shr 2);
  LM := LM or (LM shr 4);
  LM := LM or (LM shr 8);
  LM := LM or (LM shr 16);

  SetLength(LBytes, LLen shl 2);

  repeat
    ARandom.NextBytes(LBytes);
    TPack.BE_To_UInt32(LBytes, 0, LS);

    LS[LLen - 1] := LS[LLen - 1] and LM;
  until not TNat.Gte(LLen, LS, AP);

  Result := LS;
end;

class function TMod.Add30(ALen30: Int32; const AD: TCryptoLibInt32Array; const AM: TCryptoLibInt32Array): Int32;
var
  LC, LLast, LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AD) >= ALen30);
  System.Assert(System.Length(AM) >= ALen30);
  {$ENDIF}

  LC := 0;
  LLast := ALen30 - 1;

  for LI := 0 to LLast - 1 do
  begin
    LC := LC + AD[LI] + AM[LI];
    AD[LI] := LC and M30;
    LC := TBitUtilities.Asr32(LC, 30);
  end;

  LC := LC + AD[LLast] + AM[LLast];
  AD[LLast] := LC;
  LC := TBitUtilities.Asr32(LC, 30);
  Result := LC;
end;

class procedure TMod.CNegate30(ALen30: Int32; ACond: Int32; const AD: TCryptoLibInt32Array);
var
  LC, LLast, LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AD) >= ALen30);
  {$ENDIF}

  LC := 0;
  LLast := ALen30 - 1;

  for LI := 0 to LLast - 1 do
  begin
    LC := LC + ((AD[LI] xor ACond) - ACond);
    AD[LI] := LC and M30;
    LC := TBitUtilities.Asr32(LC, 30);
  end;

  LC := LC + ((AD[LLast] xor ACond) - ACond);
  AD[LLast] := LC;
end;

class procedure TMod.CNormalize30(ALen30: Int32; ACondNegate: Int32; const AD: TCryptoLibInt32Array;
  const AM: TCryptoLibInt32Array);
var
  LLast, LI: Int32;
  LC, LCondAdd, LDi: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AD) >= ALen30);
  System.Assert(System.Length(AM) >= ALen30);
  {$ENDIF}

  LLast := ALen30 - 1;

  begin
    LC := 0;
    LCondAdd := TBitUtilities.Asr32(AD[LLast], 31);
    for LI := 0 to LLast - 1 do
    begin
      LDi := AD[LI] + (AM[LI] and LCondAdd);
      LDi := (LDi xor ACondNegate) - ACondNegate;
      LC := LC + LDi;
      AD[LI] := LC and M30;
      LC := TBitUtilities.Asr32(LC, 30);
    end;

    LDi := AD[LLast] + (AM[LLast] and LCondAdd);
    LDi := (LDi xor ACondNegate) - ACondNegate;
    LC := LC + LDi;
    AD[LLast] := LC;
  end;

  begin
    LC := 0;
    LCondAdd := TBitUtilities.Asr32(AD[LLast], 31);
    for LI := 0 to LLast - 1 do
    begin
      LDi := AD[LI] + (AM[LI] and LCondAdd);
      LC := LC + LDi;
      AD[LI] := LC and M30;
      LC := TBitUtilities.Asr32(LC, 30);
    end;

    LDi := AD[LLast] + (AM[LLast] and LCondAdd);
    LC := LC + LDi;
    AD[LLast] := LC;

    {$IFDEF DEBUG}
    System.Assert((TBitUtilities.Asr32(LC, 30)) = 0);
    {$ENDIF}
  end;
end;

class procedure TMod.Decode30(ABits: Int32; const AX: TCryptoLibInt32Array; const AZ: TCryptoLibUInt32Array);
var
  LAvail: Int32;
  LData: UInt64;
  LXOff, LZOff: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ABits > 0);
  {$ENDIF}

  LAvail := 0;
  LData := 0;

  LXOff := 0;
  LZOff := 0;

  while ABits > 0 do
  begin
    while LAvail < Min(32, ABits) do
    begin
      LData := LData or (UInt64(UInt32(AX[LXOff])) shl LAvail);
      Inc(LXOff);
      Inc(LAvail, 30);
    end;

    AZ[LZOff] := UInt32(LData);
    Inc(LZOff);
    LData := LData shr 32;
    Dec(LAvail, 32);
    Dec(ABits, 32);
  end;
end;

class function TMod.Divsteps30Var(AEta: Int32; AF0: Int32; AG0: Int32; const AT: TCryptoLibInt32Array): Int32;
var
  LU, LV, LQ, LR: Int32;
  LF, LG, LM, LW, LX, LY, LZ: Int32;
  LI, LLimit, LZeros: Int32;
begin
  LU := 1; LV := 0; LQ := 0; LR := 1;
  LF := AF0; LG := AG0;
  LI := 30;

  while True do
  begin
    // sentinel bit to count zeros only up to i.
    //LZeros := TBitUtilities.NumberOfTrailingZeros(UInt32(LG) or (-1 shl LI));
    LZeros := TBitUtilities.NumberOfTrailingZeros32(UInt32(LG) or (UInt32($FFFFFFFF) shl LI));

    LG := TBitUtilities.Asr32(LG, LZeros);
    LU := LU shl LZeros;
    LV := LV shl LZeros;
    AEta := AEta - LZeros;
    LI := LI - LZeros;

    if LI <= 0 then
      Break;

    if AEta <= 0 then
    begin
      AEta := 2 - AEta;
      LX := LF; LF := LG; LG := -LX;
      LY := LU; LU := LQ; LQ := -LY;
      LZ := LV; LV := LR; LR := -LZ;

      LLimit := AEta;
      if LLimit > LI then
        LLimit := LI;

      LM := Int32((UInt32.MaxValue shr (32 - LLimit)) and 63);
      LW := (LF * LG * (LF * LF - 2)) and LM;
    end
    else
    begin
      LLimit := AEta;
      if LLimit > LI then
        LLimit := LI;

      LM := Int32((UInt32.MaxValue shr (32 - LLimit)) and 15);

      LW := LF + (((LF + 1) and 4) shl 1);
      LW := (LW * (-LG)) and LM;
    end;

    LG := LG + LF * LW;
    LQ := LQ + LU * LW;
    LR := LR + LV * LW;

    {$IFDEF DEBUG}
    System.Assert((LG and LM) = 0);
    {$ENDIF}
  end;

  AT[0] := LU;
  AT[1] := LV;
  AT[2] := LQ;
  AT[3] := LR;

  Result := AEta;
end;

class procedure TMod.Encode30(ABits: Int32; const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibInt32Array);
var
  LAvail: Int32;
  LData: UInt64;
  LXOff, LZOff: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ABits > 0);
  {$ENDIF}

  LAvail := 0;
  LData := 0;

  LXOff := 0;
  LZOff := 0;

  while ABits > 0 do
  begin
    if LAvail < Min(30, ABits) then
    begin
      LData := LData or ((UInt64(AX[LXOff]) and M32UL) shl LAvail);
      Inc(LXOff);
      Inc(LAvail, 32);
    end;

    AZ[LZOff] := Int32(LData) and M30;
    Inc(LZOff);
    LData := LData shr 30;
    Dec(LAvail, 30);
    Dec(ABits, 30);
  end;
end;

class function TMod.EqualTo(ALen: Int32; const AX: TCryptoLibInt32Array; AY: Int32): Int32;
var
  LD, LI: Int32;
begin
  LD := AX[0] xor AY;
  for LI := 1 to ALen - 1 do
  begin
    LD := LD or AX[LI];
  end;

  LD := Int32(UInt32(LD) shr 1) or (LD and 1);
  Result := TBitUtilities.Asr32(LD - 1, 31);
end;

class function TMod.EqualToVar(ALen: Int32; const AX: TCryptoLibInt32Array; AY: Int32): Boolean;
var
  LD, LI: Int32;
begin
  LD := AX[0] xor AY;
  if LD <> 0 then
    Exit(False);

  for LI := 1 to ALen - 1 do
    LD := LD or AX[LI];

  Result := LD = 0;
end;

class function TMod.GetMaximumDivsteps(ABits: Int32): Int32;
begin
  Result := Int32((Int64(188898) * ABits + (IfThen(ABits < 46, 308405, 181188))) shr 16);
end;

class function TMod.GetMaximumHDDivsteps(ABits: Int32): Int32;
begin
  Result := Int32(TBitUtilities.Asr64((Int64(150964) * ABits + 99243), 16));
end;

class function TMod.HDDivsteps30(ATheta: Int32; AF0: Int32; AG0: Int32; const AT: TCryptoLibInt32Array): Int32;
var
  LU, LV, LQ, LR: Int32;
  LF, LG: Int32;
  LI: Int32;
  LC1, LC2, LX, LY, LZ, LC3: Int32;
begin
  LU := 1 shl 30; LV := 0; LQ := 0; LR := 1 shl 30;
  LF := AF0;
  LG := AG0;

  for LI := 0 to 29 do
  begin
    LC1 := TBitUtilities.Asr32(ATheta, 31);
    LC2 := -(LG and 1);

    LX := LF xor LC1;
    LY := LU xor LC1;
    LZ := LV xor LC1;

    LG := LG - (LX and LC2);
    LQ := LQ - (LY and LC2);
    LR := LR - (LZ and LC2);

    LC3 := LC2 and (not LC1);
    ATheta := (ATheta xor LC3) + 1;

    LF := LF + (LG and LC3);
    LU := LU + (LQ and LC3);
    LV := LV + (LR and LC3);

    LG := TBitUtilities.Asr32(LG, 1);
    LQ := TBitUtilities.Asr32(LQ, 1);
    LR := TBitUtilities.Asr32(LR, 1);
  end;

  AT[0] := LU;
  AT[1] := LV;
  AT[2] := LQ;
  AT[3] := LR;

  Result := ATheta;
end;

class function TMod.Negate30(ALen30: Int32; const AD: TCryptoLibInt32Array): Int32;
var
  LC, LLast, LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AD) >= ALen30);
  {$ENDIF}

  LC := 0;
  LLast := ALen30 - 1;

  for LI := 0 to LLast - 1 do
  begin
    LC := LC - AD[LI];
    AD[LI] := LC and M30;
    LC := TBitUtilities.Asr32(LC, 30);
  end;

  LC := LC - AD[LLast];
  AD[LLast] := LC;
  LC := TBitUtilities.Asr32(LC, 30);
  Result := LC;
end;

class function TMod.TrimFG30Var(ALen30: Int32; const AF: TCryptoLibInt32Array; const AG: TCryptoLibInt32Array): Int32;
var
  LFn, LGn, LCond: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AF) >= ALen30);
  System.Assert(System.Length(AG) >= ALen30);
  {$ENDIF}

  LFn := AF[ALen30 - 1];
  LGn := AG[ALen30 - 1];

  LCond := TBitUtilities.Asr32(ALen30 - 2, 31);
  LCond := LCond or (LFn xor (TBitUtilities.Asr32(LFn, 31)));
  LCond := LCond or (LGn xor (TBitUtilities.Asr32(LGn, 31)));

  if LCond = 0 then
  begin
    AF[ALen30 - 2] := AF[ALen30 - 2] or (LFn shl 30);
    AG[ALen30 - 2] := AG[ALen30 - 2] or (LGn shl 30);
    Dec(ALen30);
  end;

  Result := ALen30;
end;

class procedure TMod.UpdateDE30(ALen30: Int32; const AD: TCryptoLibInt32Array; const AE: TCryptoLibInt32Array;
  const AT: TCryptoLibInt32Array; AM0Inv32: Int32; const AM: TCryptoLibInt32Array);
var
  LU, LV, LQ, LR: Int32;
  LDi, LEi, LI, LMd, LMe, LMi, LSd, LSe: Int32;
  LCd, LCe: Int64;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AD) >= ALen30);
  System.Assert(System.Length(AE) >= ALen30);
  System.Assert(System.Length(AM) >= ALen30);
  System.Assert(Int32(AM0Inv32 * AM[0]) = 1);
  {$ENDIF}

  LU := AT[0]; LV := AT[1]; LQ := AT[2]; LR := AT[3];

  LSd := TBitUtilities.Asr32(AD[ALen30 - 1], 31);
  LSe := TBitUtilities.Asr32(AE[ALen30 - 1], 31);

  LMd := (LU and LSd) + (LV and LSe);
  LMe := (LQ and LSd) + (LR and LSe);

  LMi := AM[0];
  LDi := AD[0];
  LEi := AE[0];

  LCd := Int64(LU) * LDi + Int64(LV) * LEi;
  LCe := Int64(LQ) * LDi + Int64(LR) * LEi;

  LMd := LMd - ((AM0Inv32 * Int32(LCd) + LMd) and M30);
  LMe := LMe - ((AM0Inv32 * Int32(LCe) + LMe) and M30);

  LCd := LCd + Int64(LMi) * LMd;
  LCe := LCe + Int64(LMi) * LMe;

  {$IFDEF DEBUG}
  System.Assert((Int32(LCd) and M30) = 0);
  System.Assert((Int32(LCe) and M30) = 0);
  {$ENDIF}

  LCd := TBitUtilities.Asr64(LCd, 30);
  LCe := TBitUtilities.Asr64(LCe, 30);

  for LI := 1 to ALen30 - 1 do
  begin
    LMi := AM[LI];
    LDi := AD[LI];
    LEi := AE[LI];

    LCd := LCd + Int64(LU) * LDi + Int64(LV) * LEi + Int64(LMi) * LMd;
    LCe := LCe + Int64(LQ) * LDi + Int64(LR) * LEi + Int64(LMi) * LMe;

    AD[LI - 1] := Int32(LCd) and M30;
    LCd := TBitUtilities.Asr64(LCd, 30);

    AE[LI - 1] := Int32(LCe) and M30;
    LCe := TBitUtilities.Asr64(LCe, 30);
  end;

  AD[ALen30 - 1] := Int32(LCd);
  AE[ALen30 - 1] := Int32(LCe);
end;

class procedure TMod.UpdateFG30(ALen30: Int32; const AF: TCryptoLibInt32Array; const AG: TCryptoLibInt32Array;
  const AT: TCryptoLibInt32Array);
var
  LU, LV, LQ, LR: Int32;
  LFi, LGi, LI: Int32;
  LCf, LCg: Int64;
begin
  {$IFDEF DEBUG}
  System.Assert(ALen30 > 0);
  System.Assert(System.Length(AF) >= ALen30);
  System.Assert(System.Length(AG) >= ALen30);
  {$ENDIF}

  LU := AT[0]; LV := AT[1]; LQ := AT[2]; LR := AT[3];

  LFi := AF[0];
  LGi := AG[0];

  LCf := Int64(LU) * LFi + Int64(LV) * LGi;
  LCg := Int64(LQ) * LFi + Int64(LR) * LGi;

  {$IFDEF DEBUG}
  System.Assert((Int32(LCf) and M30) = 0);
  System.Assert((Int32(LCg) and M30) = 0);
  {$ENDIF}

  LCf := TBitUtilities.Asr64(LCf, 30);
  LCg := TBitUtilities.Asr64(LCg, 30);

  for LI := 1 to ALen30 - 1 do
  begin
    LFi := AF[LI];
    LGi := AG[LI];

    LCf := LCf + Int64(LU) * LFi + Int64(LV) * LGi;
    LCg := LCg + Int64(LQ) * LFi + Int64(LR) * LGi;

    AF[LI - 1] := Int32(LCf) and M30;
    LCf := TBitUtilities.Asr64(LCf, 30);

    AG[LI - 1] := Int32(LCg) and M30;
    LCg := TBitUtilities.Asr64(LCg, 30);
  end;

  AF[ALen30 - 1] := Int32(LCf);
  AG[ALen30 - 1] := Int32(LCg);
end;

end.
