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

unit ClpScalarUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitUtilities,
  ClpCryptoLibTypes;

type
  TScalarUtilities = class sealed
  public
    class procedure AddShifted_NP(ALast: Int32; AShift: Int32; const ANu, ANv, AP, AT: TCryptoLibUInt32Array); static;
    class procedure AddShifted_UV(ALast: Int32; AShift: Int32; const AU0, AU1, AV0, AV1: TCryptoLibUInt32Array); static;
    class function GetBitLength(ALast: Int32; const AX: TCryptoLibUInt32Array): Int32; static;
    class function GetBitLengthPositive(ALast: Int32; const AX: TCryptoLibUInt32Array): Int32; static;
    class function LessThan(ALast: Int32; const AX, AY: TCryptoLibUInt32Array): Boolean; static;
    class procedure SubShifted_NP(ALast: Int32; AShift: Int32; const ANu, ANv, AP, AT: TCryptoLibUInt32Array); static;
    class procedure SubShifted_UV(ALast: Int32; AShift: Int32; const AU0, AU1, AV0, AV1: TCryptoLibUInt32Array); static;
    class procedure Swap(var AX: TCryptoLibUInt32Array; var AY: TCryptoLibUInt32Array); static;
  end;

implementation

{ TScalarUtilities }

class procedure TScalarUtilities.AddShifted_NP(ALast: Int32; AShift: Int32; const ANu, ANv, AP, AT: TCryptoLibUInt32Array);
var
  Lcc_p, Lcc_Nu: UInt64;
  LI, LsWords, LsBits: Int32;
  Lp_i, Lp_s, Lnext_v, Lv_s, Lq_s: UInt32;
  Lprev_p, Lprev_q, Lprev_v, Lprev_t, Lnext_t, Lt_s, Lnext_q: UInt32;
begin
  Lcc_p := 0;
  Lcc_Nu := 0;

  if AShift = 0 then
  begin
    LI := 0;
    while LI <= ALast do
    begin
      Lp_i := AP[LI];
      Lcc_Nu := Lcc_Nu + ANu[LI];
      Lcc_Nu := Lcc_Nu + Lp_i;
      Lcc_p := Lcc_p + Lp_i;
      Lcc_p := Lcc_p + ANv[LI];
      Lp_i := UInt32(Lcc_p);
      Lcc_p := Lcc_p shr 32;
      AP[LI] := Lp_i;
      Lcc_Nu := Lcc_Nu + Lp_i;
      ANu[LI] := UInt32(Lcc_Nu);
      Lcc_Nu := Lcc_Nu shr 32;
      System.Inc(LI);
    end;
    Exit;
  end;

  if AShift < 32 then
  begin
    Lprev_p := 0;
    Lprev_q := 0;
    Lprev_v := 0;
    LI := 0;
    while LI <= ALast do
    begin
      Lp_i := AP[LI];
      Lp_s := (Lp_i shl AShift) or TBitUtilities.NegativeRightShift32(Lprev_p, -AShift);
      Lprev_p := Lp_i;
      Lcc_Nu := Lcc_Nu + ANu[LI];
      Lcc_Nu := Lcc_Nu + Lp_s;
      Lnext_v := ANv[LI];
      Lv_s := (Lnext_v shl AShift) or TBitUtilities.NegativeRightShift32(Lprev_v, -AShift);
      Lprev_v := Lnext_v;
      Lcc_p := Lcc_p + Lp_i;
      Lcc_p := Lcc_p + Lv_s;
      Lp_i := UInt32(Lcc_p);
      Lcc_p := Lcc_p shr 32;
      AP[LI] := Lp_i;
      Lq_s := (Lp_i shl AShift) or TBitUtilities.NegativeRightShift32(Lprev_q, -AShift);
      Lprev_q := Lp_i;
      Lcc_Nu := Lcc_Nu + Lq_s;
      ANu[LI] := UInt32(Lcc_Nu);
      Lcc_Nu := Lcc_Nu shr 32;
      System.Inc(LI);
    end;
    Exit;
  end;

  // Copy the low limbs of the original p
  System.Move(AP[0], AT[0], ALast * System.SizeOf(UInt32));

  LsWords := TBitUtilities.Asr32(AShift, 5);
  LsBits := AShift and 31;

  if LsBits = 0 then
  begin
    LI := LsWords;
    while LI <= ALast do
    begin
      Lcc_Nu := Lcc_Nu + ANu[LI];
      Lcc_Nu := Lcc_Nu + AT[LI - LsWords];
      Lcc_p := Lcc_p + AP[LI];
      Lcc_p := Lcc_p + ANv[LI - LsWords];
      AP[LI] := UInt32(Lcc_p);
      Lcc_p := Lcc_p shr 32;
      Lcc_Nu := Lcc_Nu + AP[LI - LsWords];
      ANu[LI] := UInt32(Lcc_Nu);
      Lcc_Nu := Lcc_Nu shr 32;
      System.Inc(LI);
    end;
    Exit;
  end;

  Lprev_t := 0;
  Lprev_q := 0;
  Lprev_v := 0;
  LI := LsWords;
  while LI <= ALast do
  begin
    Lnext_t := AT[LI - LsWords];
    Lt_s := (Lnext_t shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_t, -LsBits);
    Lprev_t := Lnext_t;
    Lcc_Nu := Lcc_Nu + ANu[LI];
    Lcc_Nu := Lcc_Nu + Lt_s;
    Lnext_v := ANv[LI - LsWords];
    Lv_s := (Lnext_v shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_v, -LsBits);
    Lprev_v := Lnext_v;
    Lcc_p := Lcc_p + AP[LI];
    Lcc_p := Lcc_p + Lv_s;
    AP[LI] := UInt32(Lcc_p);
    Lcc_p := Lcc_p shr 32;
    Lnext_q := AP[LI - LsWords];
    Lq_s := (Lnext_q shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_q, -LsBits);
    Lprev_q := Lnext_q;
    Lcc_Nu := Lcc_Nu + Lq_s;
    ANu[LI] := UInt32(Lcc_Nu);
    Lcc_Nu := Lcc_Nu shr 32;
    System.Inc(LI);
  end;
end;

class procedure TScalarUtilities.AddShifted_UV(ALast: Int32; AShift: Int32; const AU0, AU1, AV0, AV1: TCryptoLibUInt32Array);
var
  LsWords, LsBits, LI: Int32;
  Lcc_u0, Lcc_u1: UInt64;
  Lnext_v0, Lnext_v1, Lv0_s, Lv1_s: UInt32;
  Lprev_v0, Lprev_v1: UInt32;
begin
  LsWords := TBitUtilities.Asr32(AShift, 5);
  LsBits := AShift and 31;
  Lcc_u0 := 0;
  Lcc_u1 := 0;

  if LsBits = 0 then
  begin
    LI := LsWords;
    while LI <= ALast do
    begin
      Lcc_u0 := Lcc_u0 + AU0[LI];
      Lcc_u1 := Lcc_u1 + AU1[LI];
      Lcc_u0 := Lcc_u0 + AV0[LI - LsWords];
      Lcc_u1 := Lcc_u1 + AV1[LI - LsWords];
      AU0[LI] := UInt32(Lcc_u0);
      Lcc_u0 := Lcc_u0 shr 32;
      AU1[LI] := UInt32(Lcc_u1);
      Lcc_u1 := Lcc_u1 shr 32;
      System.Inc(LI);
    end;
    Exit;
  end;

  Lprev_v0 := 0;
  Lprev_v1 := 0;
  LI := LsWords;
  while LI <= ALast do
  begin
    Lnext_v0 := AV0[LI - LsWords];
    Lnext_v1 := AV1[LI - LsWords];
    Lv0_s := (Lnext_v0 shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_v0, -LsBits);
    Lv1_s := (Lnext_v1 shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_v1, -LsBits);
    Lprev_v0 := Lnext_v0;
    Lprev_v1 := Lnext_v1;
    Lcc_u0 := Lcc_u0 + AU0[LI];
    Lcc_u1 := Lcc_u1 + AU1[LI];
    Lcc_u0 := Lcc_u0 + Lv0_s;
    Lcc_u1 := Lcc_u1 + Lv1_s;
    AU0[LI] := UInt32(Lcc_u0);
    Lcc_u0 := Lcc_u0 shr 32;
    AU1[LI] := UInt32(Lcc_u1);
    Lcc_u1 := Lcc_u1 shr 32;
    System.Inc(LI);
  end;
end;

class function TScalarUtilities.GetBitLength(ALast: Int32; const AX: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LSign: UInt32;
begin
  LI := ALast;
  LSign := UInt32(TBitUtilities.Asr32(Int32(AX[LI]), 31));
  while (LI > 0) and (AX[LI] = LSign) do
    System.Dec(LI);
  Result := LI * 32 + 32 - TBitUtilities.NumberOfLeadingZeros32(UInt32(Int32(AX[LI]) xor Int32(LSign)));
end;

class function TScalarUtilities.GetBitLengthPositive(ALast: Int32; const AX: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
begin
  LI := ALast;
  while (LI > 0) and (AX[LI] = 0) do
    System.Dec(LI);
  Result := LI * 32 + 32 - TBitUtilities.NumberOfLeadingZeros32(UInt32(AX[LI]));
end;

class function TScalarUtilities.LessThan(ALast: Int32; const AX: TCryptoLibUInt32Array;
  const AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  LI := ALast;
  repeat
    if AX[LI] < AY[LI] then
      Exit(True);
    if AX[LI] > AY[LI] then
      Exit(False);
    System.Dec(LI);
  until LI < 0;
  Result := False;
end;

class procedure TScalarUtilities.SubShifted_NP(ALast: Int32; AShift: Int32; const ANu, ANv, AP, AT: TCryptoLibUInt32Array);
var
  Lcc_p, Lcc_Nu: Int64;
  LI, LsWords, LsBits: Int32;
  Lp_i, Lp_s, Lnext_v, Lv_s, Lq_s: UInt32;
  Lprev_p, Lprev_q, Lprev_v, Lprev_t, Lnext_t, Lt_s, Lnext_q: UInt32;
begin
  Lcc_p := 0;
  Lcc_Nu := 0;

  if AShift = 0 then
    begin
    LI := 0;
    while LI <= ALast do
    begin
      Lp_i := AP[LI];
      Lcc_Nu := Lcc_Nu + Int64(ANu[LI]);
      Lcc_Nu := Lcc_Nu - Lp_i;
      Lcc_p := Lcc_p + Lp_i;
      Lcc_p := Lcc_p - Int64(ANv[LI]);
      Lp_i := UInt32(Lcc_p);
      Lcc_p := TBitUtilities.Asr64(Lcc_p, 32);
      AP[LI] := Lp_i;
      Lcc_Nu := Lcc_Nu - Int64(Lp_i);
      ANu[LI] := UInt32(Lcc_Nu);
      Lcc_Nu := TBitUtilities.Asr64(Lcc_Nu, 32);
      System.Inc(LI);
    end;
    Exit;
  end;

  if AShift < 32 then
  begin
    Lprev_p := 0;
    Lprev_q := 0;
    Lprev_v := 0;
    LI := 0;
    while LI <= ALast do
    begin
      Lp_i := AP[LI];
      Lp_s := (Lp_i shl AShift) or TBitUtilities.NegativeRightShift32(Lprev_p, -AShift);
      Lprev_p := Lp_i;
      Lcc_Nu := Lcc_Nu + Int64(ANu[LI]);
      Lcc_Nu := Lcc_Nu - Int64(Lp_s);
      Lnext_v := ANv[LI];
      Lv_s := (Lnext_v shl AShift) or TBitUtilities.NegativeRightShift32(Lprev_v, -AShift);
      Lprev_v := Lnext_v;
      Lcc_p := Lcc_p + Lp_i;
      Lcc_p := Lcc_p - Int64(Lv_s);
      Lp_i := UInt32(Lcc_p);
      Lcc_p := TBitUtilities.Asr64(Lcc_p, 32);
      AP[LI] := Lp_i;
      Lq_s := (Lp_i shl AShift) or TBitUtilities.NegativeRightShift32(Lprev_q, -AShift);
      Lprev_q := Lp_i;
      Lcc_Nu := Lcc_Nu - Int64(Lq_s);
      ANu[LI] := UInt32(Lcc_Nu);
      Lcc_Nu := TBitUtilities.Asr64(Lcc_Nu, 32);
      System.Inc(LI);
    end;
    Exit;
  end;

  System.Move(AP[0], AT[0], ALast * System.SizeOf(UInt32));
  LsWords := TBitUtilities.Asr32(AShift, 5);
  LsBits := AShift and 31;

  if LsBits = 0 then
  begin
    LI := LsWords;
    while LI <= ALast do
    begin
      Lcc_Nu := Lcc_Nu + Int64(ANu[LI]);
      Lcc_Nu := Lcc_Nu - Int64(AT[LI - LsWords]);
      Lcc_p := Lcc_p + Int64(AP[LI]);
      Lcc_p := Lcc_p - Int64(ANv[LI - LsWords]);
      AP[LI] := UInt32(Lcc_p);
      Lcc_p := TBitUtilities.Asr64(Lcc_p, 32);
      Lcc_Nu := Lcc_Nu - Int64(AP[LI - LsWords]);
      ANu[LI] := UInt32(Lcc_Nu);
      Lcc_Nu := TBitUtilities.Asr64(Lcc_Nu, 32);
      System.Inc(LI);
    end;
    Exit;
  end;

  Lprev_t := 0;
  Lprev_q := 0;
  Lprev_v := 0;
  LI := LsWords;
  while LI <= ALast do
  begin
    Lnext_t := AT[LI - LsWords];
    Lt_s := (Lnext_t shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_t, -LsBits);
    Lprev_t := Lnext_t;
    Lcc_Nu := Lcc_Nu + Int64(ANu[LI]);
    Lcc_Nu := Lcc_Nu - Int64(Lt_s);
    Lnext_v := ANv[LI - LsWords];
    Lv_s := (Lnext_v shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_v, -LsBits);
    Lprev_v := Lnext_v;
    Lcc_p := Lcc_p + Int64(AP[LI]);
    Lcc_p := Lcc_p - Int64(Lv_s);
    AP[LI] := UInt32(Lcc_p);
    Lcc_p := TBitUtilities.Asr64(Lcc_p, 32);
    Lnext_q := AP[LI - LsWords];
    Lq_s := (Lnext_q shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_q, -LsBits);
    Lprev_q := Lnext_q;
    Lcc_Nu := Lcc_Nu - Int64(Lq_s);
    ANu[LI] := UInt32(Lcc_Nu);
    Lcc_Nu := TBitUtilities.Asr64(Lcc_Nu, 32);
    System.Inc(LI);
  end;
end;

class procedure TScalarUtilities.SubShifted_UV(ALast: Int32; AShift: Int32; const AU0, AU1, AV0, AV1: TCryptoLibUInt32Array);
var
  LsWords, LsBits, LI: Int32;
  Lcc_u0, Lcc_u1: Int64;
  Lnext_v0, Lnext_v1, Lv0_s, Lv1_s: UInt32;
  Lprev_v0, Lprev_v1: UInt32;
begin
  LsWords := TBitUtilities.Asr32(AShift, 5);
  LsBits := AShift and 31;
  Lcc_u0 := 0;
  Lcc_u1 := 0;

  if LsBits = 0 then
  begin
    LI := LsWords;
    while LI <= ALast do
    begin
      Lcc_u0 := Lcc_u0 + AU0[LI];
      Lcc_u1 := Lcc_u1 + AU1[LI];
      Lcc_u0 := Lcc_u0 - AV0[LI - LsWords];
      Lcc_u1 := Lcc_u1 - AV1[LI - LsWords];
      AU0[LI] := UInt32(Lcc_u0);
      Lcc_u0 := TBitUtilities.Asr64(Lcc_u0, 32);
      AU1[LI] := UInt32(Lcc_u1);
      Lcc_u1 := TBitUtilities.Asr64(Lcc_u1, 32);
      System.Inc(LI);
    end;
    Exit;
  end;

  Lprev_v0 := 0;
  Lprev_v1 := 0;
  LI := LsWords;
  while LI <= ALast do
  begin
    Lnext_v0 := AV0[LI - LsWords];
    Lnext_v1 := AV1[LI - LsWords];
    Lv0_s := (Lnext_v0 shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_v0, -LsBits);
    Lv1_s := (Lnext_v1 shl LsBits) or TBitUtilities.NegativeRightShift32(Lprev_v1, -LsBits);
    Lprev_v0 := Lnext_v0;
    Lprev_v1 := Lnext_v1;
    Lcc_u0 := Lcc_u0 + AU0[LI];
    Lcc_u1 := Lcc_u1 + AU1[LI];
    Lcc_u0 := Lcc_u0 - Int64(Lv0_s);
    Lcc_u1 := Lcc_u1 - Int64(Lv1_s);
    AU0[LI] := UInt32(Lcc_u0);
    Lcc_u0 := TBitUtilities.Asr64(Lcc_u0, 32);
    AU1[LI] := UInt32(Lcc_u1);
    Lcc_u1 := TBitUtilities.Asr64(Lcc_u1, 32);
    System.Inc(LI);
  end;
end;

class procedure TScalarUtilities.Swap(var AX: TCryptoLibUInt32Array; var AY: TCryptoLibUInt32Array);
var
  LT: TCryptoLibUInt32Array;
begin
  LT := AX;
  AX := AY;
  AY := LT;
end;

end.
