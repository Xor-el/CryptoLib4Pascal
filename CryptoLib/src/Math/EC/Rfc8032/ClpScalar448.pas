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

unit ClpScalar448;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpCodec,
  ClpWnaf,
  ClpNat448,
  ClpNat,
  ClpScalarUtilities,
  ClpCryptoLibTypes;

type
  TScalar448 = class sealed
  strict private
  const
    Size = Int32(14);
    ScalarBytes = Size * 4 + 1;
    M26UL = UInt64($03FFFFFF);
    M28UL = UInt64($0FFFFFFF);
    TargetLength = Int32(447);

    L_0 = Int32($04A7BB0D);
    L_1 = Int32($0873D6D5);
    L_2 = Int32($0A70AADC);
    L_3 = Int32($03D8D723);
    L_4 = Int32($096FDE93);
    L_5 = Int32($0B65129C);
    L_6 = Int32($063BB124);
    L_7 = Int32($08335DC1);

    L4_0 = Int32($029EEC34);
    L4_1 = Int32($01CF5B55);
    L4_2 = Int32($09C2AB72);
    L4_3 = Int32($0F635C8E);
    L4_4 = Int32($05BF7A4C);
    L4_5 = Int32($0D944A72);
    L4_6 = Int32($08EEC492);
    L4_7 = Int32($20CD7705);
  class var
    FL, FLSq: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class constructor Create;
  public
    class function CheckVar(const &AS: TCryptoLibByteArray;
      AN: TCryptoLibUInt32Array): Boolean; static;
    class procedure Decode(const AK: TCryptoLibByteArray;
      AN: TCryptoLibUInt32Array); static;
    class procedure GetOrderWnafVar(AWidth: Int32;
      const AWs: TCryptoLibShortIntArray); static;
    class procedure Multiply225Var(const AX: TCryptoLibUInt32Array;
      const AY225: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); static;
    class function Reduce704(const AN: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    class procedure Reduce704(const AN: TCryptoLibByteArray;
      const AR: TCryptoLibByteArray); overload; static;
    class function Reduce912(const AN: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    class procedure Reduce912(const AN: TCryptoLibByteArray;
      const AR: TCryptoLibByteArray); overload; static;
    class function ReduceBasisVar(const AK: TCryptoLibUInt32Array;
      AZ0: TCryptoLibUInt32Array; AZ1: TCryptoLibUInt32Array): Boolean; static;
    class procedure ToSignedDigits(ABits: Int32; const AX: TCryptoLibUInt32Array;
      AZ: TCryptoLibUInt32Array); static;
  end;

implementation

{ TScalar448 }

class constructor TScalar448.Create;
begin
  Boot;
end;

class procedure TScalar448.Boot;
begin
  FL := TCryptoLibUInt32Array.Create($AB5844F3, $2378C292, $8DC58F55, $216CC272,
    $AED63690, $C44EDB49, $7CCA23E9, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $3FFFFFFF);
  FLSq := TCryptoLibUInt32Array.Create($1BA1FEA9, $C1ADFBB8, $49E0A8B2, $B91BF537,
    $E764D815, $4525492B, $A2B8716D, $4AE17CF6, $BA3C47C4, $F1A9CC14,
    $7E4D070A, $92052BCB, $9F823B72, $C3402A93, $55AC2279, $91BC6149,
    $46E2C7AA, $10B66139, $D76B1B48, $E2276DA4, $BE6511F4, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $0FFFFFFF);
end;

class function TScalar448.CheckVar(const &AS: TCryptoLibByteArray;
  AN: TCryptoLibUInt32Array): Boolean;
begin
  if &AS[ScalarBytes - 1] <> $00 then
    Exit(False);
  Decode(&AS, AN);
  Result := not TNat.Gte(Size, AN, FL);
end;

class procedure TScalar448.Decode(const AK: TCryptoLibByteArray;
  AN: TCryptoLibUInt32Array);
begin
  {$IFDEF DEBUG}
  System.Assert(AK[ScalarBytes - 1] = $00);
  {$ENDIF}
  TCodec.Decode32(AK, 0, AN, 0, Size);
end;

class procedure TScalar448.GetOrderWnafVar(AWidth: Int32;
  const AWs: TCryptoLibShortIntArray);
begin
  TWnaf.GetSignedVar(FL, AWidth, AWs);
end;

class procedure TScalar448.Multiply225Var(const AX: TCryptoLibUInt32Array;
  const AY225: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
var
  LTt: TCryptoLibUInt32Array;
  LBytes, LR: TCryptoLibByteArray;
begin
  {$IFDEF DEBUG}
  System.Assert(TBitOperations.Asr32(Int32(AY225[7]), 31) = Int32(AY225[7]));
  {$ENDIF}
  System.SetLength(LTt, 22);
  TNat.Mul(AY225, 0, 8, AX, 0, Size, LTt, 0);
  if Int32(AY225[7]) < 0 then
  begin
    TNat.AddTo(Size, FL, 0, LTt, 8);
    TNat.SubFrom(Size, AX, 0, LTt, 8);
  end;
  System.SetLength(LBytes, 88);
  TCodec.Encode32(LTt, 0, 22, LBytes, 0);
  LR := Reduce704(LBytes);
  Decode(LR, AZ);
end;

class function TScalar448.Reduce704(const AN: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  System.SetLength(Result, ScalarBytes);
  Reduce704(AN, Result);
end;

class procedure TScalar448.Reduce704(const AN: TCryptoLibByteArray;
  const AR: TCryptoLibByteArray);
var
  Lx00, Lx01, Lx02, Lx03, Lx04, Lx05, Lx06, Lx07: UInt64;
  Lx08, Lx09, Lx10, Lx11, Lx12, Lx13, Lx14, Lx15: UInt64;
  Lx16, Lx17, Lx18, Lx19, Lx20, Lx21, Lx22, Lx23: UInt64;
  Lx24, Lx25: UInt64;
begin
  Lx00 := TCodec.Decode32(AN, 0);
  Lx01 := UInt64(TCodec.Decode24(AN, 4)) shl 4;
  Lx02 := TCodec.Decode32(AN, 7);
  Lx03 := UInt64(TCodec.Decode24(AN, 11)) shl 4;
  Lx04 := TCodec.Decode32(AN, 14);
  Lx05 := UInt64(TCodec.Decode24(AN, 18)) shl 4;
  Lx06 := TCodec.Decode32(AN, 21);
  Lx07 := UInt64(TCodec.Decode24(AN, 25)) shl 4;
  Lx08 := TCodec.Decode32(AN, 28);
  Lx09 := UInt64(TCodec.Decode24(AN, 32)) shl 4;
  Lx10 := TCodec.Decode32(AN, 35);
  Lx11 := UInt64(TCodec.Decode24(AN, 39)) shl 4;
  Lx12 := TCodec.Decode32(AN, 42);
  Lx13 := UInt64(TCodec.Decode24(AN, 46)) shl 4;
  Lx14 := TCodec.Decode32(AN, 49);
  Lx15 := UInt64(TCodec.Decode24(AN, 53)) shl 4;
  Lx16 := TCodec.Decode32(AN, 56);
  Lx17 := UInt64(TCodec.Decode24(AN, 60)) shl 4;
  Lx18 := TCodec.Decode32(AN, 63);
  Lx19 := UInt64(TCodec.Decode24(AN, 67)) shl 4;
  Lx20 := TCodec.Decode32(AN, 70);
  Lx21 := UInt64(TCodec.Decode24(AN, 74)) shl 4;
  Lx22 := TCodec.Decode32(AN, 77);
  Lx23 := UInt64(TCodec.Decode24(AN, 81)) shl 4;
  Lx24 := TCodec.Decode32(AN, 84);
  Lx25 := UInt64(0);

  Lx25 := Lx25 + (Lx24 shr 28); Lx24 := Lx24 and M28UL;
  Lx09 := Lx09 + Lx25 * UInt64(L4_0);
  Lx10 := Lx10 + Lx25 * UInt64(L4_1);
  Lx11 := Lx11 + Lx25 * UInt64(L4_2);
  Lx12 := Lx12 + Lx25 * UInt64(L4_3);
  Lx13 := Lx13 + Lx25 * UInt64(L4_4);
  Lx14 := Lx14 + Lx25 * UInt64(L4_5);
  Lx15 := Lx15 + Lx25 * UInt64(L4_6);
  Lx16 := Lx16 + Lx25 * UInt64(L4_7);

  Lx21 := Lx21 + (Lx20 shr 28); Lx20 := Lx20 and M28UL;
  Lx22 := Lx22 + (Lx21 shr 28); Lx21 := Lx21 and M28UL;
  Lx23 := Lx23 + (Lx22 shr 28); Lx22 := Lx22 and M28UL;
  Lx24 := Lx24 + (Lx23 shr 28); Lx23 := Lx23 and M28UL;

  Lx08 := Lx08 + Lx24 * UInt64(L4_0);
  Lx09 := Lx09 + Lx24 * UInt64(L4_1);
  Lx10 := Lx10 + Lx24 * UInt64(L4_2);
  Lx11 := Lx11 + Lx24 * UInt64(L4_3);
  Lx12 := Lx12 + Lx24 * UInt64(L4_4);
  Lx13 := Lx13 + Lx24 * UInt64(L4_5);
  Lx14 := Lx14 + Lx24 * UInt64(L4_6);
  Lx15 := Lx15 + Lx24 * UInt64(L4_7);

  Lx07 := Lx07 + Lx23 * UInt64(L4_0);
  Lx08 := Lx08 + Lx23 * UInt64(L4_1);
  Lx09 := Lx09 + Lx23 * UInt64(L4_2);
  Lx10 := Lx10 + Lx23 * UInt64(L4_3);
  Lx11 := Lx11 + Lx23 * UInt64(L4_4);
  Lx12 := Lx12 + Lx23 * UInt64(L4_5);
  Lx13 := Lx13 + Lx23 * UInt64(L4_6);
  Lx14 := Lx14 + Lx23 * UInt64(L4_7);

  Lx06 := Lx06 + Lx22 * UInt64(L4_0);
  Lx07 := Lx07 + Lx22 * UInt64(L4_1);
  Lx08 := Lx08 + Lx22 * UInt64(L4_2);
  Lx09 := Lx09 + Lx22 * UInt64(L4_3);
  Lx10 := Lx10 + Lx22 * UInt64(L4_4);
  Lx11 := Lx11 + Lx22 * UInt64(L4_5);
  Lx12 := Lx12 + Lx22 * UInt64(L4_6);
  Lx13 := Lx13 + Lx22 * UInt64(L4_7);

  Lx18 := Lx18 + (Lx17 shr 28); Lx17 := Lx17 and M28UL;
  Lx19 := Lx19 + (Lx18 shr 28); Lx18 := Lx18 and M28UL;
  Lx20 := Lx20 + (Lx19 shr 28); Lx19 := Lx19 and M28UL;
  Lx21 := Lx21 + (Lx20 shr 28); Lx20 := Lx20 and M28UL;

  Lx05 := Lx05 + Lx21 * UInt64(L4_0);
  Lx06 := Lx06 + Lx21 * UInt64(L4_1);
  Lx07 := Lx07 + Lx21 * UInt64(L4_2);
  Lx08 := Lx08 + Lx21 * UInt64(L4_3);
  Lx09 := Lx09 + Lx21 * UInt64(L4_4);
  Lx10 := Lx10 + Lx21 * UInt64(L4_5);
  Lx11 := Lx11 + Lx21 * UInt64(L4_6);
  Lx12 := Lx12 + Lx21 * UInt64(L4_7);

  Lx04 := Lx04 + Lx20 * UInt64(L4_0);
  Lx05 := Lx05 + Lx20 * UInt64(L4_1);
  Lx06 := Lx06 + Lx20 * UInt64(L4_2);
  Lx07 := Lx07 + Lx20 * UInt64(L4_3);
  Lx08 := Lx08 + Lx20 * UInt64(L4_4);
  Lx09 := Lx09 + Lx20 * UInt64(L4_5);
  Lx10 := Lx10 + Lx20 * UInt64(L4_6);
  Lx11 := Lx11 + Lx20 * UInt64(L4_7);

  Lx03 := Lx03 + Lx19 * UInt64(L4_0);
  Lx04 := Lx04 + Lx19 * UInt64(L4_1);
  Lx05 := Lx05 + Lx19 * UInt64(L4_2);
  Lx06 := Lx06 + Lx19 * UInt64(L4_3);
  Lx07 := Lx07 + Lx19 * UInt64(L4_4);
  Lx08 := Lx08 + Lx19 * UInt64(L4_5);
  Lx09 := Lx09 + Lx19 * UInt64(L4_6);
  Lx10 := Lx10 + Lx19 * UInt64(L4_7);

  Lx15 := Lx15 + (Lx14 shr 28); Lx14 := Lx14 and M28UL;
  Lx16 := Lx16 + (Lx15 shr 28); Lx15 := Lx15 and M28UL;
  Lx17 := Lx17 + (Lx16 shr 28); Lx16 := Lx16 and M28UL;
  Lx18 := Lx18 + (Lx17 shr 28); Lx17 := Lx17 and M28UL;

  Lx02 := Lx02 + Lx18 * UInt64(L4_0);
  Lx03 := Lx03 + Lx18 * UInt64(L4_1);
  Lx04 := Lx04 + Lx18 * UInt64(L4_2);
  Lx05 := Lx05 + Lx18 * UInt64(L4_3);
  Lx06 := Lx06 + Lx18 * UInt64(L4_4);
  Lx07 := Lx07 + Lx18 * UInt64(L4_5);
  Lx08 := Lx08 + Lx18 * UInt64(L4_6);
  Lx09 := Lx09 + Lx18 * UInt64(L4_7);

  Lx01 := Lx01 + Lx17 * UInt64(L4_0);
  Lx02 := Lx02 + Lx17 * UInt64(L4_1);
  Lx03 := Lx03 + Lx17 * UInt64(L4_2);
  Lx04 := Lx04 + Lx17 * UInt64(L4_3);
  Lx05 := Lx05 + Lx17 * UInt64(L4_4);
  Lx06 := Lx06 + Lx17 * UInt64(L4_5);
  Lx07 := Lx07 + Lx17 * UInt64(L4_6);
  Lx08 := Lx08 + Lx17 * UInt64(L4_7);

  Lx16 := Lx16 * 4;
  Lx16 := Lx16 + (Lx15 shr 26); Lx15 := Lx15 and M26UL;
  Lx16 := Lx16 + 1;

  Lx00 := Lx00 + Lx16 * UInt64(L_0);
  Lx01 := Lx01 + Lx16 * UInt64(L_1);
  Lx02 := Lx02 + Lx16 * UInt64(L_2);
  Lx03 := Lx03 + Lx16 * UInt64(L_3);
  Lx04 := Lx04 + Lx16 * UInt64(L_4);
  Lx05 := Lx05 + Lx16 * UInt64(L_5);
  Lx06 := Lx06 + Lx16 * UInt64(L_6);
  Lx07 := Lx07 + Lx16 * UInt64(L_7);

  Lx01 := Lx01 + (Lx00 shr 28); Lx00 := Lx00 and M28UL;
  Lx02 := Lx02 + (Lx01 shr 28); Lx01 := Lx01 and M28UL;
  Lx03 := Lx03 + (Lx02 shr 28); Lx02 := Lx02 and M28UL;
  Lx04 := Lx04 + (Lx03 shr 28); Lx03 := Lx03 and M28UL;
  Lx05 := Lx05 + (Lx04 shr 28); Lx04 := Lx04 and M28UL;
  Lx06 := Lx06 + (Lx05 shr 28); Lx05 := Lx05 and M28UL;
  Lx07 := Lx07 + (Lx06 shr 28); Lx06 := Lx06 and M28UL;
  Lx08 := Lx08 + (Lx07 shr 28); Lx07 := Lx07 and M28UL;
  Lx09 := Lx09 + (Lx08 shr 28); Lx08 := Lx08 and M28UL;
  Lx10 := Lx10 + (Lx09 shr 28); Lx09 := Lx09 and M28UL;
  Lx11 := Lx11 + (Lx10 shr 28); Lx10 := Lx10 and M28UL;
  Lx12 := Lx12 + (Lx11 shr 28); Lx11 := Lx11 and M28UL;
  Lx13 := Lx13 + (Lx12 shr 28); Lx12 := Lx12 and M28UL;
  Lx14 := Lx14 + (Lx13 shr 28); Lx13 := Lx13 and M28UL;
  Lx15 := Lx15 + (Lx14 shr 28); Lx14 := Lx14 and M28UL;
  Lx16 := Lx15 shr 26; Lx15 := Lx15 and M26UL;

  Lx16 := Lx16 - 1;

  {$IFDEF DEBUG}
  System.Assert((Lx16 = UInt64(0)) or (Lx16 = UInt64($FFFFFFFFFFFFFFFF)));
  {$ENDIF}

  Lx00 := Lx00 - (Lx16 and UInt64(L_0));
  Lx01 := Lx01 - (Lx16 and UInt64(L_1));
  Lx02 := Lx02 - (Lx16 and UInt64(L_2));
  Lx03 := Lx03 - (Lx16 and UInt64(L_3));
  Lx04 := Lx04 - (Lx16 and UInt64(L_4));
  Lx05 := Lx05 - (Lx16 and UInt64(L_5));
  Lx06 := Lx06 - (Lx16 and UInt64(L_6));
  Lx07 := Lx07 - (Lx16 and UInt64(L_7));

  Lx01 := Lx01 + UInt64(TBitOperations.Asr64(Int64(Lx00), 28)); Lx00 := Lx00 and M28UL;
  Lx02 := Lx02 + UInt64(TBitOperations.Asr64(Int64(Lx01), 28)); Lx01 := Lx01 and M28UL;
  Lx03 := Lx03 + UInt64(TBitOperations.Asr64(Int64(Lx02), 28)); Lx02 := Lx02 and M28UL;
  Lx04 := Lx04 + UInt64(TBitOperations.Asr64(Int64(Lx03), 28)); Lx03 := Lx03 and M28UL;
  Lx05 := Lx05 + UInt64(TBitOperations.Asr64(Int64(Lx04), 28)); Lx04 := Lx04 and M28UL;
  Lx06 := Lx06 + UInt64(TBitOperations.Asr64(Int64(Lx05), 28)); Lx05 := Lx05 and M28UL;
  Lx07 := Lx07 + UInt64(TBitOperations.Asr64(Int64(Lx06), 28)); Lx06 := Lx06 and M28UL;
  Lx08 := Lx08 + UInt64(TBitOperations.Asr64(Int64(Lx07), 28)); Lx07 := Lx07 and M28UL;
  Lx09 := Lx09 + UInt64(TBitOperations.Asr64(Int64(Lx08), 28)); Lx08 := Lx08 and M28UL;
  Lx10 := Lx10 + UInt64(TBitOperations.Asr64(Int64(Lx09), 28)); Lx09 := Lx09 and M28UL;
  Lx11 := Lx11 + UInt64(TBitOperations.Asr64(Int64(Lx10), 28)); Lx10 := Lx10 and M28UL;
  Lx12 := Lx12 + UInt64(TBitOperations.Asr64(Int64(Lx11), 28)); Lx11 := Lx11 and M28UL;
  Lx13 := Lx13 + UInt64(TBitOperations.Asr64(Int64(Lx12), 28)); Lx12 := Lx12 and M28UL;
  Lx14 := Lx14 + UInt64(TBitOperations.Asr64(Int64(Lx13), 28)); Lx13 := Lx13 and M28UL;
  Lx15 := Lx15 + UInt64(TBitOperations.Asr64(Int64(Lx14), 28)); Lx14 := Lx14 and M28UL;

  {$IFDEF DEBUG}
  System.Assert(Lx15 shr 26 = UInt64(0));
  {$ENDIF}

  TCodec.Encode56(Lx00 or (Lx01 shl 28), AR, 0);
  TCodec.Encode56(Lx02 or (Lx03 shl 28), AR, 7);
  TCodec.Encode56(Lx04 or (Lx05 shl 28), AR, 14);
  TCodec.Encode56(Lx06 or (Lx07 shl 28), AR, 21);
  TCodec.Encode56(Lx08 or (Lx09 shl 28), AR, 28);
  TCodec.Encode56(Lx10 or (Lx11 shl 28), AR, 35);
  TCodec.Encode56(Lx12 or (Lx13 shl 28), AR, 42);
  TCodec.Encode56(Lx14 or (Lx15 shl 28), AR, 49);
end;

class function TScalar448.Reduce912(const AN: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  System.SetLength(Result, ScalarBytes);
  Reduce912(AN, Result);
end;

class procedure TScalar448.Reduce912(const AN: TCryptoLibByteArray;
  const AR: TCryptoLibByteArray);
var
  Lx00, Lx01, Lx02, Lx03, Lx04, Lx05, Lx06, Lx07: UInt64;
  Lx08, Lx09, Lx10, Lx11, Lx12, Lx13, Lx14, Lx15: UInt64;
  Lx16, Lx17, Lx18, Lx19, Lx20, Lx21, Lx22, Lx23: UInt64;
  Lx24, Lx25, Lx26, Lx27, Lx28, Lx29, Lx30, Lx31, Lx32: UInt64;
begin
  Lx00 := TCodec.Decode32(AN, 0);
  Lx01 := UInt64(TCodec.Decode24(AN, 4)) shl 4;
  Lx02 := TCodec.Decode32(AN, 7);
  Lx03 := UInt64(TCodec.Decode24(AN, 11)) shl 4;
  Lx04 := TCodec.Decode32(AN, 14);
  Lx05 := UInt64(TCodec.Decode24(AN, 18)) shl 4;
  Lx06 := TCodec.Decode32(AN, 21);
  Lx07 := UInt64(TCodec.Decode24(AN, 25)) shl 4;
  Lx08 := TCodec.Decode32(AN, 28);
  Lx09 := UInt64(TCodec.Decode24(AN, 32)) shl 4;
  Lx10 := TCodec.Decode32(AN, 35);
  Lx11 := UInt64(TCodec.Decode24(AN, 39)) shl 4;
  Lx12 := TCodec.Decode32(AN, 42);
  Lx13 := UInt64(TCodec.Decode24(AN, 46)) shl 4;
  Lx14 := TCodec.Decode32(AN, 49);
  Lx15 := UInt64(TCodec.Decode24(AN, 53)) shl 4;
  Lx16 := TCodec.Decode32(AN, 56);
  Lx17 := UInt64(TCodec.Decode24(AN, 60)) shl 4;
  Lx18 := TCodec.Decode32(AN, 63);
  Lx19 := UInt64(TCodec.Decode24(AN, 67)) shl 4;
  Lx20 := TCodec.Decode32(AN, 70);
  Lx21 := UInt64(TCodec.Decode24(AN, 74)) shl 4;
  Lx22 := TCodec.Decode32(AN, 77);
  Lx23 := UInt64(TCodec.Decode24(AN, 81)) shl 4;
  Lx24 := TCodec.Decode32(AN, 84);
  Lx25 := UInt64(TCodec.Decode24(AN, 88)) shl 4;
  Lx26 := TCodec.Decode32(AN, 91);
  Lx27 := UInt64(TCodec.Decode24(AN, 95)) shl 4;
  Lx28 := TCodec.Decode32(AN, 98);
  Lx29 := UInt64(TCodec.Decode24(AN, 102)) shl 4;
  Lx30 := TCodec.Decode32(AN, 105);
  Lx31 := UInt64(TCodec.Decode24(AN, 109)) shl 4;
  Lx32 := TCodec.Decode16(AN, 112);

  Lx16 := Lx16 + Lx32 * UInt64(L4_0);
  Lx17 := Lx17 + Lx32 * UInt64(L4_1);
  Lx18 := Lx18 + Lx32 * UInt64(L4_2);
  Lx19 := Lx19 + Lx32 * UInt64(L4_3);
  Lx20 := Lx20 + Lx32 * UInt64(L4_4);
  Lx21 := Lx21 + Lx32 * UInt64(L4_5);
  Lx22 := Lx22 + Lx32 * UInt64(L4_6);
  Lx23 := Lx23 + Lx32 * UInt64(L4_7);

  Lx31 := Lx31 + (Lx30 shr 28); Lx30 := Lx30 and M28UL;
  Lx15 := Lx15 + Lx31 * UInt64(L4_0);
  Lx16 := Lx16 + Lx31 * UInt64(L4_1);
  Lx17 := Lx17 + Lx31 * UInt64(L4_2);
  Lx18 := Lx18 + Lx31 * UInt64(L4_3);
  Lx19 := Lx19 + Lx31 * UInt64(L4_4);
  Lx20 := Lx20 + Lx31 * UInt64(L4_5);
  Lx21 := Lx21 + Lx31 * UInt64(L4_6);
  Lx22 := Lx22 + Lx31 * UInt64(L4_7);

  Lx14 := Lx14 + Lx30 * UInt64(L4_0);
  Lx15 := Lx15 + Lx30 * UInt64(L4_1);
  Lx16 := Lx16 + Lx30 * UInt64(L4_2);
  Lx17 := Lx17 + Lx30 * UInt64(L4_3);
  Lx18 := Lx18 + Lx30 * UInt64(L4_4);
  Lx19 := Lx19 + Lx30 * UInt64(L4_5);
  Lx20 := Lx20 + Lx30 * UInt64(L4_6);
  Lx21 := Lx21 + Lx30 * UInt64(L4_7);

  Lx29 := Lx29 + (Lx28 shr 28); Lx28 := Lx28 and M28UL;
  Lx13 := Lx13 + Lx29 * UInt64(L4_0);
  Lx14 := Lx14 + Lx29 * UInt64(L4_1);
  Lx15 := Lx15 + Lx29 * UInt64(L4_2);
  Lx16 := Lx16 + Lx29 * UInt64(L4_3);
  Lx17 := Lx17 + Lx29 * UInt64(L4_4);
  Lx18 := Lx18 + Lx29 * UInt64(L4_5);
  Lx19 := Lx19 + Lx29 * UInt64(L4_6);
  Lx20 := Lx20 + Lx29 * UInt64(L4_7);

  Lx12 := Lx12 + Lx28 * UInt64(L4_0);
  Lx13 := Lx13 + Lx28 * UInt64(L4_1);
  Lx14 := Lx14 + Lx28 * UInt64(L4_2);
  Lx15 := Lx15 + Lx28 * UInt64(L4_3);
  Lx16 := Lx16 + Lx28 * UInt64(L4_4);
  Lx17 := Lx17 + Lx28 * UInt64(L4_5);
  Lx18 := Lx18 + Lx28 * UInt64(L4_6);
  Lx19 := Lx19 + Lx28 * UInt64(L4_7);

  Lx27 := Lx27 + (Lx26 shr 28); Lx26 := Lx26 and M28UL;
  Lx11 := Lx11 + Lx27 * UInt64(L4_0);
  Lx12 := Lx12 + Lx27 * UInt64(L4_1);
  Lx13 := Lx13 + Lx27 * UInt64(L4_2);
  Lx14 := Lx14 + Lx27 * UInt64(L4_3);
  Lx15 := Lx15 + Lx27 * UInt64(L4_4);
  Lx16 := Lx16 + Lx27 * UInt64(L4_5);
  Lx17 := Lx17 + Lx27 * UInt64(L4_6);
  Lx18 := Lx18 + Lx27 * UInt64(L4_7);

  Lx10 := Lx10 + Lx26 * UInt64(L4_0);
  Lx11 := Lx11 + Lx26 * UInt64(L4_1);
  Lx12 := Lx12 + Lx26 * UInt64(L4_2);
  Lx13 := Lx13 + Lx26 * UInt64(L4_3);
  Lx14 := Lx14 + Lx26 * UInt64(L4_4);
  Lx15 := Lx15 + Lx26 * UInt64(L4_5);
  Lx16 := Lx16 + Lx26 * UInt64(L4_6);
  Lx17 := Lx17 + Lx26 * UInt64(L4_7);

  Lx25 := Lx25 + (Lx24 shr 28); Lx24 := Lx24 and M28UL;
  Lx09 := Lx09 + Lx25 * UInt64(L4_0);
  Lx10 := Lx10 + Lx25 * UInt64(L4_1);
  Lx11 := Lx11 + Lx25 * UInt64(L4_2);
  Lx12 := Lx12 + Lx25 * UInt64(L4_3);
  Lx13 := Lx13 + Lx25 * UInt64(L4_4);
  Lx14 := Lx14 + Lx25 * UInt64(L4_5);
  Lx15 := Lx15 + Lx25 * UInt64(L4_6);
  Lx16 := Lx16 + Lx25 * UInt64(L4_7);

  Lx21 := Lx21 + (Lx20 shr 28); Lx20 := Lx20 and M28UL;
  Lx22 := Lx22 + (Lx21 shr 28); Lx21 := Lx21 and M28UL;
  Lx23 := Lx23 + (Lx22 shr 28); Lx22 := Lx22 and M28UL;
  Lx24 := Lx24 + (Lx23 shr 28); Lx23 := Lx23 and M28UL;

  Lx08 := Lx08 + Lx24 * UInt64(L4_0);
  Lx09 := Lx09 + Lx24 * UInt64(L4_1);
  Lx10 := Lx10 + Lx24 * UInt64(L4_2);
  Lx11 := Lx11 + Lx24 * UInt64(L4_3);
  Lx12 := Lx12 + Lx24 * UInt64(L4_4);
  Lx13 := Lx13 + Lx24 * UInt64(L4_5);
  Lx14 := Lx14 + Lx24 * UInt64(L4_6);
  Lx15 := Lx15 + Lx24 * UInt64(L4_7);

  Lx07 := Lx07 + Lx23 * UInt64(L4_0);
  Lx08 := Lx08 + Lx23 * UInt64(L4_1);
  Lx09 := Lx09 + Lx23 * UInt64(L4_2);
  Lx10 := Lx10 + Lx23 * UInt64(L4_3);
  Lx11 := Lx11 + Lx23 * UInt64(L4_4);
  Lx12 := Lx12 + Lx23 * UInt64(L4_5);
  Lx13 := Lx13 + Lx23 * UInt64(L4_6);
  Lx14 := Lx14 + Lx23 * UInt64(L4_7);

  Lx06 := Lx06 + Lx22 * UInt64(L4_0);
  Lx07 := Lx07 + Lx22 * UInt64(L4_1);
  Lx08 := Lx08 + Lx22 * UInt64(L4_2);
  Lx09 := Lx09 + Lx22 * UInt64(L4_3);
  Lx10 := Lx10 + Lx22 * UInt64(L4_4);
  Lx11 := Lx11 + Lx22 * UInt64(L4_5);
  Lx12 := Lx12 + Lx22 * UInt64(L4_6);
  Lx13 := Lx13 + Lx22 * UInt64(L4_7);

  Lx18 := Lx18 + (Lx17 shr 28); Lx17 := Lx17 and M28UL;
  Lx19 := Lx19 + (Lx18 shr 28); Lx18 := Lx18 and M28UL;
  Lx20 := Lx20 + (Lx19 shr 28); Lx19 := Lx19 and M28UL;
  Lx21 := Lx21 + (Lx20 shr 28); Lx20 := Lx20 and M28UL;

  Lx05 := Lx05 + Lx21 * UInt64(L4_0);
  Lx06 := Lx06 + Lx21 * UInt64(L4_1);
  Lx07 := Lx07 + Lx21 * UInt64(L4_2);
  Lx08 := Lx08 + Lx21 * UInt64(L4_3);
  Lx09 := Lx09 + Lx21 * UInt64(L4_4);
  Lx10 := Lx10 + Lx21 * UInt64(L4_5);
  Lx11 := Lx11 + Lx21 * UInt64(L4_6);
  Lx12 := Lx12 + Lx21 * UInt64(L4_7);

  Lx04 := Lx04 + Lx20 * UInt64(L4_0);
  Lx05 := Lx05 + Lx20 * UInt64(L4_1);
  Lx06 := Lx06 + Lx20 * UInt64(L4_2);
  Lx07 := Lx07 + Lx20 * UInt64(L4_3);
  Lx08 := Lx08 + Lx20 * UInt64(L4_4);
  Lx09 := Lx09 + Lx20 * UInt64(L4_5);
  Lx10 := Lx10 + Lx20 * UInt64(L4_6);
  Lx11 := Lx11 + Lx20 * UInt64(L4_7);

  Lx03 := Lx03 + Lx19 * UInt64(L4_0);
  Lx04 := Lx04 + Lx19 * UInt64(L4_1);
  Lx05 := Lx05 + Lx19 * UInt64(L4_2);
  Lx06 := Lx06 + Lx19 * UInt64(L4_3);
  Lx07 := Lx07 + Lx19 * UInt64(L4_4);
  Lx08 := Lx08 + Lx19 * UInt64(L4_5);
  Lx09 := Lx09 + Lx19 * UInt64(L4_6);
  Lx10 := Lx10 + Lx19 * UInt64(L4_7);

  Lx15 := Lx15 + (Lx14 shr 28); Lx14 := Lx14 and M28UL;
  Lx16 := Lx16 + (Lx15 shr 28); Lx15 := Lx15 and M28UL;
  Lx17 := Lx17 + (Lx16 shr 28); Lx16 := Lx16 and M28UL;
  Lx18 := Lx18 + (Lx17 shr 28); Lx17 := Lx17 and M28UL;

  Lx02 := Lx02 + Lx18 * UInt64(L4_0);
  Lx03 := Lx03 + Lx18 * UInt64(L4_1);
  Lx04 := Lx04 + Lx18 * UInt64(L4_2);
  Lx05 := Lx05 + Lx18 * UInt64(L4_3);
  Lx06 := Lx06 + Lx18 * UInt64(L4_4);
  Lx07 := Lx07 + Lx18 * UInt64(L4_5);
  Lx08 := Lx08 + Lx18 * UInt64(L4_6);
  Lx09 := Lx09 + Lx18 * UInt64(L4_7);

  Lx01 := Lx01 + Lx17 * UInt64(L4_0);
  Lx02 := Lx02 + Lx17 * UInt64(L4_1);
  Lx03 := Lx03 + Lx17 * UInt64(L4_2);
  Lx04 := Lx04 + Lx17 * UInt64(L4_3);
  Lx05 := Lx05 + Lx17 * UInt64(L4_4);
  Lx06 := Lx06 + Lx17 * UInt64(L4_5);
  Lx07 := Lx07 + Lx17 * UInt64(L4_6);
  Lx08 := Lx08 + Lx17 * UInt64(L4_7);

  Lx16 := Lx16 * 4;
  Lx16 := Lx16 + (Lx15 shr 26); Lx15 := Lx15 and M26UL;
  Lx16 := Lx16 + 1;

  Lx00 := Lx00 + Lx16 * UInt64(L_0);
  Lx01 := Lx01 + Lx16 * UInt64(L_1);
  Lx02 := Lx02 + Lx16 * UInt64(L_2);
  Lx03 := Lx03 + Lx16 * UInt64(L_3);
  Lx04 := Lx04 + Lx16 * UInt64(L_4);
  Lx05 := Lx05 + Lx16 * UInt64(L_5);
  Lx06 := Lx06 + Lx16 * UInt64(L_6);
  Lx07 := Lx07 + Lx16 * UInt64(L_7);

  Lx01 := Lx01 + (Lx00 shr 28); Lx00 := Lx00 and M28UL;
  Lx02 := Lx02 + (Lx01 shr 28); Lx01 := Lx01 and M28UL;
  Lx03 := Lx03 + (Lx02 shr 28); Lx02 := Lx02 and M28UL;
  Lx04 := Lx04 + (Lx03 shr 28); Lx03 := Lx03 and M28UL;
  Lx05 := Lx05 + (Lx04 shr 28); Lx04 := Lx04 and M28UL;
  Lx06 := Lx06 + (Lx05 shr 28); Lx05 := Lx05 and M28UL;
  Lx07 := Lx07 + (Lx06 shr 28); Lx06 := Lx06 and M28UL;
  Lx08 := Lx08 + (Lx07 shr 28); Lx07 := Lx07 and M28UL;
  Lx09 := Lx09 + (Lx08 shr 28); Lx08 := Lx08 and M28UL;
  Lx10 := Lx10 + (Lx09 shr 28); Lx09 := Lx09 and M28UL;
  Lx11 := Lx11 + (Lx10 shr 28); Lx10 := Lx10 and M28UL;
  Lx12 := Lx12 + (Lx11 shr 28); Lx11 := Lx11 and M28UL;
  Lx13 := Lx13 + (Lx12 shr 28); Lx12 := Lx12 and M28UL;
  Lx14 := Lx14 + (Lx13 shr 28); Lx13 := Lx13 and M28UL;
  Lx15 := Lx15 + (Lx14 shr 28); Lx14 := Lx14 and M28UL;
  Lx16 := Lx15 shr 26; Lx15 := Lx15 and M26UL;

  Lx16 := Lx16 - 1;

  {$IFDEF DEBUG}
  System.Assert((Lx16 = UInt64(0)) or (Lx16 = UInt64($FFFFFFFFFFFFFFFF)));
  {$ENDIF}

  Lx00 := Lx00 - (Lx16 and UInt64(L_0));
  Lx01 := Lx01 - (Lx16 and UInt64(L_1));
  Lx02 := Lx02 - (Lx16 and UInt64(L_2));
  Lx03 := Lx03 - (Lx16 and UInt64(L_3));
  Lx04 := Lx04 - (Lx16 and UInt64(L_4));
  Lx05 := Lx05 - (Lx16 and UInt64(L_5));
  Lx06 := Lx06 - (Lx16 and UInt64(L_6));
  Lx07 := Lx07 - (Lx16 and UInt64(L_7));

  Lx01 := Lx01 + UInt64(TBitOperations.Asr64(Int64(Lx00), 28)); Lx00 := Lx00 and M28UL;
  Lx02 := Lx02 + UInt64(TBitOperations.Asr64(Int64(Lx01), 28)); Lx01 := Lx01 and M28UL;
  Lx03 := Lx03 + UInt64(TBitOperations.Asr64(Int64(Lx02), 28)); Lx02 := Lx02 and M28UL;
  Lx04 := Lx04 + UInt64(TBitOperations.Asr64(Int64(Lx03), 28)); Lx03 := Lx03 and M28UL;
  Lx05 := Lx05 + UInt64(TBitOperations.Asr64(Int64(Lx04), 28)); Lx04 := Lx04 and M28UL;
  Lx06 := Lx06 + UInt64(TBitOperations.Asr64(Int64(Lx05), 28)); Lx05 := Lx05 and M28UL;
  Lx07 := Lx07 + UInt64(TBitOperations.Asr64(Int64(Lx06), 28)); Lx06 := Lx06 and M28UL;
  Lx08 := Lx08 + UInt64(TBitOperations.Asr64(Int64(Lx07), 28)); Lx07 := Lx07 and M28UL;
  Lx09 := Lx09 + UInt64(TBitOperations.Asr64(Int64(Lx08), 28)); Lx08 := Lx08 and M28UL;
  Lx10 := Lx10 + UInt64(TBitOperations.Asr64(Int64(Lx09), 28)); Lx09 := Lx09 and M28UL;
  Lx11 := Lx11 + UInt64(TBitOperations.Asr64(Int64(Lx10), 28)); Lx10 := Lx10 and M28UL;
  Lx12 := Lx12 + UInt64(TBitOperations.Asr64(Int64(Lx11), 28)); Lx11 := Lx11 and M28UL;
  Lx13 := Lx13 + UInt64(TBitOperations.Asr64(Int64(Lx12), 28)); Lx12 := Lx12 and M28UL;
  Lx14 := Lx14 + UInt64(TBitOperations.Asr64(Int64(Lx13), 28)); Lx13 := Lx13 and M28UL;
  Lx15 := Lx15 + UInt64(TBitOperations.Asr64(Int64(Lx14), 28)); Lx14 := Lx14 and M28UL;

  {$IFDEF DEBUG}
  System.Assert(Lx15 shr 26 = UInt64(0));
  {$ENDIF}

  TCodec.Encode56(Lx00 or (Lx01 shl 28), AR, 0);
  TCodec.Encode56(Lx02 or (Lx03 shl 28), AR, 7);
  TCodec.Encode56(Lx04 or (Lx05 shl 28), AR, 14);
  TCodec.Encode56(Lx06 or (Lx07 shl 28), AR, 21);
  TCodec.Encode56(Lx08 or (Lx09 shl 28), AR, 28);
  TCodec.Encode56(Lx10 or (Lx11 shl 28), AR, 35);
  TCodec.Encode56(Lx12 or (Lx13 shl 28), AR, 42);
  TCodec.Encode56(Lx14 or (Lx15 shl 28), AR, 49);
end;

class function TScalar448.ReduceBasisVar(const AK: TCryptoLibUInt32Array;
  AZ0: TCryptoLibUInt32Array; AZ1: TCryptoLibUInt32Array): Boolean;
var
  LNu, LNv, Lp, Lt: TCryptoLibUInt32Array;
  Lu0, Lu1, Lv0, Lv1: TCryptoLibUInt32Array;
  LIterations, LLast, LLenNv, LLenP, LS: Int32;
begin
  System.SetLength(LNu, 28);
  System.SetLength(LNv, 28);
  System.SetLength(Lp, 28);
  System.SetLength(Lt, 28);
  System.SetLength(Lu0, 8);
  System.SetLength(Lu1, 8);
  System.SetLength(Lv0, 8);
  System.SetLength(Lv1, 8);
  System.Move(FLSq[0], LNu[0], 28 * System.SizeOf(UInt32));
  TNat448.Square(AK, LNv);
  LNv[0] := LNv[0] + 1;
  TNat448.Mul(FL, AK, Lp);
  System.Move(FL[0], Lu0[0], 8 * System.SizeOf(UInt32));
  System.Move(AK[0], Lv0[0], 8 * System.SizeOf(UInt32));
  Lv1[0] := 1;
  LIterations := TargetLength * 4;
  LLast := 27;
  LLenNv := TScalarUtilities.GetBitLengthPositive(LLast, LNv);
  while LLenNv > TargetLength do
  begin
    System.Dec(LIterations);
    if LIterations < 0 then
      Exit(False);
    LLenP := TScalarUtilities.GetBitLength(LLast, Lp);
    LS := LLenP - LLenNv;
    LS := LS and (not TBitOperations.Asr32(LS, 31));
    if Int32(Lp[LLast]) < 0 then
    begin
      TScalarUtilities.AddShifted_NP(LLast, LS, LNu, LNv, Lp, Lt);
      TScalarUtilities.AddShifted_UV(7, LS, Lu0, Lu1, Lv0, Lv1);
    end
    else
    begin
      TScalarUtilities.SubShifted_NP(LLast, LS, LNu, LNv, Lp, Lt);
      TScalarUtilities.SubShifted_UV(7, LS, Lu0, Lu1, Lv0, Lv1);
    end;
    if TScalarUtilities.LessThan(LLast, LNu, LNv) then
    begin
      TScalarUtilities.Swap(Lu0, Lv0);
      TScalarUtilities.Swap(Lu1, Lv1);
      TScalarUtilities.Swap(LNu, LNv);
      LLast := TBitOperations.Asr32(LLenNv, 5);
      LLenNv := TScalarUtilities.GetBitLengthPositive(LLast, LNv);
    end;
  end;
  {$IFDEF DEBUG}
  System.Assert(TBitOperations.Asr32(Int32(Lv0[7]), 31) = Int32(Lv0[7]));
  System.Assert(TBitOperations.Asr32(Int32(Lv1[7]), 31) = Int32(Lv1[7]));
  {$ENDIF}
  System.Move(Lv0[0], AZ0[0], 8 * System.SizeOf(UInt32));
  System.Move(Lv1[0], AZ1[0], 8 * System.SizeOf(UInt32));
  Result := True;
end;

class procedure TScalar448.ToSignedDigits(ABits: Int32;
  const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((448 < ABits) and (ABits < 480));
  System.Assert(System.Length(AZ) > Size);
  {$ENDIF}
  AZ[Size] := (UInt32(1) shl (ABits - 448))
            + TNat.CAdd(Size, (not Int32(AX[0])) and 1, AX, FL, AZ);
  LC := TNat.ShiftDownBit(Size + 1, AZ, 0);
  {$IFDEF DEBUG}
  System.Assert(LC = UInt32(1 shl 31));
  {$ENDIF}
end;

end.
