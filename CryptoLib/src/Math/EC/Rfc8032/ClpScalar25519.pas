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

unit ClpScalar25519;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpCodec,
  ClpWnaf,
  ClpNat256,
  ClpNat,
  ClpScalarUtilities,
  ClpCryptoLibTypes;

type
  TScalar25519 = class sealed
  strict private
  const
    Size = 8;
    ScalarBytes = Size * 4;
    M28L = $0FFFFFFF;
    TargetLength = 254;
    L0 = -$030A2C13;
    L1 = $012631A6;
    L2 = $079CD658;
    L3 = -$006215D1;
    L4 = $000014DF;
  class var
    FL, FLsq: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class constructor Create;
  public
    class function CheckVar(const &AS: TCryptoLibByteArray; AN: TCryptoLibUInt32Array): Boolean; static;
    class procedure Decode(const AK: TCryptoLibByteArray; AN: TCryptoLibUInt32Array); static;
    class procedure GetOrderWnafVar(AWidth: Int32; const AWs: TCryptoLibShortIntArray); static;
    class procedure Multiply128Var(const AX: TCryptoLibUInt32Array; const AY128: TCryptoLibUInt32Array;
      AZ: TCryptoLibUInt32Array); static;
    class function Reduce384(const AN: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    class procedure Reduce384(const AN: TCryptoLibByteArray; const AR: TCryptoLibByteArray); overload; static;
    class function Reduce512(const AN: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    class procedure Reduce512(const AN: TCryptoLibByteArray; const AR: TCryptoLibByteArray); overload; static;
    class function ReduceBasisVar(const AK: TCryptoLibUInt32Array; AZ0: TCryptoLibUInt32Array;
      AZ1: TCryptoLibUInt32Array): Boolean; static;
    class procedure ToSignedDigits(ABits: Int32; AZ: TCryptoLibUInt32Array); static;
  end;

implementation

class constructor TScalar25519.Create;
begin
  Boot;
end;

class procedure TScalar25519.Boot;
begin
  FL := TCryptoLibUInt32Array.Create($5CF5D3ED, $5812631A, $A2F79CD6, $14DEF9DE,
    $00000000, $00000000, $00000000, $10000000);
  FLsq := TCryptoLibUInt32Array.Create($AB128969, $E2EDF685, $2298A31D, $68039276,
    $D217F5BE, $3DCEEC73, $1B7C309A, $A1B39941, $4B9EBA7D, $CB024C63, $D45EF39A,
    $029BDF3B, $00000000, $00000000, $00000000, $01000000);
end;

class function TScalar25519.CheckVar(const &AS: TCryptoLibByteArray; AN: TCryptoLibUInt32Array): Boolean;
begin
  Decode(&AS, AN);
  Result := not TNat256.Gte(AN, FL);
end;

class procedure TScalar25519.Decode(const AK: TCryptoLibByteArray; AN: TCryptoLibUInt32Array);
begin
  TCodec.Decode32(AK, 0, AN, 0, Size);
end;

class procedure TScalar25519.GetOrderWnafVar(AWidth: Int32; const AWs: TCryptoLibShortIntArray);
begin
  TWnaf.GetSignedVar(FL, AWidth, AWs);
end;

class procedure TScalar25519.Multiply128Var(const AX: TCryptoLibUInt32Array; const AY128: TCryptoLibUInt32Array;
  AZ: TCryptoLibUInt32Array);
var
  LTt: TCryptoLibUInt32Array;
  LBytes: TCryptoLibByteArray;
  LR: TCryptoLibByteArray;
begin
  System.SetLength(LTt, 12);
  TNat256.Mul128(AX, AY128, LTt);
  if Int32(AY128[3]) < 0 then
  begin
    TNat256.AddTo(FL, 0, LTt, 4, 0);
    TNat256.SubFrom(AX, 0, LTt, 4, 0);
  end;
  System.SetLength(LBytes, 48);
  TCodec.Encode32(LTt, 0, 12, LBytes, 0);
  LR := Reduce384(LBytes);
  TCodec.Decode32(LR, 0, AZ, 0, Size);
end;

class function TScalar25519.Reduce384(const AN: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  System.SetLength(Result, ScalarBytes);
  Reduce384(AN, Result);
end;

class procedure TScalar25519.Reduce384(const AN: TCryptoLibByteArray; const AR: TCryptoLibByteArray);
var
  Lx00, Lx01, Lx02, Lx03, Lx04, Lx05, Lx06, Lx07, Lx08, Lx09, Lx10, Lx11, Lx12, Lx13, Lt: Int64;
begin
  Lx00 := Int64(TCodec.Decode32(AN, 0));
  Lx01 := Int64(TCodec.Decode24(AN, 4)) shl 4;
  Lx02 := Int64(TCodec.Decode32(AN, 7));
  Lx03 := Int64(TCodec.Decode24(AN, 11)) shl 4;
  Lx04 := Int64(TCodec.Decode32(AN, 14));
  Lx05 := Int64(TCodec.Decode24(AN, 18)) shl 4;
  Lx06 := Int64(TCodec.Decode32(AN, 21));
  Lx07 := Int64(TCodec.Decode24(AN, 25)) shl 4;
  Lx08 := Int64(TCodec.Decode32(AN, 28));
  Lx09 := Int64(TCodec.Decode24(AN, 32)) shl 4;
  Lx10 := Int64(TCodec.Decode32(AN, 35));
  Lx11 := Int64(TCodec.Decode24(AN, 39)) shl 4;
  Lx12 := Int64(TCodec.Decode32(AN, 42));
  Lx13 := Int64(TCodec.Decode16(AN, 46)) shl 4;
  Lx13 := Lx13 + TBitOperations.Asr64(Lx12, 28);
  Lx12 := Lx12 and M28L;
  Lx04 := Lx04 - Lx13 * L0;
  Lx05 := Lx05 - Lx13 * L1;
  Lx06 := Lx06 - Lx13 * L2;
  Lx07 := Lx07 - Lx13 * L3;
  Lx08 := Lx08 - Lx13 * L4;
  Lx12 := Lx12 + TBitOperations.Asr64(Lx11, 28);
  Lx11 := Lx11 and M28L;
  Lx03 := Lx03 - Lx12 * L0;
  Lx04 := Lx04 - Lx12 * L1;
  Lx05 := Lx05 - Lx12 * L2;
  Lx06 := Lx06 - Lx12 * L3;
  Lx07 := Lx07 - Lx12 * L4;
  Lx11 := Lx11 + TBitOperations.Asr64(Lx10, 28);
  Lx10 := Lx10 and M28L;
  Lx02 := Lx02 - Lx11 * L0;
  Lx03 := Lx03 - Lx11 * L1;
  Lx04 := Lx04 - Lx11 * L2;
  Lx05 := Lx05 - Lx11 * L3;
  Lx06 := Lx06 - Lx11 * L4;
  Lx10 := Lx10 + TBitOperations.Asr64(Lx09, 28);
  Lx09 := Lx09 and M28L;
  Lx01 := Lx01 - Lx10 * L0;
  Lx02 := Lx02 - Lx10 * L1;
  Lx03 := Lx03 - Lx10 * L2;
  Lx04 := Lx04 - Lx10 * L3;
  Lx05 := Lx05 - Lx10 * L4;
  Lx08 := Lx08 + TBitOperations.Asr64(Lx07, 28);
  Lx07 := Lx07 and M28L;
  Lx09 := Lx09 + TBitOperations.Asr64(Lx08, 28);
  Lx08 := Lx08 and M28L;
  Lt := TBitOperations.Asr64(Lx08, 27) and 1;
  Lx09 := Lx09 + Lt;
  Lx00 := Lx00 - Lx09 * L0;
  Lx01 := Lx01 - Lx09 * L1;
  Lx02 := Lx02 - Lx09 * L2;
  Lx03 := Lx03 - Lx09 * L3;
  Lx04 := Lx04 - Lx09 * L4;
  Lx01 := Lx01 + TBitOperations.Asr64(Lx00, 28);
  Lx00 := Lx00 and M28L;
  Lx02 := Lx02 + TBitOperations.Asr64(Lx01, 28);
  Lx01 := Lx01 and M28L;
  Lx03 := Lx03 + TBitOperations.Asr64(Lx02, 28);
  Lx02 := Lx02 and M28L;
  Lx04 := Lx04 + TBitOperations.Asr64(Lx03, 28);
  Lx03 := Lx03 and M28L;
  Lx05 := Lx05 + TBitOperations.Asr64(Lx04, 28);
  Lx04 := Lx04 and M28L;
  Lx06 := Lx06 + TBitOperations.Asr64(Lx05, 28);
  Lx05 := Lx05 and M28L;
  Lx07 := Lx07 + TBitOperations.Asr64(Lx06, 28);
  Lx06 := Lx06 and M28L;
  Lx08 := Lx08 + TBitOperations.Asr64(Lx07, 28);
  Lx07 := Lx07 and M28L;
  Lx09 := TBitOperations.Asr64(Lx08, 28);
  Lx08 := Lx08 and M28L;
  Lx09 := Lx09 - Lt;
  {$IFDEF DEBUG}
  System.Assert((Lx09 = 0) or (Lx09 = -1));
  {$ENDIF}
  Lx00 := Lx00 + (Lx09 and Int64(L0));
  Lx01 := Lx01 + (Lx09 and Int64(L1));
  Lx02 := Lx02 + (Lx09 and Int64(L2));
  Lx03 := Lx03 + (Lx09 and Int64(L3));
  Lx04 := Lx04 + (Lx09 and Int64(L4));
  Lx01 := Lx01 + TBitOperations.Asr64(Lx00, 28);
  Lx00 := Lx00 and M28L;
  Lx02 := Lx02 + TBitOperations.Asr64(Lx01, 28);
  Lx01 := Lx01 and M28L;
  Lx03 := Lx03 + TBitOperations.Asr64(Lx02, 28);
  Lx02 := Lx02 and M28L;
  Lx04 := Lx04 + TBitOperations.Asr64(Lx03, 28);
  Lx03 := Lx03 and M28L;
  Lx05 := Lx05 + TBitOperations.Asr64(Lx04, 28);
  Lx04 := Lx04 and M28L;
  Lx06 := Lx06 + TBitOperations.Asr64(Lx05, 28);
  Lx05 := Lx05 and M28L;
  Lx07 := Lx07 + TBitOperations.Asr64(Lx06, 28);
  Lx06 := Lx06 and M28L;
  Lx08 := Lx08 + TBitOperations.Asr64(Lx07, 28);
  Lx07 := Lx07 and M28L;
  TCodec.Encode56(UInt64(Lx00 or (Lx01 shl 28)), AR, 0);
  TCodec.Encode56(UInt64(Lx02 or (Lx03 shl 28)), AR, 7);
  TCodec.Encode56(UInt64(Lx04 or (Lx05 shl 28)), AR, 14);
  TCodec.Encode56(UInt64(Lx06 or (Lx07 shl 28)), AR, 21);
  TCodec.Encode32(UInt32(Lx08), AR, 28);
end;

class function TScalar25519.Reduce512(const AN: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  System.SetLength(Result, ScalarBytes);
  Reduce512(AN, Result);
end;

class procedure TScalar25519.Reduce512(const AN: TCryptoLibByteArray; const AR: TCryptoLibByteArray);
var
  Lx00, Lx01, Lx02, Lx03, Lx04, Lx05, Lx06, Lx07, Lx08, Lx09, Lx10, Lx11, Lx12, Lx13, Lx14, Lx15, Lx16, Lx17, Lx18, Lt: Int64;
begin
  Lx00 := Int64(TCodec.Decode32(AN, 0));
  Lx01 := Int64(TCodec.Decode24(AN, 4)) shl 4;
  Lx02 := Int64(TCodec.Decode32(AN, 7));
  Lx03 := Int64(TCodec.Decode24(AN, 11)) shl 4;
  Lx04 := Int64(TCodec.Decode32(AN, 14));
  Lx05 := Int64(TCodec.Decode24(AN, 18)) shl 4;
  Lx06 := Int64(TCodec.Decode32(AN, 21));
  Lx07 := Int64(TCodec.Decode24(AN, 25)) shl 4;
  Lx08 := Int64(TCodec.Decode32(AN, 28));
  Lx09 := Int64(TCodec.Decode24(AN, 32)) shl 4;
  Lx10 := Int64(TCodec.Decode32(AN, 35));
  Lx11 := Int64(TCodec.Decode24(AN, 39)) shl 4;
  Lx12 := Int64(TCodec.Decode32(AN, 42));
  Lx13 := Int64(TCodec.Decode24(AN, 46)) shl 4;
  Lx14 := Int64(TCodec.Decode32(AN, 49));
  Lx15 := Int64(TCodec.Decode24(AN, 53)) shl 4;
  Lx16 := Int64(TCodec.Decode32(AN, 56));
  Lx17 := Int64(TCodec.Decode24(AN, 60)) shl 4;
  Lx18 := Int64(AN[63]);
  Lx09 := Lx09 - Lx18 * L0;
  Lx10 := Lx10 - Lx18 * L1;
  Lx11 := Lx11 - Lx18 * L2;
  Lx12 := Lx12 - Lx18 * L3;
  Lx13 := Lx13 - Lx18 * L4;
  Lx17 := Lx17 + TBitOperations.Asr64(Lx16, 28);
  Lx16 := Lx16 and M28L;
  Lx08 := Lx08 - Lx17 * L0;
  Lx09 := Lx09 - Lx17 * L1;
  Lx10 := Lx10 - Lx17 * L2;
  Lx11 := Lx11 - Lx17 * L3;
  Lx12 := Lx12 - Lx17 * L4;
  Lx07 := Lx07 - Lx16 * L0;
  Lx08 := Lx08 - Lx16 * L1;
  Lx09 := Lx09 - Lx16 * L2;
  Lx10 := Lx10 - Lx16 * L3;
  Lx11 := Lx11 - Lx16 * L4;
  Lx15 := Lx15 + TBitOperations.Asr64(Lx14, 28);
  Lx14 := Lx14 and M28L;
  Lx06 := Lx06 - Lx15 * L0;
  Lx07 := Lx07 - Lx15 * L1;
  Lx08 := Lx08 - Lx15 * L2;
  Lx09 := Lx09 - Lx15 * L3;
  Lx10 := Lx10 - Lx15 * L4;
  Lx05 := Lx05 - Lx14 * L0;
  Lx06 := Lx06 - Lx14 * L1;
  Lx07 := Lx07 - Lx14 * L2;
  Lx08 := Lx08 - Lx14 * L3;
  Lx09 := Lx09 - Lx14 * L4;
  Lx13 := Lx13 + TBitOperations.Asr64(Lx12, 28);
  Lx12 := Lx12 and M28L;
  Lx04 := Lx04 - Lx13 * L0;
  Lx05 := Lx05 - Lx13 * L1;
  Lx06 := Lx06 - Lx13 * L2;
  Lx07 := Lx07 - Lx13 * L3;
  Lx08 := Lx08 - Lx13 * L4;
  Lx12 := Lx12 + TBitOperations.Asr64(Lx11, 28);
  Lx11 := Lx11 and M28L;
  Lx03 := Lx03 - Lx12 * L0;
  Lx04 := Lx04 - Lx12 * L1;
  Lx05 := Lx05 - Lx12 * L2;
  Lx06 := Lx06 - Lx12 * L3;
  Lx07 := Lx07 - Lx12 * L4;
  Lx11 := Lx11 + TBitOperations.Asr64(Lx10, 28);
  Lx10 := Lx10 and M28L;
  Lx02 := Lx02 - Lx11 * L0;
  Lx03 := Lx03 - Lx11 * L1;
  Lx04 := Lx04 - Lx11 * L2;
  Lx05 := Lx05 - Lx11 * L3;
  Lx06 := Lx06 - Lx11 * L4;
  Lx10 := Lx10 + TBitOperations.Asr64(Lx09, 28);
  Lx09 := Lx09 and M28L;
  Lx01 := Lx01 - Lx10 * L0;
  Lx02 := Lx02 - Lx10 * L1;
  Lx03 := Lx03 - Lx10 * L2;
  Lx04 := Lx04 - Lx10 * L3;
  Lx05 := Lx05 - Lx10 * L4;
  Lx08 := Lx08 + TBitOperations.Asr64(Lx07, 28);
  Lx07 := Lx07 and M28L;
  Lx09 := Lx09 + TBitOperations.Asr64(Lx08, 28);
  Lx08 := Lx08 and M28L;
  Lt := TBitOperations.Asr64(Lx08, 27) and 1;
  Lx09 := Lx09 + Lt;
  Lx00 := Lx00 - Lx09 * L0;
  Lx01 := Lx01 - Lx09 * L1;
  Lx02 := Lx02 - Lx09 * L2;
  Lx03 := Lx03 - Lx09 * L3;
  Lx04 := Lx04 - Lx09 * L4;
  Lx01 := Lx01 + TBitOperations.Asr64(Lx00, 28);
  Lx00 := Lx00 and M28L;
  Lx02 := Lx02 + TBitOperations.Asr64(Lx01, 28);
  Lx01 := Lx01 and M28L;
  Lx03 := Lx03 + TBitOperations.Asr64(Lx02, 28);
  Lx02 := Lx02 and M28L;
  Lx04 := Lx04 + TBitOperations.Asr64(Lx03, 28);
  Lx03 := Lx03 and M28L;
  Lx05 := Lx05 + TBitOperations.Asr64(Lx04, 28);
  Lx04 := Lx04 and M28L;
  Lx06 := Lx06 + TBitOperations.Asr64(Lx05, 28);
  Lx05 := Lx05 and M28L;
  Lx07 := Lx07 + TBitOperations.Asr64(Lx06, 28);
  Lx06 := Lx06 and M28L;
  Lx08 := Lx08 + TBitOperations.Asr64(Lx07, 28);
  Lx07 := Lx07 and M28L;
  Lx09 := TBitOperations.Asr64(Lx08, 28);
  Lx08 := Lx08 and M28L;
  Lx09 := Lx09 - Lt;
  {$IFDEF DEBUG}
  System.Assert((Lx09 = 0) or (Lx09 = -1));
  {$ENDIF}
  Lx00 := Lx00 + (Lx09 and Int64(L0));
  Lx01 := Lx01 + (Lx09 and Int64(L1));
  Lx02 := Lx02 + (Lx09 and Int64(L2));
  Lx03 := Lx03 + (Lx09 and Int64(L3));
  Lx04 := Lx04 + (Lx09 and Int64(L4));
  Lx01 := Lx01 + TBitOperations.Asr64(Lx00, 28);
  Lx00 := Lx00 and M28L;
  Lx02 := Lx02 + TBitOperations.Asr64(Lx01, 28);
  Lx01 := Lx01 and M28L;
  Lx03 := Lx03 + TBitOperations.Asr64(Lx02, 28);
  Lx02 := Lx02 and M28L;
  Lx04 := Lx04 + TBitOperations.Asr64(Lx03, 28);
  Lx03 := Lx03 and M28L;
  Lx05 := Lx05 + TBitOperations.Asr64(Lx04, 28);
  Lx04 := Lx04 and M28L;
  Lx06 := Lx06 + TBitOperations.Asr64(Lx05, 28);
  Lx05 := Lx05 and M28L;
  Lx07 := Lx07 + TBitOperations.Asr64(Lx06, 28);
  Lx06 := Lx06 and M28L;
  Lx08 := Lx08 + TBitOperations.Asr64(Lx07, 28);
  Lx07 := Lx07 and M28L;
  TCodec.Encode56(UInt64(Lx00 or (Lx01 shl 28)), AR, 0);
  TCodec.Encode56(UInt64(Lx02 or (Lx03 shl 28)), AR, 7);
  TCodec.Encode56(UInt64(Lx04 or (Lx05 shl 28)), AR, 14);
  TCodec.Encode56(UInt64(Lx06 or (Lx07 shl 28)), AR, 21);
  TCodec.Encode32(UInt32(Lx08), AR, 28);
end;

class function TScalar25519.ReduceBasisVar(const AK: TCryptoLibUInt32Array; AZ0: TCryptoLibUInt32Array;
  AZ1: TCryptoLibUInt32Array): Boolean;
var
  LNu, LNv, Lp, Lt: TCryptoLibUInt32Array;
  Lu0, Lu1, Lv0, Lv1: TCryptoLibUInt32Array;
  LIterations, LLast, LLenNv, LLenP, LS: Int32;
begin
  System.SetLength(LNu, 16);
  System.SetLength(LNv, 16);
  System.SetLength(Lp, 16);
  System.SetLength(Lt, 16);
  System.SetLength(Lu0, 4);
  System.SetLength(Lu1, 4);
  System.SetLength(Lv0, 4);
  System.SetLength(Lv1, 4);
  System.Move(FLsq[0], LNu[0], 16 * System.SizeOf(UInt32));
  TNat256.Square(AK, LNv);
  LNv[0] := LNv[0] + 1;
  TNat256.Mul(FL, AK, Lp);
  System.Move(FL[0], Lu0[0], 4 * System.SizeOf(UInt32));
  Lv0[0] := AK[0];
  Lv0[1] := AK[1];
  Lv0[2] := AK[2];
  Lv0[3] := AK[3];
  Lv1[0] := 1;
  LIterations := TargetLength * 4;
  LLast := 15;
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
      TScalarUtilities.AddShifted_UV(3, LS, Lu0, Lu1, Lv0, Lv1);
    end
    else
    begin
      TScalarUtilities.SubShifted_NP(LLast, LS, LNu, LNv, Lp, Lt);
      TScalarUtilities.SubShifted_UV(3, LS, Lu0, Lu1, Lv0, Lv1);
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
  System.Move(Lv0[0], AZ0[0], 4 * System.SizeOf(UInt32));
  System.Move(Lv1[0], AZ1[0], 4 * System.SizeOf(UInt32));
  Result := True;
end;

class procedure TScalar25519.ToSignedDigits(ABits: Int32; AZ: TCryptoLibUInt32Array);
var
  LC1, LC2: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert(ABits = 256);
  System.Assert(System.Length(AZ) >= Size);
  {$ENDIF}
  LC1 := TNat.CAddTo(Size, (not Int32(AZ[0])) and 1, FL, AZ);
  LC2 := TNat.ShiftDownBit(Size, AZ, 1);
  {$IFDEF DEBUG}
  System.Assert(LC1 = 0);
  System.Assert(LC2 = UInt32(1 shl 31));
  {$ENDIF}
end;

end.
