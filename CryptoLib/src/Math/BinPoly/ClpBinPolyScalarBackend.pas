{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpBinPolyScalarBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  ClpNat,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpIBinPolyMul;

type
  /// <summary>
  /// Scalar binary-polynomial multiply backend: the portable fallback. Dispatches to
  /// <c>TBinPolyScalarMedium</c> for sub-cutoff sizes (direct schoolbook leaf) and
  /// <c>TBinPolyScalarLarge</c> at or above the Karatsuba cutoff, and hosts the portable
  /// leaf multiply (<c>ImplMul</c>, a 16-entry-table 1x1 carryless multiply) those classes
  /// call. Kept separate from the SIMD facade: there is a single scalar implementation with
  /// its own cutoff, so no arch-dispatch is needed.
  /// </summary>
  TBinPolyScalarBackend = class sealed
  strict private
    class procedure ImplMulPostprocess(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32;
      const AU: TCryptoLibUInt64Array); static;
    class procedure ImplMulwAccTable(const AU: TCryptoLibUInt64Array; AX, AY: UInt64;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    class procedure ImplMulwAcc(const AU: TCryptoLibUInt64Array; AX, AY: UInt64;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
  public
    class function CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul; static;
    /// <summary>
    /// Portable leaf multiply: write <c>AX[AXOff..]*AY[AYOff..]</c> (carryless, arbitrary
    /// degree) into <c>AZz[AZzOff..AZzOff + 2*ALen - 1]</c>, overwriting prior contents.
    /// </summary>
    class procedure ImplMul(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32); static;
  end;

implementation

uses
  ClpBinPolyScalarMedium,
  ClpBinPolyScalarLarge;

{ TBinPolyScalarBackend }

class function TBinPolyScalarBackend.CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul;
var
  LSize: Int32;
begin
  LSize := (AN + 63) shr 6;
  if LSize < TBinPolyScalarLarge.KaratsubaCutoff then
    Result := TBinPolyScalarMedium.Create(AN, AReduce)
  else
    Result := TBinPolyScalarLarge.Create(AN, AReduce);
end;

class procedure TBinPolyScalarBackend.ImplMul(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32);
var
  LU: TCryptoLibUInt64Array;
  LI: Int32;
  LxBounds, LyBounds, LzzBounds: UInt64;
begin
  // Probe operand and output bounds early so callers get a range error at entry.
  LxBounds := AX[AXOff + ALen - 1];
  LyBounds := AY[AYOff + ALen - 1];
  LzzBounds := AZz[AZzOff + 2 * ALen - 1];

  SetLength(LU, 16);

  for LI := 0 to ALen - 1 do
    ImplMulwAccTable(LU, AX[AXOff + LI], AY[AYOff + LI], AZz, AZzOff + (LI shl 1));

  ImplMulPostprocess(ALen, AX, AXOff, AY, AYOff, AZz, AZzOff, LU);
end;

class procedure TBinPolyScalarBackend.ImplMulPostprocess(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32;
  const AU: TCryptoLibUInt64Array);
var
  LV0: UInt64;
  LV1: UInt64;
  LW: UInt64;
  LI: Int32;
  LLast: Int32;
  LZPos: Int32;
  LHi: Int32;
  LLo: Int32;
begin
  LV0 := AZz[AZzOff];
  LV1 := AZz[AZzOff + 1];
  for LI := 1 to ALen - 1 do
  begin
    LV0 := LV0 xor AZz[AZzOff + (LI shl 1)];
    AZz[AZzOff + LI] := LV0 xor LV1;
    LV1 := LV1 xor AZz[AZzOff + (LI shl 1) + 1];
  end;

  LW := LV0 xor LV1;
  TNat.Xor64(ALen, AZz, AZzOff, LW, AZz, AZzOff + ALen);

  LLast := ALen - 1;
  for LZPos := 1 to (LLast * 2) - 1 do
  begin
    LHi := Math.Min(LLast, LZPos);
    LLo := LZPos - LHi;

    while LLo < LHi do
    begin
      ImplMulwAcc(AU, AX[AXOff + LLo] xor AX[AXOff + LHi], AY[AYOff + LLo] xor AY[AYOff + LHi],
        AZz, AZzOff + LZPos);
      System.Inc(LLo);
      System.Dec(LHi);
    end;
  end;
end;

class procedure TBinPolyScalarBackend.ImplMulwAccTable(const AU: TCryptoLibUInt64Array; AX, AY: UInt64;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LH: UInt64;
  LM: UInt64;
  LN: UInt64;
  LI: Int32;
  LJ: UInt32;
  LG: UInt64;
  LL: UInt64;
  LK: Int32;
begin
  LH := 0;
  LM := AX;
  LN := AY;

  AU[1] := AY;
  LI := 2;
  while LI < 16 do
  begin
    AU[LI] := AU[LI div 2] shl 1;
    AU[LI + 1] := AU[LI] xor AY;

    LM := (LM and UInt64($FEFEFEFEFEFEFEFE)) shr 1;
    LH := LH xor (LM and UInt64(TBitOperations.Asr64(Int64(LN), 63)));
    LN := LN shl 1;
    LI := LI + 2;
  end;

  LJ := UInt32(AX);
  LL := AU[LJ and 15] xor (AU[(LJ shr 4) and 15] shl 4);
  LK := 56;
  repeat
    LJ := UInt32(AX shr LK);
    LG := AU[LJ and 15] xor (AU[(LJ shr 4) and 15] shl 4);
    LL := LL xor (LG shl LK);
    LH := LH xor TBitOperations.NegativeRightShift64(LG, -LK);
    LK := LK - 8;
  until LK <= 0;

{$IFDEF DEBUG}
  System.Assert(LH shr 63 = 0);
{$ENDIF}

  AZ[AZOff] := LL;
  AZ[AZOff + 1] := LH;
end;

class procedure TBinPolyScalarBackend.ImplMulwAcc(const AU: TCryptoLibUInt64Array; AX, AY: UInt64;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LH: UInt64;
  LM: UInt64;
  LN: UInt64;
  LI: Int32;
  LJ: UInt32;
  LG: UInt64;
  LL: UInt64;
  LK: Int32;
begin
  LH := 0;
  LM := AX;
  LN := AY;

  AU[1] := AY;
  LI := 2;
  while LI < 16 do
  begin
    AU[LI] := AU[LI div 2] shl 1;
    AU[LI + 1] := AU[LI] xor AY;

    LM := (LM and UInt64($FEFEFEFEFEFEFEFE)) shr 1;
    LH := LH xor (LM and UInt64(TBitOperations.Asr64(Int64(LN), 63)));
    LN := LN shl 1;
    LI := LI + 2;
  end;

  LJ := UInt32(AX);
  LL := AU[LJ and 15] xor (AU[(LJ shr 4) and 15] shl 4);
  LK := 56;
  repeat
    LJ := UInt32(AX shr LK);
    LG := AU[LJ and 15] xor (AU[(LJ shr 4) and 15] shl 4);
    LL := LL xor (LG shl LK);
    LH := LH xor TBitOperations.NegativeRightShift64(LG, -LK);
    LK := LK - 8;
  until LK <= 0;

{$IFDEF DEBUG}
  System.Assert(LH shr 63 = 0);
{$ENDIF}

  AZ[AZOff] := AZ[AZOff] xor LL;
  AZ[AZOff + 1] := AZ[AZOff + 1] xor LH;
end;

end.
