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

unit BinPolyTests;

{$I ..\..\..\..\CryptoLib\src\Include\CryptoLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpIBinPolyInv,
  ClpBinPolys,
  ClpNat,
  ClpIRandom,
  ClpRandom,
  ClpBinPolyScalarBackend,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpBinPolyX86Backend,
  ClpBinPolySimd,
{$ENDIF CRYPTOLIB_X86_SIMD}
  ClpBinPolyMulBaseBinomialReduce,
  CryptoLibTestBase;

type
  TBinCase = record
    CaseName: string;
    N: Int32;
  end;

  TTrinCase = record
    CaseName: string;
    N: Int32;
    K: Int32;
  end;

  TPentaCase = record
    CaseName: string;
    N: Int32;
    K1: Int32;
    K2: Int32;
    K3: Int32;
  end;

  /// <summary>
  /// Shared BinPoly test machinery (constants, RNG helpers, reference
  /// implementations, generic assert utilities). Backend-agnostic; consumed by
  /// both the public-API suite (<c>TTestBinPoly</c>) and the per-backend
  /// vs-scalar suite (<c>TBinPolyBackendTestBase</c> and its subclasses).
  /// </summary>
  TBinPolyTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    const
      BikeR1 = 12323;
      RandomTrials = 16;
      FixedSeed = $10101010;
      OffX = 3;
      OffY = 5;
      OffZ = 7;
      OffPadTail = 4;

    procedure AssertUInt64ArraysEqual(ASize: Int32;
      const AExpected, AActual: TCryptoLibUInt64Array; const AContext: string);
    procedure AssertSliceEquals(const AExpected: TCryptoLibUInt64Array;
      const AActual: TCryptoLibUInt64Array; AActualOff, ASize: Int32;
      const AContext: string);
    procedure AssertGuardZonesEqual(const ABefore, AAfter: TCryptoLibUInt64Array;
      ASliceOff, ASliceSize: Int32; const AContext: string);
    function PadBuffer(ASliceSize, ASliceOff, APadTail: Int32;
      const ARandom: IRandom): TCryptoLibUInt64Array;
    function RandomLimbs(const ARandom: IRandom; ASize: Int32)
      : TCryptoLibUInt64Array;
    function RandomReduced(const ARandom: IRandom; AN: Int32)
      : TCryptoLibUInt64Array;
    function ReferenceBitLength(ASize: Int32;
      const AX: TCryptoLibUInt64Array): Int32;
    function CarrylessMul(AN: Int32; const AX, AY: TCryptoLibUInt64Array)
      : TCryptoLibUInt64Array;
    function ReferenceBinomialMul(AR: Int32; const AX, AY: TCryptoLibUInt64Array)
      : TCryptoLibUInt64Array;
    function ReferenceTrinomialMul(AN, AK: Int32;
      const AX, AY: TCryptoLibUInt64Array): TCryptoLibUInt64Array;
    function ReferencePentanomialMul(AN, AK1, AK2, AK3: Int32;
      const AX, AY: TCryptoLibUInt64Array): TCryptoLibUInt64Array;
    procedure RunAllOpsAtOffsets(const AMul: IBinPolyMul; AN: Int32;
      const ARandom: IRandom; const ALabel: string);
    procedure RunInvertChecks(const AMul: IBinPolyMul; const AInv: IBinPolyInv;
      AN: Int32; const ARandom: IRandom; const ALabel: string);
  end;

  /// <summary>
  /// Architecture-neutral BinPoly tests: exercise the public <c>TBinPolys</c> API
  /// (binomial / trinomial / pentanomial multiply / square / invert, factory
  /// validation, bit-length). Run on every target.
  /// </summary>
  TTestBinPoly = class(TBinPolyTestBase)
  published
    procedure TestBinomial_Add_AgainstXor_BikeR1;
    procedure TestBinomial_AddTo_AgainstXor_BikeR1;
    procedure TestBinomial_Multiply_AgainstReference_BikeR1;
    procedure TestBinomial_Multiply_AgainstReference_Small;
    procedure TestBinomial_Square_AgainstReference_Even;
    procedure TestBinomial_Multiply_MultiplyByZero_BikeR1;
    procedure TestBinomial_Multiply_MultiplyByOne_BikeR1;
    procedure TestBinomial_Square_AgainstReferenceMultiplyBySelf_BikeR1;
    procedure TestBinomial_SquareN_AgainstRepeatedSquare_BikeR1;
    procedure TestBinomial_SquareN_ZeroNThrows_BikeR1;
    procedure TestBinomial_AllOps_NonZeroOffsets;
    procedure TestTrinomial_Multiply_AgainstReference;
    procedure TestTrinomial_Multiply_MultiplyByZero;
    procedure TestTrinomial_Multiply_MultiplyByOne;
    procedure TestTrinomial_Square_AgainstReferenceMultiplyBySelf;
    procedure TestTrinomial_SquareN_AgainstRepeatedSquare;
    procedure TestTrinomial_AllOps_NonZeroOffsets;
    procedure TestPentanomial_Multiply_AgainstReference;
    procedure TestPentanomial_Multiply_MultiplyByZero;
    procedure TestPentanomial_Multiply_MultiplyByOne;
    procedure TestPentanomial_Square_AgainstReferenceMultiplyBySelf;
    procedure TestPentanomial_SquareN_AgainstRepeatedSquare;
    procedure TestPentanomial_AllOps_NonZeroOffsets;
    procedure TestFactory_RejectsInvalidParameters;
    procedure TestFactory_AcceptsEvenN;
    procedure TestTrinomial_Invert_RoundTrip;
    procedure TestPentanomial_Invert_RoundTrip;
    procedure TestInv_Factory_RejectsNullAndDegenerate;
    procedure TestBitLengthVar_AgainstReference;
  end;

  /// <summary>
  /// Backend-agnostic suite that diffs a per-arch SIMD <c>IBinPolyMul</c> backend
  /// against the scalar reference. A concrete per-arch suite supplies three hooks
  /// (<c>BackendSupported</c> / <c>CreateBackendMul</c> / <c>BackendLabel</c>) and
  /// registers itself under its architecture guard; the published tests are
  /// inherited and discovered automatically. Binds to the arch-neutral
  /// <c>IBinPolyMul</c> interface, never to a concrete backend class.
  /// </summary>
  TBinPolyBackendTestBase = class abstract(TBinPolyTestBase)
  strict protected
    // ---- architecture hooks (implemented by the concrete per-arch suite) ----
    function BackendSupported: Boolean; virtual; abstract;
    function CreateBackendMul(AN: Int32; const AReduce: IBinPolyReduce)
      : IBinPolyMul; virtual; abstract;
    function BackendLabel: String; virtual; abstract;

    // ---- shared backend-vs-scalar logic ----
    procedure RunBackendVsScalar(AN: Int32; const ARandom: IRandom;
      const AContext: string);
    procedure AssertBackendMultiplyEquals(AN: Int32;
      const AX, AY: TCryptoLibUInt64Array; const AContext: string);
  published
    procedure TestBackend_Multiply_MatchesScalar;
    procedure TestBackend_SizeSweep;
    procedure TestBackend_LSize10_MidWindow;
    procedure TestBackend_SmallSizes_AllOps;
    procedure TestBackend_MultiplyByZeroAndOne;
    procedure TestBackend_EdgeVectors;
  end;

{$IFDEF CRYPTOLIB_X86_SIMD}
  /// <summary>
  /// x86 (PCLMULQDQ) instantiation of the BinPoly backend suite. Registered
  /// only when CRYPTOLIB_X86_SIMD is defined.
  /// </summary>
  TTestBinPolyX86 = class(TBinPolyBackendTestBase)
  strict protected
    function BackendSupported: Boolean; override;
    function CreateBackendMul(AN: Int32; const AReduce: IBinPolyReduce)
      : IBinPolyMul; override;
    function BackendLabel: String; override;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

implementation

const
  TrinomialCases: array [0 .. 36] of TTrinCase = (
    (CaseName: 'evenTrin_n130_k5'; N: 130; K: 5),
    (CaseName: 'evenTrin_n160_k7'; N: 160; K: 7),
    (CaseName: 'evenTrin_n200_k70'; N: 200; K: 70),
    (CaseName: 'evenTrin_n64_k5'; N: 64; K: 5),
    (CaseName: 'evenTrin_n128_k64'; N: 128; K: 64),
    (CaseName: 'evenTrin_n128_k7'; N: 128; K: 7),
    (CaseName: 'evenTrin_n192_k65'; N: 192; K: 65),
    (CaseName: 'evenTrin_n256_k9'; N: 256; K: 9),
    (CaseName: 'evenTrin_n256_k127'; N: 256; K: 127),
    (CaseName: 'sect113'; N: 113; K: 9),
    (CaseName: 'sect193'; N: 193; K: 15),
    (CaseName: 'sect233'; N: 233; K: 74),
    (CaseName: 'sect239'; N: 239; K: 158),
    (CaseName: 'sect409'; N: 409; K: 87),
    (CaseName: 'trinA_n257_k1'; N: 257; K: 1),
    (CaseName: 'trinA_n383_k29'; N: 383; K: 29),
    (CaseName: 'trinA_n767_k7'; N: 767; K: 7),
    (CaseName: 'trinA3_n65_k1'; N: 65; K: 1),
    (CaseName: 'trinA3_n95_k1'; N: 95; K: 1),
    (CaseName: 'trinA5_n129_k1'; N: 129; K: 1),
    (CaseName: 'trinA5_n159_k1'; N: 159; K: 1),
    (CaseName: 'trinA6_n161_k1'; N: 161; K: 1),
    (CaseName: 'trinA6_n191_k5'; N: 191; K: 5),
    (CaseName: 'trinA8_n225_k1'; N: 225; K: 1),
    (CaseName: 'trinA8_n255_k5'; N: 255; K: 5),
    (CaseName: 'trinB_n129_k64'; N: 129; K: 64),
    (CaseName: 'trinB_n257_k128'; N: 257; K: 128),
    (CaseName: 'trinB_n513_k128'; N: 513; K: 128),
    (CaseName: 'trinC5_n129_k65'; N: 129; K: 65),
    (CaseName: 'trinC5_n159_k95'; N: 159; K: 95),
    (CaseName: 'trinC6_n161_k65'; N: 161; K: 65),
    (CaseName: 'trinC6_n191_k127'; N: 191; K: 127),
    (CaseName: 'trinC7_n193_k65'; N: 193; K: 65),
    (CaseName: 'trinC7_n223_k159'; N: 223; K: 159),
    (CaseName: 'trinD_n65_k2'; N: 65; K: 2),
    (CaseName: 'trinD_n127_k70'; N: 127; K: 70),
    (CaseName: 'trinD_n193_k140'; N: 193; K: 140));

  PentanomialCases: array [0 .. 30] of TPentaCase = (
    (CaseName: 'penta64_n64_k1_2_3'; N: 64; K1: 1; K2: 2; K3: 3),
    (CaseName: 'penta64_n128_k2_5_7'; N: 128; K1: 2; K2: 5; K3: 7),
    (CaseName: 'penta64_n256_k5_7_12'; N: 256; K1: 5; K2: 7; K3: 12),
    (CaseName: 'penta64_n256_k1_65_130'; N: 256; K1: 1; K2: 65; K3: 130),
    (CaseName: 'penta64_n256_k1_64_130'; N: 256; K1: 1; K2: 64; K3: 130),
    (CaseName: 'sect131'; N: 131; K1: 2; K2: 3; K3: 8),
    (CaseName: 'sect163'; N: 163; K1: 3; K2: 6; K3: 7),
    (CaseName: 'sect283'; N: 283; K1: 5; K2: 7; K3: 12),
    (CaseName: 'sect571'; N: 571; K1: 2; K2: 5; K3: 10),
    (CaseName: 'pentaA3_n67_k1_2_3'; N: 67; K1: 1; K2: 2; K3: 3),
    (CaseName: 'pentaA3_n95_k15_25_31'; N: 95; K1: 15; K2: 25; K3: 31),
    (CaseName: 'pentaA4_n97_k1_2_3'; N: 97; K1: 1; K2: 2; K3: 3),
    (CaseName: 'pentaA4_n127_k5_20_63'; N: 127; K1: 5; K2: 20; K3: 63),
    (CaseName: 'pentaA7_n193_k1_2_3'; N: 193; K1: 1; K2: 2; K3: 3),
    (CaseName: 'pentaA7_n223_k30_50_63'; N: 223; K1: 30; K2: 50; K3: 63),
    (CaseName: 'pentaA8_n225_k1_2_3'; N: 225; K1: 1; K2: 2; K3: 3),
    (CaseName: 'pentaA8_n255_k5_20_63'; N: 255; K1: 5; K2: 20; K3: 63),
    (CaseName: 'pentaB_n193_k1_65_67'; N: 193; K1: 1; K2: 65; K3: 67),
    (CaseName: 'pentaB_n513_k10_70_200'; N: 513; K1: 10; K2: 70; K3: 200),
    (CaseName: 'pentaB_n513_k63_70_300'; N: 513; K1: 63; K2: 70; K3: 300),
    (CaseName: 'pentaC_n129_k1_2_66'; N: 129; K1: 1; K2: 2; K3: 66),
    (CaseName: 'pentaC_n193_k1_2_64'; N: 193; K1: 1; K2: 2; K3: 64),
    (CaseName: 'pentaC_n257_k64_65_130'; N: 257; K1: 64; K2: 65; K3: 130),
    (CaseName: 'pentaD_n129_k1_2_65'; N: 129; K1: 1; K2: 2; K3: 65),
    (CaseName: 'pentaD_n257_k3_33_130'; N: 257; K1: 3; K2: 33; K3: 130),
    (CaseName: 'pentaD_n513_k10_63_200'; N: 513; K1: 10; K2: 63; K3: 200),
    (CaseName: 'c2pnb176w1'; N: 176; K1: 1; K2: 2; K3: 43),
    (CaseName: 'c2pnb208w1'; N: 208; K1: 1; K2: 2; K3: 83),
    (CaseName: 'c2pnb272w1'; N: 272; K1: 1; K2: 3; K3: 56),
    (CaseName: 'c2pnb304w1'; N: 304; K1: 1; K2: 2; K3: 11),
    (CaseName: 'c2pnb368w1'; N: 368; K1: 1; K2: 2; K3: 85));

  SectTrinomialCases: array [0 .. 4] of TTrinCase = (
    (CaseName: 'sect113'; N: 113; K: 9),
    (CaseName: 'sect193'; N: 193; K: 15),
    (CaseName: 'sect233'; N: 233; K: 74),
    (CaseName: 'sect239'; N: 239; K: 158),
    (CaseName: 'sect409'; N: 409; K: 87));

  SectPentanomialCases: array [0 .. 3] of TPentaCase = (
    (CaseName: 'sect131'; N: 131; K1: 2; K2: 3; K3: 8),
    (CaseName: 'sect163'; N: 163; K1: 3; K2: 6; K3: 7),
    (CaseName: 'sect283'; N: 283; K1: 5; K2: 7; K3: 12),
    (CaseName: 'sect571'; N: 571; K1: 2; K2: 5; K3: 10));

  X962EvenPentanomialCases: array [0 .. 4] of TPentaCase = (
    (CaseName: 'c2pnb176w1'; N: 176; K1: 1; K2: 2; K3: 43),
    (CaseName: 'c2pnb208w1'; N: 208; K1: 1; K2: 2; K3: 83),
    (CaseName: 'c2pnb272w1'; N: 272; K1: 1; K2: 3; K3: 56),
    (CaseName: 'c2pnb304w1'; N: 304; K1: 1; K2: 2; K3: 11),
    (CaseName: 'c2pnb368w1'; N: 368; K1: 1; K2: 2; K3: 85));

{ TTestBinPoly }

procedure TBinPolyTestBase.AssertUInt64ArraysEqual(ASize: Int32;
  const AExpected, AActual: TCryptoLibUInt64Array; const AContext: string);
begin
  Check(TBinPolys.EqualTo(ASize, AExpected, 0, AActual, 0) <> 0, AContext);
end;

procedure TBinPolyTestBase.AssertSliceEquals(const AExpected: TCryptoLibUInt64Array;
  const AActual: TCryptoLibUInt64Array; AActualOff, ASize: Int32;
  const AContext: string);
var
  LI: Int32;
begin
  for LI := 0 to ASize - 1 do
    CheckEquals(AExpected[LI], AActual[AActualOff + LI], AContext + ' limb ' + IntToStr(LI));
end;

procedure TBinPolyTestBase.AssertGuardZonesEqual(const ABefore, AAfter: TCryptoLibUInt64Array;
  ASliceOff, ASliceSize: Int32; const AContext: string);
var
  LI: Int32;
begin
  for LI := 0 to ASliceOff - 1 do
    CheckEquals(ABefore[LI], AAfter[LI], AContext + ' head guard at ' + IntToStr(LI));
  for LI := ASliceOff + ASliceSize to System.Length(AAfter) - 1 do
    CheckEquals(ABefore[LI], AAfter[LI], AContext + ' tail guard at ' + IntToStr(LI));
end;

function TBinPolyTestBase.PadBuffer(ASliceSize, ASliceOff, APadTail: Int32;
  const ARandom: IRandom): TCryptoLibUInt64Array;
var
  LTotal, LI, LJ: Int32;
  LBytes: TBytes;
  LW: UInt64;
begin
  LTotal := ASliceOff + ASliceSize + APadTail;
  System.SetLength(Result, LTotal);
  System.SetLength(LBytes, LTotal shl 3);
  ARandom.NextBytes(LBytes);
  for LI := 0 to LTotal - 1 do
  begin
    LW := 0;
    for LJ := 0 to 7 do
      LW := LW or (UInt64(LBytes[(LI shl 3) + LJ]) shl (LJ shl 3));
    Result[LI] := LW;
  end;
end;

function TBinPolyTestBase.RandomLimbs(const ARandom: IRandom; ASize: Int32)
  : TCryptoLibUInt64Array;
var
  LI, LJ: Int32;
  LBytes: TBytes;
  LW: UInt64;
begin
  System.SetLength(Result, ASize);
  System.SetLength(LBytes, ASize shl 3);
  ARandom.NextBytes(LBytes);
  for LI := 0 to ASize - 1 do
  begin
    LW := 0;
    for LJ := 0 to 7 do
      LW := LW or (UInt64(LBytes[(LI shl 3) + LJ]) shl (LJ shl 3));
    Result[LI] := LW;
  end;
end;

function TBinPolyTestBase.RandomReduced(const ARandom: IRandom; AN: Int32)
  : TCryptoLibUInt64Array;
var
  LSize, LPartial, LI, LJ: Int32;
  LBytes: TBytes;
  LW: UInt64;
begin
  LSize := (AN + 63) shr 6;
  System.SetLength(Result, LSize);
  System.SetLength(LBytes, LSize shl 3);
  ARandom.NextBytes(LBytes);
  for LI := 0 to LSize - 1 do
  begin
    LW := 0;
    for LJ := 0 to 7 do
      LW := LW or (UInt64(LBytes[(LI shl 3) + LJ]) shl (LJ shl 3));
    Result[LI] := LW;
  end;
  LPartial := AN and 63;
  if LPartial <> 0 then
    Result[LSize - 1] := Result[LSize - 1] and ((UInt64(1) shl LPartial) - 1);
end;

function TBinPolyTestBase.ReferenceBitLength(ASize: Int32;
  const AX: TCryptoLibUInt64Array): Int32;
var
  LBit: Int32;
begin
  for LBit := (ASize shl 6) - 1 downto 0 do
    if ((AX[LBit shr 6] shr (LBit and 63)) and 1) <> 0 then
      Exit(LBit + 1);
  Result := 0;
end;

function TBinPolyTestBase.CarrylessMul(AN: Int32; const AX, AY: TCryptoLibUInt64Array)
  : TCryptoLibUInt64Array;
var
  LSize, LI, LWOff, LBOff, LJ: Int32;
  LYj: UInt64;
begin
  LSize := (AN + 63) shr 6;
  System.SetLength(Result, 2 * LSize);
  TBinPolys.Zero(2 * LSize, Result, 0);
  for LI := 0 to AN - 1 do
  begin
    if ((AX[LI shr 6] shr (LI and 63)) and 1) = 0 then
      Continue;
    LWOff := LI shr 6;
    LBOff := LI and 63;
    if LBOff = 0 then
    begin
      for LJ := 0 to LSize - 1 do
        Result[LWOff + LJ] := Result[LWOff + LJ] xor AY[LJ];
    end
    else
    begin
      for LJ := 0 to LSize - 1 do
      begin
        LYj := AY[LJ];
        Result[LWOff + LJ] := Result[LWOff + LJ] xor (LYj shl LBOff);
        Result[LWOff + LJ + 1] := Result[LWOff + LJ + 1] xor (LYj shr (64 - LBOff));
      end;
    end;
  end;
end;

function TBinPolyTestBase.ReferenceBinomialMul(AR: Int32;
  const AX, AY: TCryptoLibUInt64Array): TCryptoLibUInt64Array;
var
  LSize, LP, LQ, LPartial: Int32;
  LPartialMask: UInt64;
  LZz: TCryptoLibUInt64Array;
begin
  LSize := (AR + 63) shr 6;
  LZz := CarrylessMul(AR, AX, AY);
  System.SetLength(Result, LSize);
  TNat.Copy64(LSize, LZz, 0, Result, 0);
  for LP := AR to 2 * AR - 2 do
  begin
    if ((LZz[LP shr 6] shr (LP and 63)) and 1) = 0 then
      Continue;
    LQ := LP - AR;
    Result[LQ shr 6] := Result[LQ shr 6] xor (UInt64(1) shl (LQ and 63));
  end;
  LPartial := AR and 63;
  if LPartial = 0 then
    LPartialMask := High(UInt64)
  else
    LPartialMask := (UInt64(1) shl LPartial) - 1;
  Result[LSize - 1] := Result[LSize - 1] and LPartialMask;
end;

function TBinPolyTestBase.ReferenceTrinomialMul(AN, AK: Int32;
  const AX, AY: TCryptoLibUInt64Array): TCryptoLibUInt64Array;
var
  LSize, LP, LQ0, LQ1, LPartial: Int32;
  LPartialMask: UInt64;
  LZz: TCryptoLibUInt64Array;
begin
  LSize := (AN + 63) shr 6;
  LZz := CarrylessMul(AN, AX, AY);
  for LP := 2 * AN - 2 downto AN do
  begin
    if ((LZz[LP shr 6] shr (LP and 63)) and 1) = 0 then
      Continue;
    LQ0 := LP - AN;
    LQ1 := LP - AN + AK;
    LZz[LQ0 shr 6] := LZz[LQ0 shr 6] xor (UInt64(1) shl (LQ0 and 63));
    LZz[LQ1 shr 6] := LZz[LQ1 shr 6] xor (UInt64(1) shl (LQ1 and 63));
  end;
  System.SetLength(Result, LSize);
  TNat.Copy64(LSize, LZz, 0, Result, 0);
  LPartial := AN and 63;
  if LPartial = 0 then
    LPartialMask := High(UInt64)
  else
    LPartialMask := (UInt64(1) shl LPartial) - 1;
  Result[LSize - 1] := Result[LSize - 1] and LPartialMask;
end;

function TBinPolyTestBase.ReferencePentanomialMul(AN, AK1, AK2, AK3: Int32;
  const AX, AY: TCryptoLibUInt64Array): TCryptoLibUInt64Array;
var
  LSize, LP, LQ0, LQ1, LQ2, LQ3, LPartial: Int32;
  LPartialMask: UInt64;
  LZz: TCryptoLibUInt64Array;
begin
  LSize := (AN + 63) shr 6;
  LZz := CarrylessMul(AN, AX, AY);
  for LP := 2 * AN - 2 downto AN do
  begin
    if ((LZz[LP shr 6] shr (LP and 63)) and 1) = 0 then
      Continue;
    LQ0 := LP - AN;
    LQ1 := LP - AN + AK1;
    LQ2 := LP - AN + AK2;
    LQ3 := LP - AN + AK3;
    LZz[LQ0 shr 6] := LZz[LQ0 shr 6] xor (UInt64(1) shl (LQ0 and 63));
    LZz[LQ1 shr 6] := LZz[LQ1 shr 6] xor (UInt64(1) shl (LQ1 and 63));
    LZz[LQ2 shr 6] := LZz[LQ2 shr 6] xor (UInt64(1) shl (LQ2 and 63));
    LZz[LQ3 shr 6] := LZz[LQ3 shr 6] xor (UInt64(1) shl (LQ3 and 63));
  end;
  System.SetLength(Result, LSize);
  TNat.Copy64(LSize, LZz, 0, Result, 0);
  LPartial := AN and 63;
  if LPartial = 0 then
    LPartialMask := High(UInt64)
  else
    LPartialMask := (UInt64(1) shl LPartial) - 1;
  Result[LSize - 1] := Result[LSize - 1] and LPartialMask;
end;

procedure TBinPolyTestBase.RunAllOpsAtOffsets(const AMul: IBinPolyMul; AN: Int32;
  const ARandom: IRandom; const ALabel: string);
var
  LSize: Int32;
  LX, LY, LZRef, LXBuf, LYBuf, LZBuf, LXBufBefore, LYBufBefore, LZBufBefore: TCryptoLibUInt64Array;
  LZInit: TCryptoLibUInt64Array;
  LSn: Int32;
begin
  LSize := AMul.Size;

  LX := RandomReduced(ARandom, AN);
  LY := RandomReduced(ARandom, AN);
  LZRef := TBinPolys.Create(LSize);
  AMul.Multiply(LX, 0, LY, 0, LZRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LYBuf := PadBuffer(LSize, OffY, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  TNat.Copy64(LSize, LY, 0, LYBuf, OffY);
  LXBufBefore := System.Copy(LXBuf);
  LYBufBefore := System.Copy(LYBuf);
  LZBufBefore := System.Copy(LZBuf);
  AMul.Multiply(LXBuf, OffX, LYBuf, OffY, LZBuf, OffZ);
  AssertSliceEquals(LZRef, LZBuf, OffZ, LSize, ALabel + ' Multiply');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBufBefore, LXBuf, ALabel + ' Multiply xBuf clobbered');
  AssertUInt64ArraysEqual(System.Length(LYBuf), LYBufBefore, LYBuf, ALabel + ' Multiply yBuf clobbered');
  AssertGuardZonesEqual(LZBufBefore, LZBuf, OffZ, LSize, ALabel + ' Multiply zBuf');

  LX := RandomReduced(ARandom, AN);
  LZRef := TBinPolys.Create(LSize);
  AMul.Square(LX, 0, LZRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  LXBufBefore := System.Copy(LXBuf);
  LZBufBefore := System.Copy(LZBuf);
  AMul.Square(LXBuf, OffX, LZBuf, OffZ);
  AssertSliceEquals(LZRef, LZBuf, OffZ, LSize, ALabel + ' Square');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBufBefore, LXBuf, ALabel + ' Square xBuf clobbered');
  AssertGuardZonesEqual(LZBufBefore, LZBuf, OffZ, LSize, ALabel + ' Square zBuf');

  LSn := 7;
  LX := RandomReduced(ARandom, AN);
  LZRef := TBinPolys.Create(LSize);
  AMul.SquareN(LX, 0, LSn, LZRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  LXBufBefore := System.Copy(LXBuf);
  LZBufBefore := System.Copy(LZBuf);
  AMul.SquareN(LXBuf, OffX, LSn, LZBuf, OffZ);
  AssertSliceEquals(LZRef, LZBuf, OffZ, LSize, ALabel + ' SquareN');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBufBefore, LXBuf, ALabel + ' SquareN xBuf clobbered');
  AssertGuardZonesEqual(LZBufBefore, LZBuf, OffZ, LSize, ALabel + ' SquareN zBuf');

  LX := RandomReduced(ARandom, AN);
  LY := RandomReduced(ARandom, AN);
  LZRef := TBinPolys.Create(LSize);
  TBinPolys.Add(LSize, LX, 0, LY, 0, LZRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LYBuf := PadBuffer(LSize, OffY, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  TNat.Copy64(LSize, LY, 0, LYBuf, OffY);
  LXBufBefore := System.Copy(LXBuf);
  LYBufBefore := System.Copy(LYBuf);
  LZBufBefore := System.Copy(LZBuf);
  TBinPolys.Add(LSize, LXBuf, OffX, LYBuf, OffY, LZBuf, OffZ);
  AssertSliceEquals(LZRef, LZBuf, OffZ, LSize, ALabel + ' Add');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBufBefore, LXBuf, ALabel + ' Add xBuf clobbered');
  AssertUInt64ArraysEqual(System.Length(LYBuf), LYBufBefore, LYBuf, ALabel + ' Add yBuf clobbered');
  AssertGuardZonesEqual(LZBufBefore, LZBuf, OffZ, LSize, ALabel + ' Add zBuf');

  LX := RandomReduced(ARandom, AN);
  LZInit := RandomReduced(ARandom, AN);
  LZRef := System.Copy(LZInit);
  TBinPolys.AddTo(LSize, LX, 0, LZRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  TNat.Copy64(LSize, LZInit, 0, LZBuf, OffZ);
  LXBufBefore := System.Copy(LXBuf);
  LZBufBefore := System.Copy(LZBuf);
  TBinPolys.AddTo(LSize, LXBuf, OffX, LZBuf, OffZ);
  AssertSliceEquals(LZRef, LZBuf, OffZ, LSize, ALabel + ' AddTo');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBufBefore, LXBuf, ALabel + ' AddTo xBuf clobbered');
  AssertGuardZonesEqual(LZBufBefore, LZBuf, OffZ, LSize, ALabel + ' AddTo zBuf');
end;

procedure TBinPolyTestBase.RunInvertChecks(const AMul: IBinPolyMul; const AInv: IBinPolyInv;
  AN: Int32; const ARandom: IRandom; const ALabel: string);
var
  LSize, LT: Int32;
  LOne, LZero, LZInv, LA, LAInv, LProd, LAInvInv, LB, LExpected: TCryptoLibUInt64Array;
begin
  LSize := AMul.Size;
  LOne := TBinPolys.Create(LSize);
  LOne[0] := 1;
  LZero := TBinPolys.Create(LSize);
  LZInv := TBinPolys.Create(LSize);
  AInv.Invert(LZero, 0, LZInv, 0);
  AssertUInt64ArraysEqual(LSize, LZero, LZInv, ALabel + ' Invert(0)');
  AInv.Invert(LOne, 0, LZInv, 0);
  AssertUInt64ArraysEqual(LSize, LOne, LZInv, ALabel + ' Invert(1)');

  for LT := 0 to RandomTrials - 1 do
  begin
    LA := RandomReduced(ARandom, AN);
    if TBinPolys.EqualTo(LSize, LA, 0, LZero, 0) <> 0 then
      Continue;
    LAInv := TBinPolys.Create(LSize);
    AInv.Invert(LA, 0, LAInv, 0);
    LProd := TBinPolys.Create(LSize);
    AMul.Multiply(LA, 0, LAInv, 0, LProd, 0);
    AssertUInt64ArraysEqual(LSize, LOne, LProd, ALabel + ' a * inv(a) trial ' + IntToStr(LT));
    LAInvInv := TBinPolys.Create(LSize);
    AInv.Invert(LAInv, 0, LAInvInv, 0);
    AssertUInt64ArraysEqual(LSize, LA, LAInvInv, ALabel + ' inv(inv(a)) trial ' + IntToStr(LT));
  end;

  LB := RandomReduced(ARandom, AN);
  if TBinPolys.EqualTo(LSize, LB, 0, LZero, 0) = 0 then
  begin
    LExpected := TBinPolys.Create(LSize);
    AInv.Invert(LB, 0, LExpected, 0);
    AInv.Invert(LB, 0, LB, 0);
    AssertUInt64ArraysEqual(LSize, LExpected, LB, ALabel + ' in-place invert');
  end;
end;

procedure TTestBinPoly.TestBinomial_Add_AgainstXor_BikeR1;
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LT, LI: Int32;
  LX, LY, LZ: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed);
  try
    for LT := 0 to RandomTrials - 1 do
    begin
      LX := RandomReduced(LRandom, BikeR1);
      LY := RandomReduced(LRandom, BikeR1);
      LZ := TBinPolys.Create(LBinomial.Size);
      TBinPolys.Add(LBinomial.Size, LX, 0, LY, 0, LZ, 0);
      for LI := 0 to LBinomial.Size - 1 do
        CheckEquals(LX[LI] xor LY[LI], LZ[LI], 'Add at limb ' + IntToStr(LI));
    end;
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_AddTo_AgainstXor_BikeR1;
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LT, LI: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed + 1);
  try
    for LT := 0 to RandomTrials - 1 do
    begin
      LX := RandomReduced(LRandom, BikeR1);
      LZ := RandomReduced(LRandom, BikeR1);
      LExpected := System.Copy(LZ);
      for LI := 0 to LBinomial.Size - 1 do
        LExpected[LI] := LX[LI] xor LZ[LI];
      TBinPolys.AddTo(LBinomial.Size, LX, 0, LZ, 0);
      AssertUInt64ArraysEqual(LBinomial.Size, LExpected, LZ, 'trial ' + IntToStr(LT));
    end;
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_Multiply_AgainstReference_BikeR1;
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LT: Int32;
  LX, LY, LZ, LExpected: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed + 2);
  try
    for LT := 0 to RandomTrials - 1 do
    begin
      LX := RandomReduced(LRandom, BikeR1);
      LY := RandomReduced(LRandom, BikeR1);
      LZ := TBinPolys.Create(LBinomial.Size);
      LBinomial.Multiply(LX, 0, LY, 0, LZ, 0);
      LExpected := ReferenceBinomialMul(BikeR1, LX, LY);
      AssertUInt64ArraysEqual(LBinomial.Size, LExpected, LZ, 'trial ' + IntToStr(LT));
    end;
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_Multiply_AgainstReference_Small;
const
  SmallBinomials: array [0 .. 17] of TBinCase = (
    (CaseName: 'evenBin_n_66'; N: 66),
    (CaseName: 'evenBin_n_96'; N: 96),
    (CaseName: 'evenBin_n130'; N: 130),
    (CaseName: 'evenBin_n160'; N: 160),
    (CaseName: 'evenBin_n_64'; N: 64),
    (CaseName: 'evenBin_n128'; N: 128),
    (CaseName: 'evenBin_n256'; N: 256),
    (CaseName: 'evenBin_n512'; N: 512),
    (CaseName: 'small_n_63'; N: 63),
    (CaseName: 'small_n127'; N: 127),
    (CaseName: 'small_n191'; N: 191),
    (CaseName: 'small_n255'; N: 255),
    (CaseName: 'small_n319'; N: 319),
    (CaseName: 'small_n383'; N: 383),
    (CaseName: 'small_n447'; N: 447),
    (CaseName: 'small_n511'; N: 511),
    (CaseName: 'small_n575'; N: 575),
    (CaseName: 'small_n639'; N: 639));
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LT: Int32;
  LX, LY, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(SmallBinomials) to High(SmallBinomials) do
  begin
    LBinomial := TBinPolys.TBinPolysMul.Binomial(SmallBinomials[LC].N);
    LRandom := TRandom.Create(FixedSeed + SmallBinomials[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
      begin
        LX := RandomReduced(LRandom, SmallBinomials[LC].N);
        LY := RandomReduced(LRandom, SmallBinomials[LC].N);
        LZ := TBinPolys.Create(LBinomial.Size);
        LBinomial.Multiply(LX, 0, LY, 0, LZ, 0);
        LExpected := ReferenceBinomialMul(SmallBinomials[LC].N, LX, LY);
        AssertUInt64ArraysEqual(LBinomial.Size, LExpected, LZ,
          SmallBinomials[LC].CaseName + ' trial ' + IntToStr(LT));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestBinomial_Square_AgainstReference_Even;
const
  EvenBinomials: array [0 .. 7] of TBinCase = (
    (CaseName: 'evenBin_n_66'; N: 66),
    (CaseName: 'evenBin_n_96'; N: 96),
    (CaseName: 'evenBin_n130'; N: 130),
    (CaseName: 'evenBin_n160'; N: 160),
    (CaseName: 'evenBin_n_64'; N: 64),
    (CaseName: 'evenBin_n128'; N: 128),
    (CaseName: 'evenBin_n256'; N: 256),
    (CaseName: 'evenBin_n512'; N: 512));
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LT: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(EvenBinomials) to High(EvenBinomials) do
  begin
    LBinomial := TBinPolys.TBinPolysMul.Binomial(EvenBinomials[LC].N);
    LRandom := TRandom.Create(FixedSeed + EvenBinomials[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
      begin
        LX := RandomReduced(LRandom, EvenBinomials[LC].N);
        LZ := TBinPolys.Create(LBinomial.Size);
        LBinomial.Square(LX, 0, LZ, 0);
        LExpected := ReferenceBinomialMul(EvenBinomials[LC].N, LX, LX);
        AssertUInt64ArraysEqual(LBinomial.Size, LExpected, LZ,
          EvenBinomials[LC].CaseName + ' trial ' + IntToStr(LT));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestBinomial_Multiply_MultiplyByZero_BikeR1;
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LX, LZero, LZ: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed + 3);
  try
    LX := RandomReduced(LRandom, BikeR1);
    LZero := TBinPolys.Create(LBinomial.Size);
    LZ := TBinPolys.Create(LBinomial.Size);
    LBinomial.Multiply(LX, 0, LZero, 0, LZ, 0);
    AssertUInt64ArraysEqual(LBinomial.Size, LZero, LZ, 'multiply by zero');
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_Multiply_MultiplyByOne_BikeR1;
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LX, LOne, LZ: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed + 4);
  try
    LX := RandomReduced(LRandom, BikeR1);
    LOne := TBinPolys.Create(LBinomial.Size);
    LOne[0] := 1;
    LZ := TBinPolys.Create(LBinomial.Size);
    LBinomial.Multiply(LX, 0, LOne, 0, LZ, 0);
    AssertUInt64ArraysEqual(LBinomial.Size, LX, LZ, 'multiply by one');
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_Square_AgainstReferenceMultiplyBySelf_BikeR1;
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LT: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed + 5);
  try
    for LT := 0 to RandomTrials - 1 do
    begin
      LX := RandomReduced(LRandom, BikeR1);
      LZ := TBinPolys.Create(LBinomial.Size);
      LBinomial.Square(LX, 0, LZ, 0);
      LExpected := ReferenceBinomialMul(BikeR1, LX, LX);
      AssertUInt64ArraysEqual(LBinomial.Size, LExpected, LZ, 'trial ' + IntToStr(LT));
    end;
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_SquareN_AgainstRepeatedSquare_BikeR1;
const
  SquareNs: array [0 .. 4] of Int32 = (1, 2, 3, 7, 16);
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LI, LN: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LRandom := TRandom.Create(FixedSeed + 6);
  try
    for LN := Low(SquareNs) to High(SquareNs) do
    begin
      LX := RandomReduced(LRandom, BikeR1);
      LZ := TBinPolys.Create(LBinomial.Size);
      LBinomial.SquareN(LX, 0, SquareNs[LN], LZ, 0);
      LExpected := TBinPolys.Create(LBinomial.Size);
      LBinomial.Square(LX, 0, LExpected, 0);
      for LI := 1 to SquareNs[LN] - 1 do
        LBinomial.Square(LExpected, 0, LExpected, 0);
      AssertUInt64ArraysEqual(LBinomial.Size, LExpected, LZ, 'n = ' + IntToStr(SquareNs[LN]));
    end;
  finally
    LRandom := nil;
  end;
end;

procedure TTestBinPoly.TestBinomial_SquareN_ZeroNThrows_BikeR1;
var
  LBinomial: IBinPolyMul;
  LX, LZ: TCryptoLibUInt64Array;
begin
  LBinomial := TBinPolys.TBinPolysMul.Binomial(BikeR1);
  LX := TBinPolys.Create(LBinomial.Size);
  LZ := TBinPolys.Create(LBinomial.Size);
  try
    LBinomial.SquareN(LX, 0, 0, LZ, 0);
    Fail('expected exception: SquareN n=0');
  except
    on E: Exception do
      Check(True, 'SquareN n=0');
  end;
  try
    LBinomial.SquareN(LX, 0, -1, LZ, 0);
    Fail('expected exception: SquareN n=-1');
  except
    on E: Exception do
      Check(True, 'SquareN n=-1');
  end;
end;

procedure TTestBinPoly.TestBinomial_AllOps_NonZeroOffsets;
const
  BinomialOffsetCases: array [0 .. 38] of TBinCase = (
    (CaseName: 'evenBin_n_66'; N: 66),
    (CaseName: 'evenBin_n_96'; N: 96),
    (CaseName: 'evenBin_n130'; N: 130),
    (CaseName: 'evenBin_n160'; N: 160),
    (CaseName: 'evenBin_n_64'; N: 64),
    (CaseName: 'evenBin_n128'; N: 128),
    (CaseName: 'evenBin_n256'; N: 256),
    (CaseName: 'evenBin_n512'; N: 512),
    (CaseName: 'med_n_703'; N: 703),
    (CaseName: 'med_n_767'; N: 767),
    (CaseName: 'med_n_831'; N: 831),
    (CaseName: 'med_n_895'; N: 895),
    (CaseName: 'med_n_959'; N: 959),
    (CaseName: 'med_n1023'; N: 1023),
    (CaseName: 'med_n1087'; N: 1087),
    (CaseName: 'med_n1151'; N: 1151),
    (CaseName: 'med_n1215'; N: 1215),
    (CaseName: 'med_n1279'; N: 1279),
    (CaseName: 'med_n1343'; N: 1343),
    (CaseName: 'med_n1407'; N: 1407),
    (CaseName: 'med_n1471'; N: 1471),
    (CaseName: 'med_n1535'; N: 1535),
    (CaseName: 'med_n1599'; N: 1599),
    (CaseName: 'med_n1663'; N: 1663),
    (CaseName: 'med_n1727'; N: 1727),
    (CaseName: 'med_n1791'; N: 1791),
    (CaseName: 'med_n1855'; N: 1855),
    (CaseName: 'med_n1919'; N: 1919),
    (CaseName: 'med_n1983'; N: 1983),
    (CaseName: 'small_n_63'; N: 63),
    (CaseName: 'small_n127'; N: 127),
    (CaseName: 'small_n191'; N: 191),
    (CaseName: 'small_n255'; N: 255),
    (CaseName: 'small_n319'; N: 319),
    (CaseName: 'small_n383'; N: 383),
    (CaseName: 'small_n447'; N: 447),
    (CaseName: 'small_n511'; N: 511),
    (CaseName: 'small_n575'; N: 575),
    (CaseName: 'small_n639'; N: 639));
var
  LBinomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
begin
  for LC := Low(BinomialOffsetCases) to High(BinomialOffsetCases) do
  begin
    LBinomial := TBinPolys.TBinPolysMul.Binomial(BinomialOffsetCases[LC].N);
    LRandom := TRandom.Create(FixedSeed + 1100 + BinomialOffsetCases[LC].N);
    try
      RunAllOpsAtOffsets(LBinomial, BinomialOffsetCases[LC].N, LRandom,
        BinomialOffsetCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestTrinomial_Multiply_AgainstReference;
var
  LTrinomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LT: Int32;
  LX, LY, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(TrinomialCases) to High(TrinomialCases) do
  begin
    LTrinomial := TBinPolys.TBinPolysMul.Trinomial(TrinomialCases[LC].N, TrinomialCases[LC].K);
    LRandom := TRandom.Create(FixedSeed + 100 + TrinomialCases[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
      begin
        LX := RandomReduced(LRandom, TrinomialCases[LC].N);
        LY := RandomReduced(LRandom, TrinomialCases[LC].N);
        LZ := TBinPolys.Create(LTrinomial.Size);
        LTrinomial.Multiply(LX, 0, LY, 0, LZ, 0);
        LExpected := ReferenceTrinomialMul(TrinomialCases[LC].N, TrinomialCases[LC].K, LX, LY);
        AssertUInt64ArraysEqual(LTrinomial.Size, LExpected, LZ,
          TrinomialCases[LC].CaseName + ' trial ' + IntToStr(LT));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestTrinomial_Multiply_MultiplyByZero;
var
  LTrinomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
  LX, LZero, LZ: TCryptoLibUInt64Array;
begin
  for LC := Low(TrinomialCases) to High(TrinomialCases) do
  begin
    LTrinomial := TBinPolys.TBinPolysMul.Trinomial(TrinomialCases[LC].N, TrinomialCases[LC].K);
    LRandom := TRandom.Create(FixedSeed + 200 + TrinomialCases[LC].N);
    try
      LX := RandomReduced(LRandom, TrinomialCases[LC].N);
      LZero := TBinPolys.Create(LTrinomial.Size);
      LZ := TBinPolys.Create(LTrinomial.Size);
      LTrinomial.Multiply(LX, 0, LZero, 0, LZ, 0);
      AssertUInt64ArraysEqual(LTrinomial.Size, LZero, LZ, TrinomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestTrinomial_Multiply_MultiplyByOne;
var
  LTrinomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
  LX, LOne, LZ: TCryptoLibUInt64Array;
begin
  for LC := Low(TrinomialCases) to High(TrinomialCases) do
  begin
    LTrinomial := TBinPolys.TBinPolysMul.Trinomial(TrinomialCases[LC].N, TrinomialCases[LC].K);
    LRandom := TRandom.Create(FixedSeed + 300 + TrinomialCases[LC].N);
    try
      LX := RandomReduced(LRandom, TrinomialCases[LC].N);
      LOne := TBinPolys.Create(LTrinomial.Size);
      LOne[0] := 1;
      LZ := TBinPolys.Create(LTrinomial.Size);
      LTrinomial.Multiply(LX, 0, LOne, 0, LZ, 0);
      AssertUInt64ArraysEqual(LTrinomial.Size, LX, LZ, TrinomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestTrinomial_Square_AgainstReferenceMultiplyBySelf;
var
  LTrinomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LT: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(TrinomialCases) to High(TrinomialCases) do
  begin
    LTrinomial := TBinPolys.TBinPolysMul.Trinomial(TrinomialCases[LC].N, TrinomialCases[LC].K);
    LRandom := TRandom.Create(FixedSeed + 400 + TrinomialCases[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
      begin
        LX := RandomReduced(LRandom, TrinomialCases[LC].N);
        LZ := TBinPolys.Create(LTrinomial.Size);
        LTrinomial.Square(LX, 0, LZ, 0);
        LExpected := ReferenceTrinomialMul(TrinomialCases[LC].N, TrinomialCases[LC].K, LX, LX);
        AssertUInt64ArraysEqual(LTrinomial.Size, LExpected, LZ,
          TrinomialCases[LC].CaseName + ' trial ' + IntToStr(LT));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestTrinomial_SquareN_AgainstRepeatedSquare;
const
  SquareNs: array [0 .. 4] of Int32 = (1, 2, 3, 7, 16);
var
  LTrinomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LI, LSn: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(TrinomialCases) to High(TrinomialCases) do
  begin
    LTrinomial := TBinPolys.TBinPolysMul.Trinomial(TrinomialCases[LC].N, TrinomialCases[LC].K);
    LRandom := TRandom.Create(FixedSeed + 500 + TrinomialCases[LC].N);
    try
      for LSn := Low(SquareNs) to High(SquareNs) do
      begin
        LX := RandomReduced(LRandom, TrinomialCases[LC].N);
        LZ := TBinPolys.Create(LTrinomial.Size);
        LTrinomial.SquareN(LX, 0, SquareNs[LSn], LZ, 0);
        LExpected := TBinPolys.Create(LTrinomial.Size);
        LTrinomial.Square(LX, 0, LExpected, 0);
        for LI := 1 to SquareNs[LSn] - 1 do
          LTrinomial.Square(LExpected, 0, LExpected, 0);
        AssertUInt64ArraysEqual(LTrinomial.Size, LExpected, LZ,
          TrinomialCases[LC].CaseName + ' sn = ' + IntToStr(SquareNs[LSn]));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestTrinomial_AllOps_NonZeroOffsets;
var
  LTrinomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
begin
  for LC := Low(TrinomialCases) to High(TrinomialCases) do
  begin
    LTrinomial := TBinPolys.TBinPolysMul.Trinomial(TrinomialCases[LC].N, TrinomialCases[LC].K);
    LRandom := TRandom.Create(FixedSeed + 1200 + TrinomialCases[LC].N);
    try
      RunAllOpsAtOffsets(LTrinomial, TrinomialCases[LC].N, LRandom, TrinomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_Multiply_AgainstReference;
var
  LPentanomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LT: Int32;
  LX, LY, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(PentanomialCases) to High(PentanomialCases) do
  begin
    LPentanomial := TBinPolys.TBinPolysMul.Pentanomial(PentanomialCases[LC].N, PentanomialCases[LC].K1,
      PentanomialCases[LC].K2, PentanomialCases[LC].K3);
    LRandom := TRandom.Create(FixedSeed + 600 + PentanomialCases[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
      begin
        LX := RandomReduced(LRandom, PentanomialCases[LC].N);
        LY := RandomReduced(LRandom, PentanomialCases[LC].N);
        LZ := TBinPolys.Create(LPentanomial.Size);
        LPentanomial.Multiply(LX, 0, LY, 0, LZ, 0);
        LExpected := ReferencePentanomialMul(PentanomialCases[LC].N, PentanomialCases[LC].K1,
          PentanomialCases[LC].K2, PentanomialCases[LC].K3, LX, LY);
        AssertUInt64ArraysEqual(LPentanomial.Size, LExpected, LZ,
          PentanomialCases[LC].CaseName + ' trial ' + IntToStr(LT));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_Multiply_MultiplyByZero;
var
  LPentanomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
  LX, LZero, LZ: TCryptoLibUInt64Array;
begin
  for LC := Low(PentanomialCases) to High(PentanomialCases) do
  begin
    LPentanomial := TBinPolys.TBinPolysMul.Pentanomial(PentanomialCases[LC].N, PentanomialCases[LC].K1,
      PentanomialCases[LC].K2, PentanomialCases[LC].K3);
    LRandom := TRandom.Create(FixedSeed + 700 + PentanomialCases[LC].N);
    try
      LX := RandomReduced(LRandom, PentanomialCases[LC].N);
      LZero := TBinPolys.Create(LPentanomial.Size);
      LZ := TBinPolys.Create(LPentanomial.Size);
      LPentanomial.Multiply(LX, 0, LZero, 0, LZ, 0);
      AssertUInt64ArraysEqual(LPentanomial.Size, LZero, LZ, PentanomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_Multiply_MultiplyByOne;
var
  LPentanomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
  LX, LOne, LZ: TCryptoLibUInt64Array;
begin
  for LC := Low(PentanomialCases) to High(PentanomialCases) do
  begin
    LPentanomial := TBinPolys.TBinPolysMul.Pentanomial(PentanomialCases[LC].N, PentanomialCases[LC].K1,
      PentanomialCases[LC].K2, PentanomialCases[LC].K3);
    LRandom := TRandom.Create(FixedSeed + 800 + PentanomialCases[LC].N);
    try
      LX := RandomReduced(LRandom, PentanomialCases[LC].N);
      LOne := TBinPolys.Create(LPentanomial.Size);
      LOne[0] := 1;
      LZ := TBinPolys.Create(LPentanomial.Size);
      LPentanomial.Multiply(LX, 0, LOne, 0, LZ, 0);
      AssertUInt64ArraysEqual(LPentanomial.Size, LX, LZ, PentanomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_Square_AgainstReferenceMultiplyBySelf;
var
  LPentanomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LT: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(PentanomialCases) to High(PentanomialCases) do
  begin
    LPentanomial := TBinPolys.TBinPolysMul.Pentanomial(PentanomialCases[LC].N, PentanomialCases[LC].K1,
      PentanomialCases[LC].K2, PentanomialCases[LC].K3);
    LRandom := TRandom.Create(FixedSeed + 900 + PentanomialCases[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
      begin
        LX := RandomReduced(LRandom, PentanomialCases[LC].N);
        LZ := TBinPolys.Create(LPentanomial.Size);
        LPentanomial.Square(LX, 0, LZ, 0);
        LExpected := ReferencePentanomialMul(PentanomialCases[LC].N, PentanomialCases[LC].K1,
          PentanomialCases[LC].K2, PentanomialCases[LC].K3, LX, LX);
        AssertUInt64ArraysEqual(LPentanomial.Size, LExpected, LZ,
          PentanomialCases[LC].CaseName + ' trial ' + IntToStr(LT));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_SquareN_AgainstRepeatedSquare;
const
  SquareNs: array [0 .. 4] of Int32 = (1, 2, 3, 7, 16);
var
  LPentanomial: IBinPolyMul;
  LRandom: IRandom;
  LC, LI, LSn: Int32;
  LX, LZ, LExpected: TCryptoLibUInt64Array;
begin
  for LC := Low(PentanomialCases) to High(PentanomialCases) do
  begin
    LPentanomial := TBinPolys.TBinPolysMul.Pentanomial(PentanomialCases[LC].N, PentanomialCases[LC].K1,
      PentanomialCases[LC].K2, PentanomialCases[LC].K3);
    LRandom := TRandom.Create(FixedSeed + 1000 + PentanomialCases[LC].N);
    try
      for LSn := Low(SquareNs) to High(SquareNs) do
      begin
        LX := RandomReduced(LRandom, PentanomialCases[LC].N);
        LZ := TBinPolys.Create(LPentanomial.Size);
        LPentanomial.SquareN(LX, 0, SquareNs[LSn], LZ, 0);
        LExpected := TBinPolys.Create(LPentanomial.Size);
        LPentanomial.Square(LX, 0, LExpected, 0);
        for LI := 1 to SquareNs[LSn] - 1 do
          LPentanomial.Square(LExpected, 0, LExpected, 0);
        AssertUInt64ArraysEqual(LPentanomial.Size, LExpected, LZ,
          PentanomialCases[LC].CaseName + ' sn = ' + IntToStr(SquareNs[LSn]));
      end;
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_AllOps_NonZeroOffsets;
var
  LPentanomial: IBinPolyMul;
  LRandom: IRandom;
  LC: Int32;
begin
  for LC := Low(PentanomialCases) to High(PentanomialCases) do
  begin
    LPentanomial := TBinPolys.TBinPolysMul.Pentanomial(PentanomialCases[LC].N, PentanomialCases[LC].K1,
      PentanomialCases[LC].K2, PentanomialCases[LC].K3);
    LRandom := TRandom.Create(FixedSeed + 1300 + PentanomialCases[LC].N);
    try
      RunAllOpsAtOffsets(LPentanomial, PentanomialCases[LC].N, LRandom, PentanomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestFactory_RejectsInvalidParameters;
begin
  try
    TBinPolys.TBinPolysMul.Binomial(0);
    Fail('expected exception: Binomial(0)');
  except
    on E: Exception do
      Check(True, 'Binomial(0)');
  end;
  try
    TBinPolys.TBinPolysMul.Binomial(-1);
    Fail('expected exception: Binomial(-1)');
  except
    on E: Exception do
      Check(True, 'Binomial(-1)');
  end;
  try
    TBinPolys.TBinPolysMul.Trinomial(BikeR1, 0);
    Fail('expected exception: Trinomial k=0');
  except
    on E: Exception do
      Check(True, 'Trinomial k=0');
  end;
  try
    TBinPolys.TBinPolysMul.Trinomial(BikeR1, BikeR1);
    Fail('expected exception: Trinomial k=n');
  except
    on E: Exception do
      Check(True, 'Trinomial k=n');
  end;
  try
    TBinPolys.TBinPolysMul.Trinomial(2, 1);
    Fail('expected exception: Trinomial n<3');
  except
    on E: Exception do
      Check(True, 'Trinomial n<3');
  end;
  try
    TBinPolys.TBinPolysMul.Pentanomial(BikeR1, 5, 5, 9);
    Fail('expected exception: Pentanomial k2 not > k1');
  except
    on E: Exception do
      Check(True, 'Pentanomial k2 not > k1');
  end;
  try
    TBinPolys.TBinPolysMul.Pentanomial(BikeR1, 1, 5, 5);
    Fail('expected exception: Pentanomial k3 not > k2');
  except
    on E: Exception do
      Check(True, 'Pentanomial k3 not > k2');
  end;
  try
    TBinPolys.TBinPolysMul.Pentanomial(BikeR1, 1, 3, BikeR1);
    Fail('expected exception: Pentanomial k3 not < n');
  except
    on E: Exception do
      Check(True, 'Pentanomial k3 not < n');
  end;
  try
    TBinPolys.TBinPolysMul.Pentanomial(4, 1, 2, 3);
    Fail('expected exception: Pentanomial n<5');
  except
    on E: Exception do
      Check(True, 'Pentanomial n<5');
  end;
end;

procedure TTestBinPoly.TestFactory_AcceptsEvenN;
var
  LMul: IBinPolyMul;
begin
  LMul := TBinPolys.TBinPolysMul.Binomial(2);
  Check(LMul <> nil, 'Binomial(2)');
  LMul := TBinPolys.TBinPolysMul.Binomial(64);
  Check(LMul <> nil, 'Binomial(64)');
  LMul := TBinPolys.TBinPolysMul.Trinomial(4, 1);
  Check(LMul <> nil, 'Trinomial(4,1)');
  LMul := TBinPolys.TBinPolysMul.Trinomial(64, 1);
  Check(LMul <> nil, 'Trinomial(64,1)');
  LMul := TBinPolys.TBinPolysMul.Trinomial(128, 7);
  Check(LMul <> nil, 'Trinomial(128,7)');
  LMul := TBinPolys.TBinPolysMul.Pentanomial(6, 1, 2, 3);
  Check(LMul <> nil, 'Pentanomial(6,1,2,3)');
  LMul := TBinPolys.TBinPolysMul.Pentanomial(64, 1, 2, 3);
  Check(LMul <> nil, 'Pentanomial(64,1,2,3)');
  LMul := TBinPolys.TBinPolysMul.Pentanomial(128, 2, 5, 7);
  Check(LMul <> nil, 'Pentanomial(128,2,5,7)');
end;

procedure TTestBinPoly.TestTrinomial_Invert_RoundTrip;
var
  LMul: IBinPolyMul;
  LInv: IBinPolyInv;
  LRandom: IRandom;
  LC: Int32;
begin
  for LC := Low(SectTrinomialCases) to High(SectTrinomialCases) do
  begin
    LMul := TBinPolys.TBinPolysMul.Trinomial(SectTrinomialCases[LC].N, SectTrinomialCases[LC].K);
    LInv := TBinPolys.TBinPolysInv.ItohTsujii(LMul);
    LRandom := TRandom.Create(FixedSeed + 1400 + SectTrinomialCases[LC].N);
    try
      RunInvertChecks(LMul, LInv, SectTrinomialCases[LC].N, LRandom, SectTrinomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestPentanomial_Invert_RoundTrip;
var
  LMul: IBinPolyMul;
  LInv: IBinPolyInv;
  LRandom: IRandom;
  LC: Int32;
begin
  for LC := Low(SectPentanomialCases) to High(SectPentanomialCases) do
  begin
    LMul := TBinPolys.TBinPolysMul.Pentanomial(SectPentanomialCases[LC].N, SectPentanomialCases[LC].K1,
      SectPentanomialCases[LC].K2, SectPentanomialCases[LC].K3);
    LInv := TBinPolys.TBinPolysInv.ItohTsujii(LMul);
    LRandom := TRandom.Create(FixedSeed + 1500 + SectPentanomialCases[LC].N);
    try
      RunInvertChecks(LMul, LInv, SectPentanomialCases[LC].N, LRandom, SectPentanomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;

  for LC := Low(X962EvenPentanomialCases) to High(X962EvenPentanomialCases) do
  begin
    LMul := TBinPolys.TBinPolysMul.Pentanomial(X962EvenPentanomialCases[LC].N,
      X962EvenPentanomialCases[LC].K1, X962EvenPentanomialCases[LC].K2, X962EvenPentanomialCases[LC].K3);
    LInv := TBinPolys.TBinPolysInv.ItohTsujii(LMul);
    LRandom := TRandom.Create(FixedSeed + 1500 + X962EvenPentanomialCases[LC].N);
    try
      RunInvertChecks(LMul, LInv, X962EvenPentanomialCases[LC].N, LRandom,
        X962EvenPentanomialCases[LC].CaseName);
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TTestBinPoly.TestInv_Factory_RejectsNullAndDegenerate;
begin
  try
    TBinPolys.TBinPolysInv.ItohTsujii(nil);
    Fail('expected exception: ItohTsujii(null)');
  except
    on E: Exception do
      Check(True, 'ItohTsujii(null)');
  end;
  try
    TBinPolys.TBinPolysInv.ItohTsujii(TBinPolys.TBinPolysMul.Binomial(1));
    Fail('expected exception: ItohTsujii(Binomial(1))');
  except
    on E: Exception do
      Check(True, 'ItohTsujii(Binomial(1))');
  end;
end;

// Cross-backend check: the SIMD backend under test must agree with the scalar
// backend for Multiply, Square and SquareN, even when operands and outputs live
// at non-zero offsets inside guard-padded buffers (verifies offset handling,
// that inputs are never clobbered, and that nothing is written outside the
// result slice).
procedure TBinPolyBackendTestBase.RunBackendVsScalar(AN: Int32; const ARandom: IRandom;
  const AContext: string);
const
  SquareNCount = 5;
var
  LReduce: IBinPolyReduce;
  LScalar, LSimd: IBinPolyMul;
  LSize: Int32;
  LX, LY, LRef, LXBuf, LYBuf, LZBuf, LXBefore, LYBefore, LZBefore: TCryptoLibUInt64Array;
begin
  if not BackendSupported then
    Exit;

  LReduce := TBinPolyMulBaseBinomialReduce.Create(AN);
  LScalar := TBinPolyScalarBackend.CreateBinPolyMul(AN, LReduce);
  LSimd := CreateBackendMul(AN, LReduce);
  LSize := LSimd.Size;

  // Multiply
  LX := RandomReduced(ARandom, AN);
  LY := RandomReduced(ARandom, AN);
  LRef := TBinPolys.Create(LSize);
  LScalar.Multiply(LX, 0, LY, 0, LRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LYBuf := PadBuffer(LSize, OffY, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  TNat.Copy64(LSize, LY, 0, LYBuf, OffY);
  LXBefore := System.Copy(LXBuf);
  LYBefore := System.Copy(LYBuf);
  LZBefore := System.Copy(LZBuf);
  LSimd.Multiply(LXBuf, OffX, LYBuf, OffY, LZBuf, OffZ);
  AssertSliceEquals(LRef, LZBuf, OffZ, LSize, AContext + ' Multiply');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBefore, LXBuf, AContext + ' Multiply xBuf clobbered');
  AssertUInt64ArraysEqual(System.Length(LYBuf), LYBefore, LYBuf, AContext + ' Multiply yBuf clobbered');
  AssertGuardZonesEqual(LZBefore, LZBuf, OffZ, LSize, AContext + ' Multiply zBuf');

  // Square
  LX := RandomReduced(ARandom, AN);
  LRef := TBinPolys.Create(LSize);
  LScalar.Square(LX, 0, LRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  LXBefore := System.Copy(LXBuf);
  LZBefore := System.Copy(LZBuf);
  LSimd.Square(LXBuf, OffX, LZBuf, OffZ);
  AssertSliceEquals(LRef, LZBuf, OffZ, LSize, AContext + ' Square');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBefore, LXBuf, AContext + ' Square xBuf clobbered');
  AssertGuardZonesEqual(LZBefore, LZBuf, OffZ, LSize, AContext + ' Square zBuf');

  // SquareN
  LX := RandomReduced(ARandom, AN);
  LRef := TBinPolys.Create(LSize);
  LScalar.SquareN(LX, 0, SquareNCount, LRef, 0);
  LXBuf := PadBuffer(LSize, OffX, OffPadTail, ARandom);
  LZBuf := PadBuffer(LSize, OffZ, OffPadTail, ARandom);
  TNat.Copy64(LSize, LX, 0, LXBuf, OffX);
  LXBefore := System.Copy(LXBuf);
  LZBefore := System.Copy(LZBuf);
  LSimd.SquareN(LXBuf, OffX, SquareNCount, LZBuf, OffZ);
  AssertSliceEquals(LRef, LZBuf, OffZ, LSize, AContext + ' SquareN');
  AssertUInt64ArraysEqual(System.Length(LXBuf), LXBefore, LXBuf, AContext + ' SquareN xBuf clobbered');
  AssertGuardZonesEqual(LZBefore, LZBuf, OffZ, LSize, AContext + ' SquareN zBuf');
end;

procedure TBinPolyBackendTestBase.AssertBackendMultiplyEquals(AN: Int32;
  const AX, AY: TCryptoLibUInt64Array; const AContext: string);
var
  LReduce: IBinPolyReduce;
  LScalar, LSimd: IBinPolyMul;
  LScalarZ, LSimdZ: TCryptoLibUInt64Array;
begin
  if not BackendSupported then
    Exit;

  LReduce := TBinPolyMulBaseBinomialReduce.Create(AN);
  LScalar := TBinPolyScalarBackend.CreateBinPolyMul(AN, LReduce);
  LSimd := CreateBackendMul(AN, LReduce);
  LScalarZ := TBinPolys.Create(LScalar.Size);
  LSimdZ := TBinPolys.Create(LSimd.Size);
  LScalar.Multiply(AX, 0, AY, 0, LScalarZ, 0);
  LSimd.Multiply(AX, 0, AY, 0, LSimdZ, 0);
  AssertUInt64ArraysEqual(LScalar.Size, LScalarZ, LSimdZ, AContext);
end;

procedure TBinPolyBackendTestBase.TestBackend_Multiply_MatchesScalar;
var
  LRandom: IRandom;
  LT: Int32;
begin
  if not BackendSupported then
    Exit;

  LRandom := TRandom.Create(FixedSeed + 2000);
  try
    for LT := 0 to RandomTrials - 1 do
      RunBackendVsScalar(BikeR1, LRandom,
        'BikeR1 equivalence trial ' + IntToStr(LT));
  finally
    LRandom := nil;
  end;
end;

procedure TBinPolyBackendTestBase.TestBackend_SizeSweep;
const
  SweepCases: array [0 .. 17] of TBinCase = (
    (CaseName: 'lsize1'; N: 32),
    (CaseName: 'lsize2'; N: 96),
    (CaseName: 'lsize3'; N: 160),
    (CaseName: 'lsize4'; N: 224),
    (CaseName: 'lsize5'; N: 288),
    (CaseName: 'lsize6'; N: 352),
    (CaseName: 'lsize7'; N: 416),
    (CaseName: 'lsize8'; N: 480),
    (CaseName: 'lsize9'; N: 544),
    (CaseName: 'lsize10'; N: 608),
    (CaseName: 'lsize11'; N: 672),
    (CaseName: 'lsize12'; N: 736),
    (CaseName: 'lsize17'; N: 1056),
    (CaseName: 'lsize20'; N: 1248),
    (CaseName: 'lsize31'; N: 1952),
    (CaseName: 'lsize32'; N: 2016),
    (CaseName: 'lsize48'; N: 3040),
    (CaseName: 'lsize48b'; N: 3071));
var
  LRandom: IRandom;
  LC, LT: Int32;
begin
  if not BackendSupported then
    Exit;

  for LC := Low(SweepCases) to High(SweepCases) do
  begin
    LRandom := TRandom.Create(FixedSeed + SweepCases[LC].N);
    try
      for LT := 0 to RandomTrials - 1 do
        RunBackendVsScalar(SweepCases[LC].N, LRandom,
          SweepCases[LC].CaseName + ' trial ' + IntToStr(LT));
    finally
      LRandom := nil;
    end;
  end;
end;

procedure TBinPolyBackendTestBase.TestBackend_LSize10_MidWindow;
var
  LRandom: IRandom;
  LT: Int32;
begin
  if not BackendSupported then
    Exit;

  LRandom := TRandom.Create(FixedSeed + 610);
  try
    for LT := 0 to RandomTrials * 2 - 1 do
      RunBackendVsScalar(610, LRandom,
        'LSize10 mid-window trial ' + IntToStr(LT));
  finally
    LRandom := nil;
  end;
end;

// Exhaustively exercise every generated small fixed-size kernel (lsize 1..10)
// through all three operations at non-zero offsets.
procedure TBinPolyBackendTestBase.TestBackend_SmallSizes_AllOps;
var
  LRandom: IRandom;
  LLSize, LT, LN: Int32;
begin
  if not BackendSupported then
    Exit;

  for LLSize := 1 to 10 do
  begin
    LN := LLSize * 64;
    LRandom := TRandom.Create(FixedSeed + 4000 + LLSize);
    try
      for LT := 0 to RandomTrials - 1 do
        RunBackendVsScalar(LN, LRandom,
          'small lsize' + IntToStr(LLSize) + ' trial ' + IntToStr(LT));
    finally
      LRandom := nil;
    end;
  end;
end;

// Multiplying by zero must yield zero and multiplying by one must be the
// identity, matching the scalar backend, across small, medium and large sizes.
procedure TBinPolyBackendTestBase.TestBackend_MultiplyByZeroAndOne;
const
  Sizes: array [0 .. 5] of Int32 = (64, 320, 608, 672, 1248, BikeR1);
var
  LRandom: IRandom;
  LC, LSize: Int32;
  LX, LZero, LOne: TCryptoLibUInt64Array;
begin
  if not BackendSupported then
    Exit;

  LRandom := TRandom.Create(FixedSeed + 5000);
  try
    for LC := Low(Sizes) to High(Sizes) do
    begin
      LSize := (Sizes[LC] + 63) shr 6;
      LX := RandomReduced(LRandom, Sizes[LC]);
      LZero := TBinPolys.Create(LSize);
      LOne := TBinPolys.Create(LSize);
      LOne[0] := 1;
      AssertBackendMultiplyEquals(Sizes[LC], LX, LZero,
        'mul-by-zero n=' + IntToStr(Sizes[LC]));
      AssertBackendMultiplyEquals(Sizes[LC], LX, LOne,
        'mul-by-one n=' + IntToStr(Sizes[LC]));
    end;
  finally
    LRandom := nil;
  end;
end;

// Adversarial bit patterns (all-ones, single high bit, alternating) maximise
// carryless lane interaction and catch lane-splice / shift errors that random
// inputs may miss.
procedure TBinPolyBackendTestBase.TestBackend_EdgeVectors;
const
  Sizes: array [0 .. 6] of Int32 = (64, 192, 608, 672, 736, 1248, BikeR1);
var
  LC, LSize, LTop, LBit: Int32;
  LAllOnes, LAlt, LHighBit, LLowBit: TCryptoLibUInt64Array;

  function MaskedTop(const AVec: TCryptoLibUInt64Array; AN: Int32)
    : TCryptoLibUInt64Array;
  var
    LPartial: Int32;
  begin
    Result := AVec;
    LPartial := AN and 63;
    if LPartial <> 0 then
      Result[System.Length(Result) - 1] := Result[System.Length(Result) - 1]
        and ((UInt64(1) shl LPartial) - 1);
  end;

begin
  if not BackendSupported then
    Exit;

  for LC := Low(Sizes) to High(Sizes) do
  begin
    LSize := (Sizes[LC] + 63) shr 6;

    LAllOnes := TBinPolys.Create(LSize);
    LAlt := TBinPolys.Create(LSize);
    for LTop := 0 to LSize - 1 do
    begin
      LAllOnes[LTop] := UInt64($FFFFFFFFFFFFFFFF);
      LAlt[LTop] := UInt64($AAAAAAAAAAAAAAAA);
    end;
    LAllOnes := MaskedTop(LAllOnes, Sizes[LC]);
    LAlt := MaskedTop(LAlt, Sizes[LC]);

    LHighBit := TBinPolys.Create(LSize);
    LBit := Sizes[LC] - 1;
    LHighBit[LBit shr 6] := UInt64(1) shl (LBit and 63);

    LLowBit := TBinPolys.Create(LSize);
    LLowBit[0] := 1;

    AssertBackendMultiplyEquals(Sizes[LC], LAllOnes, LAllOnes,
      'edge allones^2 n=' + IntToStr(Sizes[LC]));
    AssertBackendMultiplyEquals(Sizes[LC], LAllOnes, LAlt,
      'edge allones*alt n=' + IntToStr(Sizes[LC]));
    AssertBackendMultiplyEquals(Sizes[LC], LHighBit, LHighBit,
      'edge highbit^2 n=' + IntToStr(Sizes[LC]));
    AssertBackendMultiplyEquals(Sizes[LC], LHighBit, LAllOnes,
      'edge highbit*allones n=' + IntToStr(Sizes[LC]));
    AssertBackendMultiplyEquals(Sizes[LC], LAlt, LLowBit,
      'edge alt*lowbit n=' + IntToStr(Sizes[LC]));
  end;
end;

procedure TTestBinPoly.TestBitLengthVar_AgainstReference;
const
  Sizes: array [0 .. 4] of Int32 = (1, 2, 3, 5, 9);
var
  LRandom: IRandom;
  LS, LT: Int32;
  LZero, LOne, LTop, LX: TCryptoLibUInt64Array;
begin
  LRandom := TRandom.Create(FixedSeed + 1600);
  try
    for LS := Low(Sizes) to High(Sizes) do
    begin
      System.SetLength(LZero, Sizes[LS]);
      CheckEquals(0, TBinPolys.BitLengthVar(Sizes[LS], LZero, 0), 'zero size ' + IntToStr(Sizes[LS]));
      System.SetLength(LOne, Sizes[LS]);
      LOne[0] := 1;
      CheckEquals(1, TBinPolys.BitLengthVar(Sizes[LS], LOne, 0), 'one size ' + IntToStr(Sizes[LS]));
      System.SetLength(LTop, Sizes[LS]);
      LTop[Sizes[LS] - 1] := UInt64(1) shl 63;
      CheckEquals(Sizes[LS] * 64, TBinPolys.BitLengthVar(Sizes[LS], LTop, 0),
        'top size ' + IntToStr(Sizes[LS]));
      for LT := 0 to 31 do
      begin
        LX := RandomLimbs(LRandom, Sizes[LS]);
        CheckEquals(ReferenceBitLength(Sizes[LS], LX),
          TBinPolys.BitLengthVar(Sizes[LS], LX, 0),
          'size ' + IntToStr(Sizes[LS]) + ' trial ' + IntToStr(LT));
      end;
    end;
  finally
    LRandom := nil;
  end;
end;

{$IFDEF CRYPTOLIB_X86_SIMD}

{ TTestBinPolyX86 }

function TTestBinPolyX86.BackendSupported: Boolean;
begin
  Result := TBinPolyX86Backend.IsSupported;
end;

function TTestBinPolyX86.CreateBackendMul(AN: Int32;
  const AReduce: IBinPolyReduce): IBinPolyMul;
begin
  if not TBinPolySimd.TryCreateBinPolyMul(AN, AReduce, Result) then
    Result := nil;
end;

function TTestBinPolyX86.BackendLabel: String;
begin
  Result := 'X86';
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

initialization

{$IFDEF FPC}
  RegisterTest(TTestBinPoly);
{$ELSE}
  RegisterTest(TTestBinPoly.Suite);
{$ENDIF FPC}

{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF FPC}
  RegisterTest(TTestBinPolyX86);
{$ELSE}
  RegisterTest(TTestBinPolyX86.Suite);
{$ENDIF FPC}
{$ENDIF CRYPTOLIB_X86_SIMD}

end.
