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

unit ClpMontKernelContext;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpMontKernelSimd,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SMontKernelUnavailable =
    'Montgomery kernel unavailable after the width probe succeeded';

type

  /// <summary>
  /// A reusable Montgomery kernel context over an odd modulus, expressed in 64-bit
  /// little-endian limbs: the single source of truth for the kernel context layout
  /// (<c>[-n0', N64, modulus-limbs]</c>), the Newton derivation of <c>n0'</c>, and the
  /// N64+2 CIOS accumulator discipline. Shared by the windowed modular exponentiation
  /// and by RSA blinding so the two never drift.
  ///
  /// <c>Ctx</c> is immutable once built, so one context is safe to share across threads;
  /// the scratch is caller-owned (each thread/operation supplies its own), which is what
  /// lets concurrent signatures run one shared blinding context without contending.
  /// </summary>
  TMontKernelContext = record
  public
  var
    Ctx: TCryptoLibUInt64Array;
    N64: Int32;
    /// <summary>Build the context from the low <c>ALN64</c> 64-bit limbs of an odd
    /// modulus. Returns True iff the kernel engages for this width (probe); on False
    /// the caller must use a scalar fallback.</summary>
    function TryBuild(const AModulusLimbs: TCryptoLibUInt64Array;
      ALN64: Int32): Boolean;
    /// <summary><c>ADst[0..N64-1] := AX*AY*R^-1 mod n</c>. <c>AScratch</c> must hold at
    /// least N64+2 limbs and must not alias AX/AY; ADst may alias AX/AY (the product
    /// lands in the scratch first, then is copied out).</summary>
    procedure Mul(const AScratch, AX, AY, ADst: TCryptoLibUInt64Array);
    /// <summary><c>ADst := AX^2*R^-1 mod n</c>, via the dedicated square kernel where
    /// available, otherwise <c>Mul(AX, AX)</c>.</summary>
    procedure Sqr(const AScratch, AX, ADst: TCryptoLibUInt64Array);
  end;

implementation

{ TMontKernelContext }

function TMontKernelContext.TryBuild(const AModulusLimbs: TCryptoLibUInt64Array;
  ALN64: Int32): Boolean;
var
  LN0: UInt64;
  LI: Int32;
  LProbe, LInput: TCryptoLibUInt64Array;
begin
  Result := False;
  if ALN64 < 2 then
    Exit;
  N64 := ALN64;
  System.SetLength(Ctx, N64 + 2);
  Ctx[1] := UInt64(N64);
  System.Move(AModulusLimbs[0], Ctx[2], N64 * System.SizeOf(UInt64));
  LN0 := AModulusLimbs[0];
  for LI := 1 to 5 do
    LN0 := LN0 * (UInt64(2) - AModulusLimbs[0] * LN0);
  Ctx[0] := UInt64(0) - LN0;
  // probe with a throwaway N64+2 CIOS accumulator (the wide kernels write N64+2 limbs)
  // over a zeroed N64 input; the result buffer must not alias the input.
  System.SetLength(LProbe, N64 + 2);
  System.SetLength(LInput, N64);
  Result := TMontKernelSimd.TryMontMul(PUInt64(@LProbe[0]), PUInt64(@LInput[0]),
    PUInt64(@LInput[0]), PUInt64(@Ctx[0]));
end;

procedure TMontKernelContext.Mul(const AScratch, AX, AY, ADst: TCryptoLibUInt64Array);
begin
  // the width was probed at build; a False here means the kernel was disabled since,
  // leaving the scratch unwritten - never publish it as a result.
  if not TMontKernelSimd.TryMontMul(PUInt64(@AScratch[0]), PUInt64(@AX[0]),
    PUInt64(@AY[0]), PUInt64(@Ctx[0])) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SMontKernelUnavailable);
  System.Move(AScratch[0], ADst[0], N64 * System.SizeOf(UInt64));
end;

procedure TMontKernelContext.Sqr(const AScratch, AX, ADst: TCryptoLibUInt64Array);
begin
  if TMontKernelSimd.TryMontSqr(PUInt64(@AScratch[0]), PUInt64(@AX[0]),
    PUInt64(@Ctx[0])) then
    System.Move(AScratch[0], ADst[0], N64 * System.SizeOf(UInt64))
  else
    Mul(AScratch, AX, AX, ADst);
end;

end.
