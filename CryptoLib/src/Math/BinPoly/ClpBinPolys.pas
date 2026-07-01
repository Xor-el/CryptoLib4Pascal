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

unit ClpBinPolys;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpInt64Utilities,
  ClpNat,
  ClpIBinPolyMul,
  ClpIBinPolyInv,
  ClpBinPolyMulBaseBinomialReduce,
  ClpBinPolyMulBaseTrinomialReduce,
  ClpBinPolyMulBasePentanomialReduce,
  ClpBinPolySimd,
  ClpBinPolyScalarBackend,
  ClpItohTsujiiInv;

type
  /// <summary>
  /// Static entry point for binary-polynomial helpers. Reducer-independent operations
  /// (<c>Size</c>, <c>Create</c>, <c>Add</c>, <c>AddTo</c>, etc.) sit at the top level;
  /// factories classified by reduction polynomial shape live under the nested
  /// <c>TBinPolysMul</c> class, and inversion factories under <c>TBinPolysInv</c>
  /// (Itoh-Tsujii).
  /// </summary>
  /// <remarks>
  /// Internal library surface — consumed by the generic F2m field layer and other
  /// in-library callers, not a published public API.
  /// </remarks>
  TBinPolys = class sealed
  public
    /// <summary>
    /// Number of UInt64 limbs required to hold a polynomial of bit length <paramref name="AN"/>.
    /// </summary>
    class function Size(AN: Int32): Int32; static;
    /// <summary>
    /// Allocate a fresh limb array of length <paramref name="ASize"/> (in UInt64 limbs, as
    /// returned by <c>Size</c>), initialised to zero. Caller-side bit-length-to-limb-count
    /// conversion sits at <c>Size</c>; this helper takes the already-converted limb count,
    /// matching the shape of <c>Add</c> / <c>AddTo</c>.
    /// </summary>
    class function Create(ASize: Int32): TCryptoLibUInt64Array; static;
    /// <summary>
    /// Compute <c>AZ = AX + AY</c> as polynomial addition over GF(2) (limb-wise XOR).
    /// Independent of any reduction polynomial: degree-&lt;n stays degree-&lt;n automatically
    /// (no carry, no reduction). Operates on <paramref name="ASize"/>-limb slices starting at
    /// the given offsets.
    /// </summary>
    class procedure Add(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    /// <summary>
    /// Compute <c>AZ = AZ + AX</c> as polynomial addition over GF(2) (limb-wise XOR into the
    /// accumulator). See <c>Add</c> for the reduction-independence rationale.
    /// </summary>
    class procedure AddTo(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    /// <summary>
    /// Copy a polynomial: <c>AZ[AzOff..AzOff + ASize] = AX[AxOff..AxOff + ASize]</c>.
    /// No secret-wipe semantics — value-level move.
    /// </summary>
    class procedure Copy(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    /// <summary>
    /// Set the polynomial to the zero element of the ring: write 0 to every limb in
    /// <c>AZ[AzOff..AzOff + ASize]</c>. Value-level — for initialising accumulators and
    /// similar. For wiping secret-bearing intermediate buffers, use <c>Clear</c> instead.
    /// </summary>
    class procedure Zero(ASize: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    /// <summary>
    /// Secret-wipe: actively erase <c>AZ[AzOff..AzOff + ASize]</c>. Use this — not
    /// <c>Zero</c> — at sites where the buffer carried partial-product / key material that
    /// must be wiped under the project's side-channel discipline.
    /// </summary>
    class procedure Clear(ASize: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    /// <summary>
    /// Set the polynomial to 1 (the multiplicative identity in GF(2)[x] / r(x) for any r(x)
    /// with a non-zero constant term — true for all binomial / trinomial / pentanomial
    /// reductions this subsystem supports). This is the polynomial 1 (low bit set, all other
    /// bits clear), not "all bits set".
    /// </summary>
    class procedure One(ASize: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    /// <summary>
    /// Constant-time equality test: returns <c>UInt64.MaxValue</c> if
    /// <c>AX[AxOff..AxOff + ASize]</c> equals <c>AY[AyOff..AyOff + ASize]</c> limb-for-limb,
    /// and <c>0</c> otherwise. Forwards to <c>TNat.EqualTo64</c>; safe to use on
    /// secret-bearing polynomials.
    /// </summary>
    class function EqualTo(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32): UInt64; static;
    /// <summary>
    /// Constant-time test for the multiplicative identity: returns <c>UInt64.MaxValue</c> if
    /// <c>AX</c> is the polynomial 1 (low bit set, all other bits clear), and <c>0</c>
    /// otherwise. Safe to use on secret-bearing polynomials.
    /// </summary>
    class function EqualToOne(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32): UInt64; static;
    /// <summary>
    /// Constant-time test for the zero element: returns <c>UInt64.MaxValue</c> if every limb
    /// of <c>AX</c> is zero, and <c>0</c> otherwise. Safe to use on secret-bearing
    /// polynomials.
    /// </summary>
    class function EqualToZero(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32): UInt64; static;
    /// <summary>
    /// Variable-time bit length of the polynomial in <c>AX</c>: the position of its most
    /// significant set bit plus one (i.e. degree + 1), or 0 for the zero polynomial. The
    /// <c>Var</c> suffix flags the data-dependent running time — must not be used where the
    /// polynomial is secret and timing is observable.
    /// </summary>
    class function BitLengthVar(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32): Int32; static;

    type
      /// <summary>
      /// Factories for <c>IBinPolyMul</c> instances, classified by reduction polynomial shape:
      /// <c>Binomial</c> for <c>x^n + 1</c>, <c>Trinomial</c> for <c>x^n + x^k + 1</c>, and
      /// <c>Pentanomial</c> for <c>x^n + x^k3 + x^k2 + x^k1 + 1</c>.
      /// </summary>
      /// <remarks>
      /// The factories check parameter ranges and tap ordering but not irreducibility; callers
      /// attest to irreducibility by selecting the appropriate factory (a reducible polynomial
      /// yields defined-but-meaningless results).
      /// </remarks>
      TBinPolysMul = class sealed
      strict private
        /// <summary>
        /// Upper bound on the polynomial bit length n, enforced at factory time. The cap keeps
        /// all downstream limb-count and offset arithmetic provably within Int32 range.
        /// </summary>
        const
          MaxN = 1 shl 20;
        class function CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul; static;
      public
        /// <summary>Reduction by <c>x^n + 1</c> (cyclic ring).</summary>
        class function Binomial(AN: Int32): IBinPolyMul; static;
        /// <summary>Reduction by <c>x^n + x^k + 1</c>.</summary>
        class function Trinomial(AN, AK: Int32): IBinPolyMul; static;
        /// <summary>Reduction by <c>x^n + x^k3 + x^k2 + x^k1 + 1</c>.</summary>
        class function Pentanomial(AN, AK1, AK2, AK3: Int32): IBinPolyMul; static;
      end;

      /// <summary>
      /// Factories for <c>IBinPolyInv</c> instances (multiplicative inversion in GF(2^n)),
      /// the inversion-specialised sibling of <c>TBinPolysMul</c>.
      /// </summary>
      /// <remarks>
      /// Inversion requires a field: the reduction polynomial backing the <c>IBinPolyMul</c>
      /// passed to <c>ItohTsujii</c> must be irreducible. The binomial reducer (<c>x^n + 1</c>)
      /// is always reducible and must not be passed.
      /// </remarks>
      TBinPolysInv = class sealed
      public
        /// <summary>
        /// Itoh-Tsujii inversion driving the supplied <c>IBinPolyMul</c>'s arithmetic:
        /// <c>a^{-1} = a^(2^n - 2)</c> via an addition chain on <c>n - 1</c>. Valid for any
        /// n (even or odd) provided the reduction polynomial is irreducible.
        /// </summary>
        class function ItohTsujii(const AMul: IBinPolyMul): IBinPolyInv; static;
      end;
  end;

implementation

{ TBinPolys }

class function TBinPolys.Size(AN: Int32): Int32;
begin
  Result := (AN + 63) shr 6;
end;

class function TBinPolys.Create(ASize: Int32): TCryptoLibUInt64Array;
begin
  SetLength(Result, ASize);
end;

class procedure TBinPolys.Add(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  TNat.Xor64(ASize, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

class procedure TBinPolys.AddTo(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  TNat.XorTo64(ASize, AX, AXOff, AZ, AZOff);
end;

class procedure TBinPolys.Copy(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  TNat.Copy64(ASize, AX, AXOff, AZ, AZOff);
end;

class procedure TBinPolys.Zero(ASize: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  TArrayUtilities.Fill<UInt64>(AZ, AZOff, AZOff + ASize, 0);
end;

class procedure TBinPolys.Clear(ASize: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  TArrayUtilities.Fill<UInt64>(AZ, AZOff, AZOff + ASize, 0);
end;

class procedure TBinPolys.One(ASize: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  AZ[AZOff] := 1;
  if ASize > 1 then
    TArrayUtilities.Fill<UInt64>(AZ, AZOff + 1, AZOff + ASize, 0);
end;

class function TBinPolys.EqualTo(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32): UInt64;
begin
  Result := TNat.EqualTo64(ASize, AX, AXOff, AY, AYOff);
end;

class function TBinPolys.EqualToOne(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32): UInt64;
begin
  Result := TNat.EqualToOne64(ASize, AX, AXOff);
end;

class function TBinPolys.EqualToZero(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32): UInt64;
begin
  Result := TNat.EqualToZero64(ASize, AX, AXOff);
end;

class function TBinPolys.BitLengthVar(ASize: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32): Int32;
var
  LI: Int32;
  LX_i: UInt64;
begin
  for LI := ASize - 1 downto 0 do
  begin
    LX_i := AX[AXOff + LI];
    if LX_i <> 0 then
      Exit(LI * TInt64Utilities.NumBits + TInt64Utilities.BitLength(LX_i));
  end;
  Result := 0;
end;

{ TBinPolys.TBinPolysMul }

class function TBinPolys.TBinPolysMul.CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul;
begin
  if TBinPolySimd.TryCreateBinPolyMul(AN, AReduce, Result) then
    Exit;
  Result := TBinPolyScalarBackend.CreateBinPolyMul(AN, AReduce);
end;

class function TBinPolys.TBinPolysMul.Binomial(AN: Int32): IBinPolyMul;
begin
  if AN < 1 then
    raise EArgumentOutOfRangeException.Create('n must be positive');
  if AN > MaxN then
    raise EArgumentOutOfRangeException.Create('n must be at most 2^20');
  Result := CreateBinPolyMul(AN, TBinPolyMulBaseBinomialReduce.Create(AN));
end;

class function TBinPolys.TBinPolysMul.Trinomial(AN, AK: Int32): IBinPolyMul;
begin
  if AN < 3 then
    raise EArgumentOutOfRangeException.Create('n must be at least 3');
  if AN > MaxN then
    raise EArgumentOutOfRangeException.Create('n must be at most 2^20');
  if (AK < 1) or (AK >= AN) then
    raise EArgumentOutOfRangeException.Create('k must satisfy 0 < k < n');
  Result := CreateBinPolyMul(AN, TBinPolyMulBaseTrinomialReduce.Create(AN, AK));
end;

class function TBinPolys.TBinPolysMul.Pentanomial(AN, AK1, AK2, AK3: Int32): IBinPolyMul;
begin
  if AN < 5 then
    raise EArgumentOutOfRangeException.Create('n must be at least 5');
  if AN > MaxN then
    raise EArgumentOutOfRangeException.Create('n must be at most 2^20');
  if (AK1 < 1) or (AK2 <= AK1) or (AK3 <= AK2) or (AK3 >= AN) then
    raise EArgumentException.Create('must satisfy 0 < k1 < k2 < k3 < n');
  Result := CreateBinPolyMul(AN, TBinPolyMulBasePentanomialReduce.Create(AN, AK1, AK2, AK3));
end;

{ TBinPolys.TBinPolysInv }

class function TBinPolys.TBinPolysInv.ItohTsujii(const AMul: IBinPolyMul): IBinPolyInv;
begin
  if AMul = nil then
    raise EArgumentNilException.Create('mul');
  if AMul.N < 2 then
    raise EArgumentException.Create('inversion requires a field of degree at least 2');
  Result := TItohTsujiiInv.Create(AMul);
end;

end.
