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

unit ClpBinPolySimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  ClpBinPolyX86Backend,
{$ELSEIF DEFINED(CRYPTOLIB_AARCH64_ASM)}
  ClpBinPolyArmBackend,
{$IFEND}
  ClpCryptoLibExceptions,
  ClpIBinPolyMul;

type
  /// <summary>
  /// Arch-neutral SIMD coordinator for binary-polynomial multiplication. Owns the
  /// size-dispatch factory that builds the arch-neutral SIMD multipliers
  /// (<c>ClpBinPolySimd{Sizes,Medium,Large}</c>) and exposes the leaf carryless
  /// multiply kernels, routing them at compile time to the active per-arch backend
  /// (x86 PCLMULQDQ, aarch64 PMULL). SIMD-only by contract: <c>TryCreateBinPolyMul</c>
  /// reports "not handled" (False) when no SIMD backend is available or supported,
  /// so the scalar fallback stays with the caller (<c>TBinPolys</c>), matching the
  /// Try*-then-scalar shape used across the other SIMD families.
  /// </summary>
  TBinPolySimd = class sealed
  public
    /// <summary>
    /// Build a SIMD <c>IBinPolyMul</c> for degree <paramref name="AN"/> under the
    /// given reduction when a SIMD backend is available (returns True with
    /// <paramref name="AMul"/> set); otherwise <paramref name="AMul"/> is nil and
    /// the caller runs its scalar path (returns False).
    /// </summary>
    class function TryCreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce;
      out AMul: IBinPolyMul): Boolean; static;

    /// <summary>
    /// Leaf carryless multiply, routed to the active per-arch SIMD backend; called by
    /// the arch-neutral <c>ClpBinPolySimd*</c> multipliers.
    /// </summary>
    class procedure ImplMulSmall(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplMulEven(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplMulOdd(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplSquare(ALen: Int32; PX, PZz: PUInt64); static;
  end;

implementation

{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
uses
  ClpBinPolySimdSizes,
  ClpBinPolySimdMedium,
  ClpBinPolySimdLarge;
{$IFEND}

{ TBinPolySimd }

class function TBinPolySimd.TryCreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce;
  out AMul: IBinPolyMul): Boolean;
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
var
  LSize: Int32;
{$IFEND}
begin
  AMul := nil;
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if TBinPolyX86Backend.IsSupported then
{$ELSE}
  if TBinPolyArmBackend.IsSupported then
{$IFEND}
  begin
    LSize := (AN + 63) shr 6;
    case LSize of
      1: AMul := TBinPolySimdSize1.Create(AN, AReduce);
      2: AMul := TBinPolySimdSize2.Create(AN, AReduce);
      3: AMul := TBinPolySimdSize3.Create(AN, AReduce);
      4: AMul := TBinPolySimdSize4.Create(AN, AReduce);
      5: AMul := TBinPolySimdSize5.Create(AN, AReduce);
      6: AMul := TBinPolySimdSize6.Create(AN, AReduce);
      7: AMul := TBinPolySimdSize7.Create(AN, AReduce);
      8: AMul := TBinPolySimdSize8.Create(AN, AReduce);
      9: AMul := TBinPolySimdSize9.Create(AN, AReduce);
      10: AMul := TBinPolySimdSize10.Create(AN, AReduce);
    else
      if LSize >= TBinPolySimdLarge.KaratsubaCutoff then
        AMul := TBinPolySimdLarge.Create(AN, AReduce)
      else if (LSize and 1) = 0 then
        AMul := TBinPolySimdMediumEven.Create(AN, AReduce)
      else
        AMul := TBinPolySimdMediumOdd.Create(AN, AReduce);
    end;
    Exit(True);
  end;
{$IFEND}
  Result := False;
end;

class procedure TBinPolySimd.ImplMulSmall(ALen: Int32; PX, PY, PZz: PUInt64);
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  TBinPolyX86Backend.ImplMulSmall(ALen, PX, PY, PZz);
{$ELSEIF DEFINED(CRYPTOLIB_AARCH64_ASM)}
  TBinPolyArmBackend.ImplMulSmall(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplementedCryptoLibException.Create('SIMD ImplMulSmall is not available on this target');
{$IFEND}
end;

class procedure TBinPolySimd.ImplMulEven(ALen: Int32; PX, PY, PZz: PUInt64);
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  TBinPolyX86Backend.ImplMulEven(ALen, PX, PY, PZz);
{$ELSEIF DEFINED(CRYPTOLIB_AARCH64_ASM)}
  TBinPolyArmBackend.ImplMulEven(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplementedCryptoLibException.Create('SIMD ImplMulEven is not available on this target');
{$IFEND}
end;

class procedure TBinPolySimd.ImplMulOdd(ALen: Int32; PX, PY, PZz: PUInt64);
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  TBinPolyX86Backend.ImplMulOdd(ALen, PX, PY, PZz);
{$ELSEIF DEFINED(CRYPTOLIB_AARCH64_ASM)}
  TBinPolyArmBackend.ImplMulOdd(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplementedCryptoLibException.Create('SIMD ImplMulOdd is not available on this target');
{$IFEND}
end;

class procedure TBinPolySimd.ImplSquare(ALen: Int32; PX, PZz: PUInt64);
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  TBinPolyX86Backend.ImplSquare(ALen, PX, PZz);
{$ELSEIF DEFINED(CRYPTOLIB_AARCH64_ASM)}
  TBinPolyArmBackend.ImplSquare(ALen, PX, PZz);
{$ELSE}
  raise ENotImplementedCryptoLibException.Create('SIMD ImplSquare is not available on this target');
{$IFEND}
end;

end.
