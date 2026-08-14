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

unit ClpFpKernelSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpFpKernelX86Backend,
{$ENDIF}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpFpKernelArmBackend,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Arch-neutral facade over the prime-field (Fp) big-integer multiply/square
  /// kernel. <c>TryMul</c>/<c>TrySqr</c> reinterpret the caller's little-endian
  /// 32-bit-limb field arrays as 64-bit limbs and run the wide multiply, returning
  /// <c>False</c> when no fast path applies (unsupported arch, a forced-scalar
  /// build, or an odd 32-bit limb count such as P-521's 17); the caller then uses its
  /// existing 32-bit path.
  /// </summary>
  TFpKernelSimd = class sealed
  public
    /// <summary>AZz[0..2*ALimbs32-1] := AX * AY (both ALimbs32 uint32 limbs).
    /// Returns False if unsupported (caller falls back).</summary>
    class function TryMul(const AX, AY, AZz: TCryptoLibUInt32Array;
      ALimbs32: Int32): Boolean; overload; static;
    class function TryMul(APX, APY, APZz: PUInt32; ALimbs32: Int32): Boolean; overload; static;
    /// <summary>AZz[0..2*ALimbs32-1] := AX^2. Returns False if unsupported.</summary>
    class function TrySqr(const AX, AZz: TCryptoLibUInt32Array;
      ALimbs32: Int32): Boolean; overload; static;
    class function TrySqr(APX, APZz: PUInt32; ALimbs32: Int32): Boolean; overload; static;
  end;

implementation

{ TFpKernelSimd }

class function TFpKernelSimd.TryMul(const AX, AY, AZz: TCryptoLibUInt32Array;
  ALimbs32: Int32): Boolean;
begin
  Result := TryMul(PUInt32(@AX[0]), PUInt32(@AY[0]), PUInt32(@AZz[0]), ALimbs32);
end;

class function TFpKernelSimd.TryMul(APX, APY, APZz: PUInt32; ALimbs32: Int32): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  // Even 32-bit limb count only: uint32[2N] == uint64[N]. Odd widths (P-521 = 17)
  // are not byte-identical to any uint64[k] and need a mixed-width kernel.
  if (ALimbs32 and 1) <> 0 then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  TFpKernelX86Backend.Mul(PUInt64(APX), PUInt64(APY), PUInt64(APZz), ALimbs32 shr 1);
  {$ELSE}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  TFpKernelArmBackend.Mul(PUInt64(APX), PUInt64(APY), PUInt64(APZz), ALimbs32 shr 1);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelSimd.TrySqr(const AX, AZz: TCryptoLibUInt32Array;
  ALimbs32: Int32): Boolean;
begin
  Result := TrySqr(PUInt32(@AX[0]), PUInt32(@AZz[0]), ALimbs32);
end;

class function TFpKernelSimd.TrySqr(APX, APZz: PUInt32; ALimbs32: Int32): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if (ALimbs32 and 1) <> 0 then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  TFpKernelX86Backend.Sqr(PUInt64(APX), PUInt64(APZz), ALimbs32 shr 1);
  {$ELSE}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  TFpKernelArmBackend.Sqr(PUInt64(APX), PUInt64(APZz), ALimbs32 shr 1);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
