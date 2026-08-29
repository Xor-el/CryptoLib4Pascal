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
  strict private
    class var FForceP256Disabled: Boolean;
  public
    /// <summary>AZz[0..2*ALimbs32-1] := AX * AY (both ALimbs32 uint32 limbs).
    /// Returns False if unsupported (caller falls back).</summary>
    class function TryMul(const AX, AY, AZz: TCryptoLibUInt32Array;
      ALimbs32: Int32): Boolean; overload; static; inline;
    class function TryMul(APX, APY, APZz: PUInt32; ALimbs32: Int32): Boolean; overload; static; inline;
    /// <summary>AZz[0..2*ALimbs32-1] := AX^2. Returns False if unsupported.</summary>
    class function TrySqr(const AX, AZz: TCryptoLibUInt32Array;
      ALimbs32: Int32): Boolean; overload; static; inline;
    class function TrySqr(APX, APZz: PUInt32; ALimbs32: Int32): Boolean; overload; static; inline;
    /// <summary>Fused CIOS Montgomery multiply APR := APA*APB*R^-1 mod p. APCtx =
    /// [n0', N, p[0..N-1]] (64-bit limbs); APR is the N+2-limb scratch and receives
    /// the reduced N-limb result. Returns False when unsupported (caller uses its
    /// Montgomery fallback).</summary>
    class function TryMontMul(APR, APA, APB, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>P-256 special-prime Montgomery multiply APR := APA*APB*R^-1 mod p (folded
    /// shift/add reduction). APCtx = the P-256 [n0'=1, N=4, p0..p3]. False when the gate
    /// is disabled, force-scalar, no BMI2+ADX, or non-x86-64 -> caller uses generic CIOS,
    /// bit-for-bit.</summary>
    class function TryMontMulP256(APR, APA, APB, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>P-256 dedicated Montgomery square APR := APA^2 * R^-1 mod p (dual-chain
    /// SOS square + the same folded reduction). Same gating as TryMontMulP256; False ->
    /// caller falls back to the multiply.</summary>
    class function TryMontSqrP256(APR, APA, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Fused P-256 incomplete-Jacobian doubling APR := 2*APA (Jacobian). False
    /// when force-scalar, no BMI2+ADX, or non-x86-64 -> caller uses the generic per-op
    /// Jacobian formula.</summary>
    class function TryP256JacPointDouble(APR, APA, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Fused P-256 incomplete-Jacobian addition. APScratch is a TJacAddScratch
    /// base (R + H + RS); the masked-infinity completion runs inside the kernel and the
    /// caller owns the P=Q detect-and-double.</summary>
    class function TryP256JacPointAdd(APScratch, APA, APQ, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Fused P-256 incomplete-Jacobian mixed addition (APQ a TFeAffine base,
    /// implicit Z2=1 from APCtx.MontOne).</summary>
    class function TryP256JacPointAddMixed(APScratch, APA, APQ, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Fused secp256k1 (a=0) incomplete-Jacobian doubling APR := 2*APA. False
    /// when force-scalar, no BMI2+ADX, or non-x86-64 (no arm k1 kernel yet) -> caller
    /// uses the generic per-op Jacobian formula.</summary>
    class function TryK256JacPointDouble(APR, APA, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Fused secp256k1 incomplete-Jacobian addition. APScratch is a
    /// TJacAddScratch base (R + H + RS); the masked-infinity completion runs inside the
    /// kernel and the caller owns the P=Q detect-and-double.</summary>
    class function TryK256JacPointAdd(APScratch, APA, APQ, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Fused secp256k1 incomplete-Jacobian mixed addition (APQ a TFeAffine base,
    /// implicit Z2=1 from APCtx.MontOne).</summary>
    class function TryK256JacPointAddMixed(APScratch, APA, APQ, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Constant-time modular add/sub APR := (APA +/- APB) mod p. APCtx =
    /// [n0'(unused), N, p[0..N-1]]; inputs assumed < p. False when unsupported.</summary>
    class function TryModAdd(APR, APA, APB, APCtx: PUInt64): Boolean; static; inline;
    class function TryModSub(APR, APA, APB, APCtx: PUInt64): Boolean; static; inline;
    /// <summary>Constant-time gather: APDst := the AIndex-th of ACount entries (each
    /// AEntryBytes wide), with index-independent access. False when force-scalar.</summary>
    class function TryGather(APDst, APTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean; static; inline;
    /// <summary>Test gate: force the P-256 special kernel off so the generic CIOS runs
    /// (differential dual-path validation). Default False.</summary>
    class property ForceP256Disabled: Boolean read FForceP256Disabled write FForceP256Disabled;
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

class function TFpKernelSimd.TryMontMul(APR, APA, APB, APCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.MontMul(APR, APA, APB, APCtx);
  {$ELSE}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.MontMul(APR, APA, APB, APCtx);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelSimd.TryMontMulP256(APR, APA, APB, APCtx: PUInt64): Boolean;
begin
  if FForceP256Disabled then
    Exit(False);
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False); // force-scalar / no SIMD -> generic CIOS
  Result := TFpKernelX86Backend.MontMulP256(APR, APA, APB, APCtx); // False if no BMI2+ADX
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False); // force-scalar / no SIMD -> generic CIOS
  Result := TFpKernelArmBackend.MontMulP256(APR, APA, APB, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryMontSqrP256(APR, APA, APCtx: PUInt64): Boolean;
begin
  if FForceP256Disabled then
    Exit(False);
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False); // force-scalar / no SIMD -> generic CIOS
  Result := TFpKernelX86Backend.MontSqrP256(APR, APA, APCtx); // False if no BMI2+ADX
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelSimd.TryP256JacPointDouble(APR, APA, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.JacPointDoubleP256(APR, APA, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.JacPointDoubleP256(APR, APA, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryP256JacPointAdd(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.JacPointAddP256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.JacPointAddP256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryP256JacPointAddMixed(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.JacPointAddMixedP256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.JacPointAddMixedP256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryK256JacPointDouble(APR, APA, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.JacPointDoubleK256(APR, APA, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.JacPointDoubleK256(APR, APA, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryK256JacPointAdd(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.JacPointAddK256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.JacPointAddK256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryK256JacPointAddMixed(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.JacPointAddMixedK256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.JacPointAddMixedK256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelSimd.TryModAdd(APR, APA, APB, APCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.ModAdd(APR, APA, APB, APCtx);
  {$ELSE}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.ModAdd(APR, APA, APB, APCtx);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelSimd.TryModSub(APR, APA, APB, APCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.ModSub(APR, APA, APB, APCtx);
  {$ELSE}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.ModSub(APR, APA, APB, APCtx);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelSimd.TryGather(APDst, APTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TFpKernelX86Backend.IsSupported then
    Exit(False);
  Result := TFpKernelX86Backend.Gather(APDst, APTable, AEntryBytes, ACount, AIndex);
  {$ELSE}
  if not TFpKernelArmBackend.IsSupported then
    Exit(False);
  Result := TFpKernelArmBackend.Gather(APDst, APTable, AEntryBytes, ACount, AIndex);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
