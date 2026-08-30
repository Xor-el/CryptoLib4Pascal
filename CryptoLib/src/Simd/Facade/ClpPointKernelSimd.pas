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

unit ClpPointKernelSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpPointKernelX86Backend,
{$ENDIF}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpPointKernelArmBackend,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Arch-neutral facade over the fused special-prime kernels: the P-256
  /// special-prime Montgomery multiply/square and the fused P-256/secp256k1
  /// incomplete-Jacobian point operations. Each <c>Try*</c> returns <c>False</c>
  /// when no fast path applies (unsupported arch, a forced-scalar build, or a
  /// missing CPU feature); the caller then uses its generic per-op path.
  /// </summary>
  TPointKernelSimd = class sealed
  strict private
    class var FForceP256Disabled: Boolean;
  public
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
    /// <summary>Test gate: force the P-256 special kernel off so the generic CIOS runs
    /// (differential dual-path validation). Default False.</summary>
    class property ForceP256Disabled: Boolean read FForceP256Disabled write FForceP256Disabled;
  end;

implementation

{ TPointKernelSimd }

class function TPointKernelSimd.TryMontMulP256(APR, APA, APB, APCtx: PUInt64): Boolean;
begin
  if FForceP256Disabled then
    Exit(False);
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False); // force-scalar / no SIMD -> generic CIOS
  Result := TPointKernelX86Backend.MontMulP256(APR, APA, APB, APCtx); // False if no BMI2+ADX
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False); // force-scalar / no SIMD -> generic CIOS
  Result := TPointKernelArmBackend.MontMulP256(APR, APA, APB, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TPointKernelSimd.TryMontSqrP256(APR, APA, APCtx: PUInt64): Boolean;
begin
  if FForceP256Disabled then
    Exit(False);
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False); // force-scalar / no SIMD -> generic CIOS
  Result := TPointKernelX86Backend.MontSqrP256(APR, APA, APCtx); // False if no BMI2+ADX
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelSimd.TryP256JacPointDouble(APR, APA, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False);
  Result := TPointKernelX86Backend.JacPointDoubleP256(APR, APA, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False);
  Result := TPointKernelArmBackend.JacPointDoubleP256(APR, APA, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TPointKernelSimd.TryP256JacPointAdd(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False);
  Result := TPointKernelX86Backend.JacPointAddP256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False);
  Result := TPointKernelArmBackend.JacPointAddP256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TPointKernelSimd.TryP256JacPointAddMixed(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False);
  Result := TPointKernelX86Backend.JacPointAddMixedP256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False);
  Result := TPointKernelArmBackend.JacPointAddMixedP256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TPointKernelSimd.TryK256JacPointDouble(APR, APA, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False);
  Result := TPointKernelX86Backend.JacPointDoubleK256(APR, APA, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False);
  Result := TPointKernelArmBackend.JacPointDoubleK256(APR, APA, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TPointKernelSimd.TryK256JacPointAdd(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False);
  Result := TPointKernelX86Backend.JacPointAddK256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False);
  Result := TPointKernelArmBackend.JacPointAddK256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TPointKernelSimd.TryK256JacPointAddMixed(APScratch, APA, APQ, APCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TPointKernelX86Backend.IsSupported then
    Exit(False);
  Result := TPointKernelX86Backend.JacPointAddMixedK256(APScratch, APA, APQ, APCtx);
{$ELSE}
  {$IFDEF CRYPTOLIB_AARCH64_ASM}
  if not TPointKernelArmBackend.IsSupported then
    Exit(False);
  Result := TPointKernelArmBackend.JacPointAddMixedK256(APScratch, APA, APQ, APCtx);
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

end.
