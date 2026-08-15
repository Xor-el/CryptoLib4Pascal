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

unit ClpCurveFieldSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpCurveFieldX86Backend,
{$ENDIF}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpCurveFieldArmBackend,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Arch-neutral facade over the reduced-radix curve field (RFC 7748/8032)
  /// multiply/square kernels. The X25519/Ed25519 field is radix-2^25.5 (ten
  /// signed Int32 limbs); the X448/Ed448 field is radix-2^28 (sixteen signed
  /// Int32 limbs). Each <c>Try*</c> runs the fully-reduced field operation and
  /// returns <c>False</c> when no fast path applies (unsupported arch or a
  /// forced-scalar build); the caller then uses its existing Pascal path.
  /// </summary>
  TCurveFieldSimd = class sealed
  public
    /// <summary>AH := AF * AG (mod 2^255-19), ten signed Int32 limbs each.</summary>
    class function TryMul25519(const AF, AG, AH: TCryptoLibInt32Array): Boolean; static;
    /// <summary>AZ := AX^2 (mod 2^255-19), ten signed Int32 limbs.</summary>
    class function TrySqr25519(const AX, AZ: TCryptoLibInt32Array): Boolean; static;
    /// <summary>AZ := AX + AY (unreduced), ten Int32 limbs.</summary>
    class function TryAdd25519(const AX, AY, AZ: TCryptoLibInt32Array): Boolean; static;
    /// <summary>AZ := AX - AY (unreduced), ten Int32 limbs.</summary>
    class function TrySub25519(const AX, AY, AZ: TCryptoLibInt32Array): Boolean; static;
    /// <summary>AZp := AX+AY; AZm := AX-AY (unreduced), ten Int32 limbs.</summary>
    class function TryApm25519(const AX, AY, AZp, AZm: TCryptoLibInt32Array): Boolean; static;
    /// <summary>Constant-time conditional swap of AA and AB when ASwap=1.</summary>
    class function TryCSwap25519(ASwap: Int32; const AA, AB: TCryptoLibInt32Array): Boolean; static;
    /// <summary>AZ := carry-propagated AZ (radix-2^25.5 reduce).</summary>
    class function TryCarry25519(const AZ: TCryptoLibInt32Array): Boolean; static;
    /// <summary>AZ := AX * AY (mod 2^255-19), AY a small signed scalar.</summary>
    class function TryMulWord25519(const AX: TCryptoLibInt32Array; AY: Int32;
      const AZ: TCryptoLibInt32Array): Boolean; static;
  end;

implementation

{ TCurveFieldSimd }

class function TCurveFieldSimd.TryMul25519(const AF, AG, AH: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
  TCurveFieldX86Backend.Mul25519(@AF[0], @AG[0], @AH[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then
    Exit(False);
  TCurveFieldArmBackend.Mul25519(@AF[0], @AG[0], @AH[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TrySqr25519(const AX, AZ: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
  TCurveFieldX86Backend.Sqr25519(@AX[0], @AZ[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then
    Exit(False);
  TCurveFieldArmBackend.Sqr25519(@AX[0], @AZ[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryAdd25519(const AX, AY, AZ: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then Exit(False);
  TCurveFieldX86Backend.Add25519(@AX[0], @AY[0], @AZ[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then Exit(False);
  TCurveFieldArmBackend.Add25519(@AX[0], @AY[0], @AZ[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TrySub25519(const AX, AY, AZ: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then Exit(False);
  TCurveFieldX86Backend.Sub25519(@AX[0], @AY[0], @AZ[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then Exit(False);
  TCurveFieldArmBackend.Sub25519(@AX[0], @AY[0], @AZ[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryApm25519(const AX, AY, AZp, AZm: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then Exit(False);
  TCurveFieldX86Backend.Apm25519(@AX[0], @AY[0], @AZp[0], @AZm[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then Exit(False);
  TCurveFieldArmBackend.Apm25519(@AX[0], @AY[0], @AZp[0], @AZm[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryCSwap25519(ASwap: Int32; const AA, AB: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then Exit(False);
  TCurveFieldX86Backend.CSwap25519(ASwap, @AA[0], @AB[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then Exit(False);
  TCurveFieldArmBackend.CSwap25519(ASwap, @AA[0], @AB[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryCarry25519(const AZ: TCryptoLibInt32Array): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then Exit(False);
  TCurveFieldX86Backend.Carry25519(@AZ[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then Exit(False);
  TCurveFieldArmBackend.Carry25519(@AZ[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryMulWord25519(const AX: TCryptoLibInt32Array;
  AY: Int32; const AZ: TCryptoLibInt32Array): Boolean;
begin
  // MulWord asm on all three arches.
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then Exit(False);
  TCurveFieldX86Backend.MulWord25519(@AX[0], AY, @AZ[0]);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then Exit(False);
  TCurveFieldArmBackend.MulWord25519(@AX[0], AY, @AZ[0]);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
