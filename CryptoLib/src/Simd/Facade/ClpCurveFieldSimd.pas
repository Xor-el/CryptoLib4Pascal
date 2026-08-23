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
  /// Force-tier gate for the fe64 (radix-2^64 ADX) curve25519 dispatch. When
  /// ForceDisabled is True, Fe64Supported returns False and every fe64 path routes
  /// through the fe51 kernel / Pascal fallback. Used by the dual-path test harness
  /// to prove the tiers agree byte-for-byte on an ADX host.
  /// </summary>
  TCurveFieldGate = class sealed(TObject)
  strict private
    class var FForceDisabled: Boolean;
    class var FForceAdx32Disabled: Boolean;
  public
    class property ForceDisabled: Boolean read FForceDisabled write FForceDisabled;
    // Sub-tier gate for the i386 radix-2^32 ADX curve25519 kernel: when True the
    // fe51 per-op path uses the plain-mul kernel. Lets the dual-path test prove
    // the two i386 kernels agree, and the bench compare them.
    class property ForceAdx32Disabled: Boolean
      read FForceAdx32Disabled write FForceAdx32Disabled;
  end;

  /// <summary>
  /// Arch-neutral facade over the curve25519 (radix-2^51) and curve448
  /// (radix-2^56) field multiply/square kernels. Each <c>Try*</c> runs the
  /// fully-reduced field operation over the packed 64-bit limbs and returns
  /// <c>False</c> when no kernel applies (unsupported arch or a forced-scalar
  /// build); the caller then uses its Pascal fallback.
  /// </summary>
  TCurveFieldSimd = class sealed
  public
    /// <summary>APH := APF * APG (mod 2^255-19), five 64-bit limbs each.</summary>
    class function TryMul25519(APF, APG, APH: PUInt64): Boolean; static; inline;
    /// <summary>APZ := APX^2 (mod 2^255-19), five 64-bit limbs.</summary>
    class function TrySqr25519(APX, APZ: PUInt64): Boolean; static; inline;

    /// <summary>Whether the i386 radix-2^32 ADX curve25519 kernel applies (i386
    /// with BMI2 + ADX, and its sub-tier gate is not disabling it).</summary>
    class function Adx32Supported: Boolean; static; inline;
    /// <summary>APH := APF * APG (mod 2^448-2^224-1), eight 64-bit limbs each.</summary>
    class function TryMul448(APF, APG, APH: PUInt64): Boolean; static; inline;
    /// <summary>APZ := APX^2 (mod 2^448-2^224-1), eight 64-bit limbs.</summary>
    class function TrySqr448(APX, APZ: PUInt64): Boolean; static; inline;

    /// <summary>Whether the radix-2^64 ADX curve25519 tier applies (x86-64 with
    /// BMI2 + ADX, and the force-tier gate is not disabling it).</summary>
    class function Fe64Supported: Boolean; static; inline;
    /// <summary>Radix-2^64 (4-limb) mod (2^255-19). Each returns False when the
    /// fe64 tier does not apply; the caller falls back.</summary>
    class function TryFe64Mul25519(APF, APG, APH: PUInt64): Boolean; static; inline;
    class function TryFe64Sqr25519(APX, APZ: PUInt64): Boolean; static; inline;
    class function TryFe64Add(APA, APB, APR: PUInt64): Boolean; static; inline;
    class function TryFe64Sub(APA, APB, APR: PUInt64): Boolean; static; inline;
    class function TryFe64Mul121666(APF, APH: PUInt64): Boolean; static; inline;
    class function TryFe64SqrN(APF, APH: PUInt64; AN: NativeInt): Boolean; static; inline;
    /// <summary>One Montgomery ladder step + cswap over APState = (x1,x2,z2,x3,z3),
    /// four 64-bit limbs each; AMask is 0 or all-ones.</summary>
    class function TryFe64LadderStep25519(APState: PUInt64; AMask: UInt64): Boolean; static; inline;
  end;

implementation

class function TCurveFieldSimd.Adx32Supported: Boolean;
begin
  if TCurveFieldGate.ForceAdx32Disabled then
    Exit(False);
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCurveFieldX86Backend.Adx32Supported;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldSimd.TryMul25519(APF, APG, APH: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
  if Adx32Supported then
    Result := TCurveFieldX86Backend.Adx32Mul25519(APF, APG, APH)
  else
    Result := TCurveFieldX86Backend.Mul25519(APF, APG, APH);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then
    Exit(False);
  Result := TCurveFieldArmBackend.Mul25519(APF, APG, APH);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TrySqr25519(APX, APZ: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
  if Adx32Supported then
    Result := TCurveFieldX86Backend.Adx32Sqr25519(APX, APZ)
  else
    Result := TCurveFieldX86Backend.Sqr25519(APX, APZ);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then
    Exit(False);
  Result := TCurveFieldArmBackend.Sqr25519(APX, APZ);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryMul448(APF, APG, APH: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
  Result := TCurveFieldX86Backend.Mul448(APF, APG, APH);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then
    Exit(False);
  Result := TCurveFieldArmBackend.Mul448(APF, APG, APH);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TrySqr448(APX, APZ: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
  Result := TCurveFieldX86Backend.Sqr448(APX, APZ);
  {$ELSE}
  if not TCurveFieldArmBackend.IsSupported then
    Exit(False);
  Result := TCurveFieldArmBackend.Sqr448(APX, APZ);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.Fe64Supported: Boolean;
begin
  if TCurveFieldGate.ForceDisabled then
    Exit(False);
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCurveFieldX86Backend.Fe64Supported;
  {$ELSE}
  Result := TCurveFieldArmBackend.Fe64Supported;
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64Mul25519(APF, APG, APH: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64Mul25519(APF, APG, APH);
  {$ELSE}
  TCurveFieldArmBackend.Fe64Mul25519(APF, APG, APH);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64Sqr25519(APX, APZ: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64Sqr25519(APX, APZ);
  {$ELSE}
  TCurveFieldArmBackend.Fe64Sqr25519(APX, APZ);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64Add(APA, APB, APR: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64Add(APA, APB, APR);
  {$ELSE}
  TCurveFieldArmBackend.Fe64Add(APA, APB, APR);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64Sub(APA, APB, APR: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64Sub(APA, APB, APR);
  {$ELSE}
  TCurveFieldArmBackend.Fe64Sub(APA, APB, APR);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64Mul121666(APF, APH: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64Mul121666(APF, APH);
  {$ELSE}
  TCurveFieldArmBackend.Fe64Mul121666(APF, APH);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64SqrN(APF, APH: PUInt64; AN: NativeInt): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64SqrN(APF, APH, AN);
  {$ELSE}
  TCurveFieldArmBackend.Fe64SqrN(APF, APH, AN);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TCurveFieldSimd.TryFe64LadderStep25519(APState: PUInt64; AMask: UInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  if not Fe64Supported then
    Exit(False);
  {$IFDEF CRYPTOLIB_X86_SIMD}
  TCurveFieldX86Backend.Fe64LadderStep25519(APState, AMask);
  {$ELSE}
  TCurveFieldArmBackend.Fe64LadderStep25519(APState, AMask);
  {$ENDIF}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
