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
  /// Arch-neutral facade over the radix-2^51 curve25519 field multiply/square
  /// kernels. Each <c>Try*</c> runs the fully-reduced field operation over five
  /// 64-bit limbs and returns <c>False</c> when no kernel applies (unsupported
  /// arch or a forced-scalar build); the caller then uses its Pascal fallback.
  /// </summary>
  TCurveFieldSimd = class sealed
  public
    /// <summary>APH := APF * APG (mod 2^255-19), five 64-bit limbs each.</summary>
    class function TryMul25519(APF, APG, APH: PUInt64): Boolean; static; inline;
    /// <summary>APZ := APX^2 (mod 2^255-19), five 64-bit limbs.</summary>
    class function TrySqr25519(APX, APZ: PUInt64): Boolean; static; inline;
  end;

implementation

class function TCurveFieldSimd.TryMul25519(APF, APG, APH: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TCurveFieldX86Backend.IsSupported then
    Exit(False);
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

end.
