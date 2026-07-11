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

unit ClpGhashSimd;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  , ClpGhashX86Backend
{$IFEND}
  ;

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for the GHASH / GF(2^128) field kernels
  /// behind <c>TGcmUtilities</c>. Selects the per-arch backend at compile time;
  /// on a build with no SIMD backend every entry point
  /// returns <c>False</c>, so the field operations run on their scalar reference
  /// path. <c>TGcmUtilities</c> calls only this facade and stays free of any
  /// <c>TCpuFeatures</c> / <c>CRYPTOLIB_*_ASM</c> knowledge.
  /// </summary>
  TGhashSimd = class sealed
  public
    /// <summary>Carryless multiply-reduce: <c>PX := PX * PY</c> in GF(2^128).</summary>
    class function TryMultiply(PX, PY: Pointer): Boolean; static;
    /// <summary>Carryless multiply to three 128-bit limbs (48 bytes).</summary>
    class function TryMultiplyExt(PX, PY, POut48: PByte): Boolean; static;
    /// <summary>Fold + reduce of three 128-bit limbs into one block.</summary>
    class function TryReduce3(PZ0, PZ1, PZ2, PSVector16: PByte): Boolean; static;
    /// <summary>Xor three 16-byte limbs with three slices of a 48-byte MultiplyExt output.</summary>
    class function TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte): Boolean; static;
    /// <summary>Fused 4-way GHASH over ABatchCount contiguous 64-byte batches.</summary>
    class function TryFusedFourShuffledGhash(PFS, PC0, PHPow64: PByte;
      ABatchCount: NativeInt): Boolean; static;
    /// <summary>Fused 8-way GHASH over ABatchCount contiguous 128-byte batches.</summary>
    class function TryFusedEightShuffledGhash(PFS, PC0, PHPow128: PByte;
      ABatchCount: NativeInt): Boolean; static;

    /// <summary>True when the shuffled/fused GHASH path (4-/8-way) is usable on this build/CPU. Gates the batch dispatch and the H-power precompute.</summary>
    class function IsShuffledGhashSupported: Boolean; static;
    /// <summary>True when a hardware carryless (polynomial) multiply is available (selects the carryless-multiply GCM multiplier over the 4K-table one).</summary>
    class function HasCarrylessMultiply: Boolean; static;
    /// <summary>Full byte-reverse of one 128-bit block from PSrc into PDst; False when unavailable.</summary>
    class function TryBlockReverse128(PDst, PSrc: PByte): Boolean; static;
  end;

implementation

{ TGhashSimd }

class function TGhashSimd.TryMultiply(PX, PY: Pointer): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryMultiply(PX, PY);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.TryMultiplyExt(PX, PY, POut48: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryMultiplyExt(PX, PY, POut48);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.TryReduce3(PZ0, PZ1, PZ2, PSVector16: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryReduce3(PZ0, PZ1, PZ2, PSVector16);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.TryFusedFourShuffledGhash(PFS, PC0, PHPow64: PByte;
  ABatchCount: NativeInt): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryFusedFourShuffledGhash(PFS, PC0, PHPow64, ABatchCount);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.TryFusedEightShuffledGhash(PFS, PC0, PHPow128: PByte;
  ABatchCount: NativeInt): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryFusedEightShuffledGhash(PFS, PC0, PHPow128, ABatchCount);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.IsShuffledGhashSupported: Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.IsShuffledGhashSupported;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.HasCarrylessMultiply: Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.HasCarrylessMultiply;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TGhashSimd.TryBlockReverse128(PDst, PSrc: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGhashX86Backend.TryBlockReverse128(PDst, PSrc);
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
