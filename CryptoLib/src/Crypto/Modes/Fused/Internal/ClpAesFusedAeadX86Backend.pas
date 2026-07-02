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

unit ClpAesFusedAeadX86Backend;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIAesEngineX86,
  ClpCpuFeatures,
  ClpIntrinsicsVector;

type
  /// <summary>
  /// x86 backend for the fused AES-NI AEAD pipeline: owns the CPU/build gate and
  /// the concrete <c>IAesEngineX86</c> resolution used by the in-tree AES-NI AEAD
  /// kernel factories. Compiles on every target - <c>CpuSupports</c> is
  /// <c>False</c> off x86 and <c>TryResolveEngine</c> then finds no engine.
  /// </summary>
  TAesFusedAeadX86Backend = class sealed
  public
    /// <summary>True only when the build defines CRYPTOLIB_X86_SIMD, the CPU
    /// exposes hardware AES + carryless multiply, and the SIMD intrinsics layout is packed.</summary>
    class function CpuSupports: Boolean; static;

    /// <summary>Probe ACipher for IAesEngineX86, handling both the direct case
    /// (ACipher itself is the engine) and the wrapped case (ACipher is an
    /// IBlockCipherMode whose UnderlyingCipher is the engine). AEngine is nil on False.</summary>
    class function TryResolveEngine(const ACipher: IBlockCipher;
      out AEngine: IAesEngineX86): Boolean; static;
  end;

implementation

{ TAesFusedAeadX86Backend }

class function TAesFusedAeadX86Backend.CpuSupports: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasAESNI and TCpuFeatures.X86.HasPCLMULQDQ and
    TCpuFeatures.X86.HasSSSE3 and TIntrinsicsVector.IsPacked;
{$ELSE}
  Result := False;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

class function TAesFusedAeadX86Backend.TryResolveEngine(const ACipher: IBlockCipher;
  out AEngine: IAesEngineX86): Boolean;
var
  LMode: IBlockCipherMode;
begin
  AEngine := nil;
  if ACipher = nil then
  begin
    Result := False;
    Exit;
  end;
  if Supports(ACipher, IAesEngineX86, AEngine) then
  begin
    Result := True;
    Exit;
  end;
  if Supports(ACipher, IBlockCipherMode, LMode) and (LMode <> nil) then
  begin
    Result := Supports(LMode.UnderlyingCipher, IAesEngineX86, AEngine);
    Exit;
  end;
  Result := False;
end;

end.
