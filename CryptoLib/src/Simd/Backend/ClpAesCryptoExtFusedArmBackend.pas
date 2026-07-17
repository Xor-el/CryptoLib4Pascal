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

unit ClpAesCryptoExtFusedArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIAesEngineArm,
  ClpCpuFeatures;

type
  /// <summary>
  /// ARM backend shared by the in-tree AES CryptoExt fused kernel factories:
  /// owns the CPU/build gate and the concrete <c>IAesEngineArm</c> resolution.
  /// Compiles on every target - <c>CpuSupports</c> is <c>False</c> off aarch64
  /// and <c>TryResolveEngine</c> then finds no engine.
  /// </summary>
  TAesCryptoExtFusedArmBackend = class sealed
  public
    /// <summary>True only when the build defines CRYPTOLIB_AARCH64_ASM and the
    /// CPU exposes both FEAT_AES and FEAT_PMULL (the fused GCM kernel runs
    /// aese and pmull; mirrors the x86 gate, which requires AESNI and
    /// PCLMULQDQ together).</summary>
    class function CpuSupports: Boolean; static;

    /// <summary>Probe ACipher for IAesEngineArm, handling both the direct case
    /// (ACipher itself is the engine) and the wrapped case (ACipher is an
    /// IBlockCipherMode whose UnderlyingCipher is the engine). AEngine is nil on False.</summary>
    class function TryResolveEngine(const ACipher: IBlockCipher;
      out AEngine: IAesEngineArm): Boolean; static;
  end;

implementation

{ TAesCryptoExtFusedArmBackend }

class function TAesCryptoExtFusedArmBackend.CpuSupports: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.HasAES() and TCpuFeatures.Arm.HasPMULL();
{$ELSE}
  Result := False;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

class function TAesCryptoExtFusedArmBackend.TryResolveEngine(const ACipher: IBlockCipher;
  out AEngine: IAesEngineArm): Boolean;
var
  LMode: IBlockCipherMode;
begin
  AEngine := nil;
  if ACipher = nil then
  begin
    Result := False;
    Exit;
  end;
  if Supports(ACipher, IAesEngineArm, AEngine) then
  begin
    Result := True;
    Exit;
  end;
  if Supports(ACipher, IBlockCipherMode, LMode) and (LMode <> nil) then
  begin
    Result := Supports(LMode.UnderlyingCipher, IAesEngineArm, AEngine);
    Exit;
  end;
  Result := False;
end;

end.
