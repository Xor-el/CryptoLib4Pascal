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

{ Platform + dispatch reporting shared by both constant-time drivers. The scalar-
  dispatch check is a CORRECTNESS gate, not banner text: if a hardware SIMD kernel
  (AES-NI, PCLMUL) is live, the tool would measure that instead of the software
  constant-time kernel and call the result a CT proof. Both drivers must agree on
  this, so it lives here rather than being copied per driver. }

unit CtPlatform;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

type
  TCtPlatform = record
  public
    // OS/CPU/compiler line for the run banner.
    class function PlatformInfo: string; static;
    // Human description of the active SIMD dispatch level; AIsScalar is the gate.
    class function DispatchDescription(out AIsScalar: Boolean): string; static;
    // True only when the software (scalar) crypto kernels are what will execute.
    class function ScalarDispatchActive: Boolean; static;
  end;

implementation

uses
  SysUtils
{$IF DEFINED(CPUX86_64) OR DEFINED(CPUI386)}
  , ClpSimdLevels, ClpX86SimdFeatures
{$ELSEIF DEFINED(CPUAARCH64) OR DEFINED(CPUARM)}
  , ClpSimdLevels, ClpArmSimdFeatures
{$ENDIF};

{ TCtPlatform }

class function TCtPlatform.PlatformInfo: string;
var
  LOS, LCPU: string;
begin
{$IF DEFINED(MSWINDOWS)}
  LOS := 'Windows';
{$ELSEIF DEFINED(LINUX)}
  LOS := 'Linux';
{$ELSEIF DEFINED(DARWIN)}
  LOS := 'macOS';
{$ELSE}
  LOS := 'Unknown OS';
{$ENDIF}
{$IF DEFINED(CPUX86_64)}
  LCPU := 'x86_64';
{$ELSEIF DEFINED(CPUI386)}
  LCPU := 'i386';
{$ELSEIF DEFINED(CPUAARCH64)}
  LCPU := 'AArch64';
{$ELSEIF DEFINED(CPUARM)}
  LCPU := 'ARM';
{$ELSE}
  LCPU := 'Unknown CPU';
{$ENDIF}
  Result := Format('Platform: %s %s, FPC %s', [LOS, LCPU, {$I %FPCVERSION%}]);
end;

class function TCtPlatform.DispatchDescription(out AIsScalar: Boolean): string;
{$IF DEFINED(CPUX86_64) OR DEFINED(CPUI386)}
var
  LLevel: TX86SimdLevel;
begin
  LLevel := TX86SimdFeatures.GetActiveSimdLevel();
  AIsScalar := LLevel = TX86SimdLevel.Scalar;
  case LLevel of
    TX86SimdLevel.Scalar: Result := 'x86 SIMD level = Scalar';
    TX86SimdLevel.SSE2: Result := 'x86 SIMD level = SSE2';
    TX86SimdLevel.SSE3: Result := 'x86 SIMD level = SSE3';
    TX86SimdLevel.SSSE3: Result := 'x86 SIMD level = SSSE3';
    TX86SimdLevel.SSE41: Result := 'x86 SIMD level = SSE4.1';
    TX86SimdLevel.SSE42: Result := 'x86 SIMD level = SSE4.2';
    TX86SimdLevel.AVX2: Result := 'x86 SIMD level = AVX2';
  else
    Result := 'x86 SIMD level = (unknown)';
  end;
end;
{$ELSEIF DEFINED(CPUAARCH64) OR DEFINED(CPUARM)}
var
  LLevel: TArmSimdLevel;
begin
  LLevel := TArmSimdFeatures.GetActiveSimdLevel();
  AIsScalar := LLevel = TArmSimdLevel.Scalar;
  case LLevel of
    TArmSimdLevel.Scalar: Result := 'ARM SIMD level = Scalar';
    TArmSimdLevel.NEON: Result := 'ARM SIMD level = NEON';
    TArmSimdLevel.SVE: Result := 'ARM SIMD level = SVE';
    TArmSimdLevel.SVE2: Result := 'ARM SIMD level = SVE2';
  else
    Result := 'ARM SIMD level = (unknown)';
  end;
end;
{$ELSE}
begin
  AIsScalar := True; // no SIMD crypto engines on this architecture
  Result := 'no SIMD engines on this architecture';
end;
{$ENDIF}

class function TCtPlatform.ScalarDispatchActive: Boolean;
var
  LDesc: string;
begin
  LDesc := DispatchDescription(Result);
end;

end.
