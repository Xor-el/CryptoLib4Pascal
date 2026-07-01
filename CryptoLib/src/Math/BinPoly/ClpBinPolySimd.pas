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

unit ClpBinPolySimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBinPolyMul
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  , ClpBinPolyX86V128Backend
{$ELSEIF DEFINED(CRYPTOLIB_ARM_SIMD)}
  , ClpBinPolyArmV128Backend
{$IFEND}
  ;

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for binary-polynomial multiplication.
  /// SIMD-only by contract: it produces the per-arch SIMD multiplier
  /// when available, or reports "not handled" - it never
  /// returns the portable scalar backend. The scalar fallback belongs to the
  /// caller (<c>TBinPolys</c>), matching the Try*-then-scalar shape used across
  /// the other SIMD families. Selects the per-arch backend at compile time.
  /// </summary>
  TBinPolySimd = class sealed
  public
    /// <summary>
    /// Build a SIMD <c>IBinPolyMul</c> for degree <paramref name="AN"/> under the
    /// given reduction when a SIMD backend is available (returns True with
    /// <paramref name="AMul"/> set); otherwise <paramref name="AMul"/> is nil and
    /// the caller runs its scalar path (returns False).
    /// </summary>
    class function TryCreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce;
      out AMul: IBinPolyMul): Boolean; static;
  end;

implementation

{ TBinPolySimd }

class function TBinPolySimd.TryCreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce;
  out AMul: IBinPolyMul): Boolean;
begin
  AMul := nil;
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if TBinPolyX86V128Backend.IsSupported then
  begin
    AMul := TBinPolyX86V128Backend.CreateBinPolyMul(AN, AReduce);
    Exit(True);
  end;
{$ELSEIF DEFINED(CRYPTOLIB_ARM_SIMD)}
  if TBinPolyArmV128Backend.IsSupported then
  begin
    AMul := TBinPolyArmV128Backend.CreateBinPolyMul(AN, AReduce);
    Exit(True);
  end;
{$IFEND}
  Result := False;
end;

end.
