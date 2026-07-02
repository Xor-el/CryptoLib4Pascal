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

unit ClpPoly1305Simd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpPoly1305State,
  ClpCryptoLibTypes
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  , ClpPoly1305X86Backend
{$IFEND}
  ;

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for Poly1305. Selects the per-arch
  /// backend at compile time; on a build with no SIMD
  /// backend <c>TryInitPowerTable</c> returns False and <c>ProcessBulk</c>
  /// consumes zero blocks, so the MAC runs entirely on its scalar reference
  /// path. The Poly1305 MAC calls only this facade and stays free of any
  /// <c>TCpuFeatures</c> / <c>CRYPTOLIB_*_ASM</c> knowledge.
  /// </summary>
  TPoly1305Simd = class sealed
  public
    /// <summary>
    /// If a SIMD tier is available, build the per-key power table into
    /// <paramref name="APowTable"/> and return True; otherwise leave it
    /// untouched and return False (the nil-ness of the caller's table then
    /// doubles as the "scalar path" dispatch flag).
    /// </summary>
    class function TryInitPowerTable(var APowTable: TCryptoLibByteArray;
      const AState: TPoly1305State): Boolean; static;
    /// <summary>
    /// Process the leading lane-multiple of <paramref name="ANumBlocks"/> blocks
    /// with SIMD and return how many blocks were consumed (0 when no SIMD path
    /// applies); the caller processes the remainder on its scalar path.
    /// </summary>
    class function ProcessBulk(var AState: TPoly1305State; APowTable: PByte;
      const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32): Int32; static;
  end;

implementation

{ TPoly1305Simd }

class function TPoly1305Simd.TryInitPowerTable(var APowTable: TCryptoLibByteArray;
  const AState: TPoly1305State): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TPoly1305X86Backend.TryInitPowerTable(APowTable, AState);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TPoly1305Simd.ProcessBulk(var AState: TPoly1305State; APowTable: PByte;
  const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32): Int32;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TPoly1305X86Backend.ProcessBulk(AState, APowTable, ABuf, AOff, ANumBlocks);
{$ELSE}
  Result := 0;
{$IFEND}
end;

end.
