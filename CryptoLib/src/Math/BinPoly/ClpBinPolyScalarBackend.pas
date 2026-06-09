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

unit ClpBinPolyScalarBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBinPolyMul,
  ClpBinPolyScalarMedium,
  ClpBinPolyScalarLarge;

type
  /// <summary>
  /// Entry point for the scalar binary-polynomial multiply backend. Dispatches to
  /// <c>TBinPolyScalarMedium</c> for sub-cutoff sizes (direct schoolbook leaf) and
  /// <c>TBinPolyScalarLarge</c> for sizes at or above the Karatsuba cutoff.
  /// </summary>
  TBinPolyScalarBackend = class sealed
  public
    class function CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul; static;
  end;

implementation

{ TBinPolyScalarBackend }

class function TBinPolyScalarBackend.CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul;
var
  LSize: Int32;
begin
  LSize := (AN + 63) shr 6;
  if LSize < TBinPolyScalarLarge.KaratsubaCutoff then
    Result := TBinPolyScalarMedium.Create(AN, AReduce)
  else
    Result := TBinPolyScalarLarge.Create(AN, AReduce);
end;

end.
