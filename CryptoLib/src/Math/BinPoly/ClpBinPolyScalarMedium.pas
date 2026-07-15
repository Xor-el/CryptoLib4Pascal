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

unit ClpBinPolyScalarMedium;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase,
  ClpArrayUtilities;

type
  /// <summary>
  /// Scalar <c>IBinPolyMul</c> implementation for sizes below
  /// <c>TBinPolyScalarLarge.KaratsubaCutoff</c>: small enough that the schoolbook leaf beats a
  /// Karatsuba descent. <c>Multiply</c> is a single call to
  /// <c>TBinPolyScalarBackend.ImplMul</c> followed by reduction.
  /// </summary>
  TBinPolyScalarMedium = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

implementation

uses
  ClpBinPolyScalarBackend;

{ TBinPolyScalarMedium }

constructor TBinPolyScalarMedium.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyScalarMedium.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
begin
  SetLength(Ltt, FSizeExt);
  try
    TBinPolyScalarBackend.ImplMul(FSize, AX, AXOff, AY, AYOff, Ltt, 0);
    FReduce.Reduce(Ltt, 0, AZ, AZOff);
  finally
    TArrayUtilities.Fill(Ltt, 0, FSizeExt, 0);
  end;
end;

end.
