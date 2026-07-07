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

unit ClpBinPolyX86V128Medium;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase,
  ClpArrayUtilities,
  ClpBinPolyX86V128Kernels;

type
  /// <summary>
  /// x86/V128 <c>IBinPolyMul</c> for even limb counts in (10, <c>KaratsubaCutoff</c>).
  /// </summary>
  TBinPolyX86V128MediumEven = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  /// <summary>
  /// x86/V128 <c>IBinPolyMul</c> for odd limb counts in (10, <c>KaratsubaCutoff</c>).
  /// </summary>
  TBinPolyX86V128MediumOdd = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

implementation

{ TBinPolyX86V128MediumEven }

constructor TBinPolyX86V128MediumEven.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
{$IFDEF DEBUG}
  System.Assert((FSize and 1) = 0);
  System.Assert((FSize > 10) and (FSize < 32));
{$ENDIF}
end;

procedure TBinPolyX86V128MediumEven.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
begin
  SetLength(Ltt, FSizeExt);
  try
    TBinPolyX86V128Kernels.ImplMulEven(FSize, AX, AXOff, AY, AYOff, Ltt, 0);
    FReduce.Reduce(Ltt, 0, AZ, AZOff);
  finally
    TArrayUtilities.Fill(Ltt, 0, FSizeExt, 0);
  end;
end;

{ TBinPolyX86V128MediumOdd }

constructor TBinPolyX86V128MediumOdd.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
{$IFDEF DEBUG}
  System.Assert((FSize and 1) = 1);
  System.Assert((FSize > 10) and (FSize < 32));
{$ENDIF}
end;

procedure TBinPolyX86V128MediumOdd.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
begin
  SetLength(Ltt, FSizeExt);
  try
    TBinPolyX86V128Kernels.ImplMulOdd(FSize, AX, AXOff, AY, AYOff, Ltt, 0);
    FReduce.Reduce(Ltt, 0, AZ, AZOff);
  finally
    TArrayUtilities.Fill(Ltt, 0, FSizeExt, 0);
  end;
end;

end.
