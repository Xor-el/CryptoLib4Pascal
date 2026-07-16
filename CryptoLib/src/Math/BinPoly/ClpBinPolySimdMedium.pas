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

unit ClpBinPolySimdMedium;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase,
  ClpBinPolySimdSizes,
  ClpArrayUtilities;

type
  /// <summary>
  /// SIMD <c>IBinPolyMul</c> for even limb counts in (10, <c>KaratsubaCutoff</c>).
  /// </summary>
  TBinPolySimdMediumEven = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  /// <summary>
  /// SIMD <c>IBinPolyMul</c> for odd limb counts in (10, <c>KaratsubaCutoff</c>).
  /// </summary>
  TBinPolySimdMediumOdd = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

implementation

uses
  ClpBinPolySimd;

{ TBinPolySimdMediumEven }

constructor TBinPolySimdMediumEven.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
{$IFDEF DEBUG}
  System.Assert((FSize and 1) = 0);
  System.Assert((FSize > 10) and (FSize < 32));
{$ENDIF}
end;

procedure TBinPolySimdMediumEven.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: array [0 .. TBinPolyMulBase.MaxStackExtLimbs - 1] of UInt64; // FSizeExt <= 62 here
begin
  try
    TBinPolySimd.ImplMulEven(FSize, @AX[AXOff], @AY[AYOff], @Ltt[0]);
    FReduce.Reduce(@Ltt[0], @AZ[AZOff]);
  finally
    FillChar(Ltt, FSizeExt * System.SizeOf(UInt64), 0);
  end;
end;

{ TBinPolySimdMediumOdd }

constructor TBinPolySimdMediumOdd.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
{$IFDEF DEBUG}
  System.Assert((FSize and 1) = 1);
  System.Assert((FSize > 10) and (FSize < 32));
{$ENDIF}
end;

procedure TBinPolySimdMediumOdd.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: array [0 .. TBinPolyMulBase.MaxStackExtLimbs - 1] of UInt64; // FSizeExt <= 62 here
begin
  try
    TBinPolySimd.ImplMulOdd(FSize, @AX[AXOff], @AY[AYOff], @Ltt[0]);
    FReduce.Reduce(@Ltt[0], @AZ[AZOff]);
  finally
    FillChar(Ltt, FSizeExt * System.SizeOf(UInt64), 0);
  end;
end;

end.
