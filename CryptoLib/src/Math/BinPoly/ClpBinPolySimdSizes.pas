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

unit ClpBinPolySimdSizes;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase;

type
  /// <summary>
  /// Shared base for the SIMD <c>IBinPolyMul</c> classes: squaring expands via
  /// one carryless multiply of each limb with itself (a GF(2)[x] square IS the
  /// bit interleave) instead of the scalar shuffle-based expansion.
  /// </summary>
  TBinPolySimdMulBase = class abstract(TBinPolyMulBase)
  protected
    procedure ExpandSquare(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      Att: PUInt64); override;
  end;

  TBinPolySimdSize1 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize2 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize3 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize4 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize5 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize6 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize7 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize8 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize9 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolySimdSize10 = class sealed(TBinPolySimdMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

implementation

uses
  ClpBinPolySimd;

{ TBinPolySimdMulBase }

procedure TBinPolySimdMulBase.ExpandSquare(const AX: TCryptoLibUInt64Array;
  AXOff: Int32; Att: PUInt64);
begin
  TBinPolySimd.ImplSquare(FSize, @AX[AXOff], Att);
end;

procedure MultiplySmallFixed(ASmallLen: Int32; const AReduce: IBinPolyReduce; ASizeExt: Int32;
  const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: array [0 .. 19] of UInt64; // ASizeExt <= 20 for limb counts 1..10
begin
  try
    TBinPolySimd.ImplMulSmall(ASmallLen, @AX[AXOff], @AY[AYOff], @Ltt[0]);
    AReduce.Reduce(@Ltt[0], @AZ[AZOff]);
  finally
    FillChar(Ltt, System.SizeOf(Ltt), 0);
  end;
end;

{ TBinPolySimdSize1 }

constructor TBinPolySimdSize1.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize1.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(1, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize2 }

constructor TBinPolySimdSize2.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize2.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(2, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize3 }

constructor TBinPolySimdSize3.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize3.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(3, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize4 }

constructor TBinPolySimdSize4.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize4.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(4, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize5 }

constructor TBinPolySimdSize5.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize5.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(5, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize6 }

constructor TBinPolySimdSize6.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize6.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(6, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize7 }

constructor TBinPolySimdSize7.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize7.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(7, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize8 }

constructor TBinPolySimdSize8.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize8.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(8, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize9 }

constructor TBinPolySimdSize9.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize9.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(9, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolySimdSize10 }

constructor TBinPolySimdSize10.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolySimdSize10.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(10, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

end.
