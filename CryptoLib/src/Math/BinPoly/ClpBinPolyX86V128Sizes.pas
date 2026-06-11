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

unit ClpBinPolyX86V128Sizes;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase,
  ClpArrayUtilities,
  ClpBinPolyX86V128Kernels;

type
  TBinPolyX86V128Size1 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size2 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size3 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size4 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size5 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size6 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size7 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size8 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size9 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

  TBinPolyX86V128Size10 = class sealed(TBinPolyMulBase)
  public
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

implementation

procedure MultiplySmallFixed(ASmallLen: Int32; const AReduce: IBinPolyReduce; ASizeExt: Int32;
  const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
begin
  SetLength(Ltt, ASizeExt);
  try
    TBinPolyX86V128Kernels.ImplMulSmall(ASmallLen, AX, AXOff, AY, AYOff, Ltt, 0);
    AReduce.Reduce(Ltt, 0, AZ, AZOff);
  finally
    TArrayUtilities.Fill<UInt64>(Ltt, 0, ASizeExt, 0);
  end;
end;

{ TBinPolyX86V128Size1 }

constructor TBinPolyX86V128Size1.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size1.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(1, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size2 }

constructor TBinPolyX86V128Size2.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size2.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(2, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size3 }

constructor TBinPolyX86V128Size3.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size3.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(3, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size4 }

constructor TBinPolyX86V128Size4.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size4.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(4, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size5 }

constructor TBinPolyX86V128Size5.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size5.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(5, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size6 }

constructor TBinPolyX86V128Size6.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size6.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(6, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size7 }

constructor TBinPolyX86V128Size7.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size7.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(7, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size8 }

constructor TBinPolyX86V128Size8.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size8.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(8, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size9 }

constructor TBinPolyX86V128Size9.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size9.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(9, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

{ TBinPolyX86V128Size10 }

constructor TBinPolyX86V128Size10.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyX86V128Size10.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  MultiplySmallFixed(10, FReduce, FSizeExt, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

end.
