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

unit ClpItohTsujiiInv;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpInt32Utilities,
  ClpCryptoLibTypes,
  ClpIBinPolyMul;

type
  /// <summary>
  /// Itoh-Tsujii multiplicative inversion in GF(2^n): computes
  /// <c>a^{-1} = a^(2^n - 2) = (a^(2^(n-1) - 1))^2</c> using a generic binary addition chain
  /// on the exponent <c>e = n - 1</c>, driving the supplied <c>IBinPolyMul</c>'s
  /// <c>Multiply</c> / <c>Square</c> / <c>SquareN</c>.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Let <c>a_k = a^(2^k - 1)</c>. The chain walks the bits of <c>e = n - 1</c> from the bit
  /// below the MSB down to bit 0, applying a "double" step (<c>SquareN</c> then <c>Multiply</c>)
  /// and an "increment" step (<c>Square</c> then <c>Multiply</c>) when the bit is set.
  /// </para>
  /// <para>
  /// The element value never steers control flow: 0 and 1 are fixed points of the primitives,
  /// so <c>Invert(0) = 0</c> and <c>Invert(1) = 1</c> fall out of the unconditional chain
  /// with no special case. Correct only for an irreducible reduction polynomial — see
  /// <c>IBinPolyInv</c>.
  /// </para>
  /// </remarks>
  TItohTsujiiInv = class sealed(TInterfacedObject, IBinPolyInv)
  private
    FMul: IBinPolyMul;
    FN: Int32;
    FSize: Int32;
    {$IFDEF DEBUG}
    procedure DebugAssertInverse(const Aa: TCryptoLibUInt64Array; AaOff: Int32;
      const Ab: TCryptoLibUInt64Array);
    {$ENDIF}
  public
    constructor Create(const AMul: IBinPolyMul);
    function GetN: Int32;
    function GetSize: Int32;
    procedure Invert(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    property N: Int32 read GetN;
    property Size: Int32 read GetSize;
  end;

implementation

uses
  ClpBinPolys;

{ TItohTsujiiInv }

constructor TItohTsujiiInv.Create(const AMul: IBinPolyMul);
begin
  inherited Create;
{$IFDEF DEBUG}
  System.Assert(AMul.N >= 2);
{$ENDIF}
  FMul := AMul;
  FN := AMul.N;
  FSize := AMul.Size;
end;

function TItohTsujiiInv.GetN: Int32;
begin
  Result := FN;
end;

function TItohTsujiiInv.GetSize: Int32;
begin
  Result := FSize;
end;

procedure TItohTsujiiInv.Invert(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Lb: TCryptoLibUInt64Array;
  Lt: TCryptoLibUInt64Array;
  Ln: Int32;
  LSize: Int32;
  Le: Int32;
  Lj: Int32;
  LI: Int32;
begin
  Ln := FN;
  LSize := FSize;

  SetLength(Lb, LSize);
  SetLength(Lt, LSize);
  try
    TBinPolys.Copy(LSize, AX, AXOff, Lb, 0);

    Le := Ln - 1;
    Lj := 1;
    for LI := TInt32Utilities.BitLength(Le) - 2 downto 0 do
    begin
      FMul.SquareN(Lb, 0, Lj, Lt, 0);
      FMul.Multiply(Lb, 0, Lt, 0, Lb, 0);
      Lj := Lj shl 1;

      if (Le and (1 shl LI)) <> 0 then
      begin
        FMul.Square(Lb, 0, Lb, 0);
        FMul.Multiply(Lb, 0, AX, AXOff, Lb, 0);
        System.Inc(Lj);
      end;
    end;
{$IFDEF DEBUG}
    System.Assert(Lj = Le);
    DebugAssertInverse(AX, AXOff, Lb);
{$ENDIF}
    FMul.Square(Lb, 0, AZ, AZOff);
  finally
    TBinPolys.Clear(LSize, Lb, 0);
    TBinPolys.Clear(LSize, Lt, 0);
  end;
end;

{$IFDEF DEBUG}
procedure TItohTsujiiInv.DebugAssertInverse(const Aa: TCryptoLibUInt64Array; AaOff: Int32;
  const Ab: TCryptoLibUInt64Array);
var
  LProduct: TCryptoLibUInt64Array;
  LOk: Boolean;
begin
  SetLength(LProduct, FSize);
  try
    FMul.Square(Ab, 0, LProduct, 0);
    FMul.Multiply(LProduct, 0, Aa, AaOff, LProduct, 0);

    if TBinPolys.EqualToZero(FSize, Aa, AaOff) <> 0 then
      LOk := TBinPolys.EqualToZero(FSize, LProduct, 0) <> 0
    else
      LOk := TBinPolys.EqualToOne(FSize, LProduct, 0) <> 0;

    System.Assert(LOk, 'Itoh-Tsujii inverse self-check failed');
  finally
    TBinPolys.Clear(FSize, LProduct, 0);
  end;
end;
{$ENDIF}

end.
