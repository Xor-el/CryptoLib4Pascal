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

unit ClpCTScalarField;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpNat,
  ClpCTFieldValue,
  ClpCTFieldArith,
  ClpIScalarFieldOps,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Generic constant-time scalar-field (mod n) arithmetic over the value-type
  /// Montgomery kernel. <c>TOps</c> supplies the order-domain constants (its
  /// <c>MontParams</c> built from n); every operation is fixed-width and the
  /// nonce inversion is a public-exponent Montgomery ladder (Fermat, so
  /// constant-time in the secret operand). See <see cref="IScalarFieldOps"/>.
  /// </summary>
  TCTScalarField<TOps: TCTFieldArithBase> = class(TInterfacedObject, IScalarFieldOps)
  strict private
    FLimbs: Int32;
    FNm2: TCryptoLibUInt32Array; // n-2, exponent for the Fermat inverse
    FNm2Bits: Int32;
    procedure BigToFe(const AX: TBigInteger; out AZ: TFe);
    function FeToBig(const AX: TFe): TBigInteger;
    // AZ := AXMont^(n-2) in the Montgomery domain (AXMont is x*R mod n)
    procedure MontInv(const AXMont: TFe; out AZ: TFe);
  public
    constructor Create(const AOrder: TBigInteger);
    function InvModN(const AX: TBigInteger): TBigInteger;
    function MulModN(const AX, AY: TBigInteger): TBigInteger;
    function AddModN(const AX, AY: TBigInteger): TBigInteger;
    function ComputeS(const AK, AE, AD, AR: TBigInteger): TBigInteger;
  end;

implementation

{ TCTScalarField<TOps> }

constructor TCTScalarField<TOps>.Create(const AOrder: TBigInteger);
var
  LNm2: TBigInteger;
begin
  Inherited Create;
  FLimbs := TOps.FieldLimbs;
  LNm2 := AOrder.Subtract(TBigInteger.Two);
  FNm2 := TNat.FromBigInteger(FLimbs * 32, LNm2);
  FNm2Bits := LNm2.BitLength;
end;

procedure TCTScalarField<TOps>.BigToFe(const AX: TBigInteger; out AZ: TFe);
begin
  TOps.ArrToFe(TNat.FromBigInteger(FLimbs * 32, AX), FLimbs, AZ);
end;

function TCTScalarField<TOps>.FeToBig(const AX: TFe): TBigInteger;
var
  LArr: TCryptoLibUInt32Array;
begin
  LArr := TNat.Create(FLimbs);
  Move(AX.W[0], LArr[0], FLimbs * SizeOf(UInt32));
  Result := TNat.ToBigInteger(FLimbs, LArr);
end;

procedure TCTScalarField<TOps>.MontInv(const AXMont: TFe; out AZ: TFe);
var
  LAcc: TFe;
  LTT: TFeExt;
  LI: Int32;
begin
  // square-and-multiply over the public exponent n-2; secret operand only ever
  // flows through the constant-time Montgomery multiply
  TOps.SetOne(LAcc);
  for LI := FNm2Bits - 1 downto 0 do
  begin
    TOps.Mul(LAcc, LAcc, LAcc, LTT);
    if ((FNm2[LI shr 5] shr (LI and 31)) and 1) = 1 then
      TOps.Mul(LAcc, AXMont, LAcc, LTT);
  end;
  AZ := LAcc;
end;

function TCTScalarField<TOps>.InvModN(const AX: TBigInteger): TBigInteger;
var
  LXm, LInv: TFe;
  LTT: TFeExt;
begin
  BigToFe(AX, LXm);
  TOps.ToMont(LXm, LXm, LTT);
  MontInv(LXm, LInv);
  TOps.FromMont(LInv, LInv, LTT);
  Result := FeToBig(LInv);
end;

function TCTScalarField<TOps>.MulModN(const AX, AY: TBigInteger): TBigInteger;
var
  LXm, LY, LZ: TFe;
  LTT: TFeExt;
begin
  BigToFe(AX, LXm);
  BigToFe(AY, LY);
  TOps.ToMont(LXm, LXm, LTT);   // x*R
  TOps.Mul(LXm, LY, LZ, LTT);   // x*R*y*R^-1 = x*y
  Result := FeToBig(LZ);
end;

function TCTScalarField<TOps>.AddModN(const AX, AY: TBigInteger): TBigInteger;
var
  LX, LY, LZ: TFe;
begin
  BigToFe(AX, LX);
  BigToFe(AY, LY);
  TOps.Add(LX, LY, LZ);
  Result := FeToBig(LZ);
end;

function TCTScalarField<TOps>.ComputeS(const AK, AE, AD, AR: TBigInteger): TBigInteger;
var
  LKm, LEm, LDm, LRm, LInv, LT: TFe;
  LTT: TFeExt;
begin
  BigToFe(AK, LKm); TOps.ToMont(LKm, LKm, LTT);
  MontInv(LKm, LInv);                    // (k^-1) in Montgomery
  BigToFe(AE, LEm); TOps.ToMont(LEm, LEm, LTT);
  BigToFe(AD, LDm); TOps.ToMont(LDm, LDm, LTT);
  BigToFe(AR, LRm); TOps.ToMont(LRm, LRm, LTT);
  TOps.Mul(LDm, LRm, LT, LTT);           // d*r
  TOps.Add(LEm, LT, LT);                 // e + d*r
  TOps.Mul(LInv, LT, LT, LTT);           // k^-1 * (e + d*r)
  TOps.FromMont(LT, LT, LTT);
  Result := FeToBig(LT);
end;

end.
