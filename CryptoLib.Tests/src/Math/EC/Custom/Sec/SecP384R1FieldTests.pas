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

unit SecP384R1FieldTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIAsn1Objects,
  ClpISecureRandom,
  ClpSecObjectIdentifiers,
  ClpIECFieldElement,
  ClpBigInteger,
  ClpCryptoLibTypes,
  SecPFieldTestBase;

type

  TTestSecP384R1Field = class(TSecPFieldTestBase)
  strict protected
    function GetCurveOid: IDerObjectIdentifier; override;
  strict private
    function GenerateSquareInput_CarryBug(): IECFieldElement;
  published
    procedure TestSquare_CarryBug();

    /// <summary>
    /// Based on another example input demonstrating the carry propagation
    /// bug in Nat192.square, as <br />reported by Joseph Friel on
    /// dev-crypto.
    /// </summary>
    procedure TestSquare_CarryBug_Reported();
  end;

implementation

{ TTestSecP384R1Field }

function TTestSecP384R1Field.GetCurveOid: IDerObjectIdentifier;
begin
  result := TSecObjectIdentifiers.SecP384r1;
end;

function TTestSecP384R1Field.GenerateSquareInput_CarryBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat_Create(12);
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[6] := 2;
  x[10] := $FFFF0000;
  x[11] := $FFFFFFFF;

  result := FE(Nat_ToBigInteger(12, x));
end;

procedure TTestSecP384R1Field.TestSquare_CarryBug;
var
  Count, i: Int32;
  x, z: IECFieldElement;
  bigX, bigR, bigZ: TBigInteger;
begin
  Count := 100;
  i := 0;

  while i < Count do
  begin
    x := GenerateSquareInput_CarryBug();

    bigX := x.ToBigInteger();
    bigR := bigX.Multiply(bigX).&Mod(FQ);

    z := x.Square();
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);
    System.Inc(i);
  end;
end;

procedure TTestSecP384R1Field.TestSquare_CarryBug_Reported;
var
  x, z: IECFieldElement;
  bigX, bigR, bigZ: TBigInteger;
begin
  x := FE(TBigInteger.Create
    ('2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd',
    16));

  bigX := x.ToBigInteger();
  bigR := bigX.Multiply(bigX).&Mod(FQ);

  z := x.Square();
  bigZ := z.ToBigInteger();

  AssertAreBigIntegersEqual(bigR, bigZ);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSecP384R1Field);
{$ELSE}
  RegisterTest(TTestSecP384R1Field.Suite);
{$ENDIF FPC}

end.
