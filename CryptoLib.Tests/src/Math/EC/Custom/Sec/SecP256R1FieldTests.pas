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

unit SecP256R1FieldTests;

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

  TTestSecP256R1Field = class(TSecPFieldTestBase)
  strict protected
    function GetCurveOid: IDerObjectIdentifier; override;
  strict private
    function GenerateSquareInput_OpenSSLBug(): IECFieldElement;
    function GenerateMultiplyInputA_OpenSSLBug(): IECFieldElement;
    function GenerateMultiplyInputB_OpenSSLBug(): IECFieldElement;
  published
    /// <summary>
    /// <para>
    /// Test squaring with specifically selected values that triggered a
    /// bug in the modular reduction <br />in OpenSSL (last affected
    /// version 0.9.8g).
    /// </para>
    /// <para>
    /// See "Practical realisation and elimination of an ECC-related
    /// software bug attack", B. B. <br />Brumley, M. Barbarosa, D. Page,
    /// F. Vercauteren.
    /// </para>
    /// </summary>
    procedure TestSquare_OpenSSLBug();

    /// <summary>
    /// <para>
    /// Test multiplication with specifically selected values that
    /// triggered a bug in the modular <br />reduction in OpenSSL (last
    /// affected version 0.9.8g).
    /// </para>
    /// <para>
    /// See "Practical realisation and elimination of an ECC-related
    /// software bug attack", B. B. <br />Brumley, M. Barbarosa, D. Page,
    /// F. Vercauteren.
    /// </para>
    /// </summary>
    procedure TestMultiply_OpenSSLBug();
  end;

implementation

{ TTestSecP256R1Field }

function TTestSecP256R1Field.GetCurveOid: IDerObjectIdentifier;
begin
  result := TSecObjectIdentifiers.SecP256r1;
end;

function TTestSecP256R1Field.GenerateMultiplyInputA_OpenSSLBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat_Create(8);
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[4] := 3;
  x[7] := $FFFFFFFF;

  result := FE(Nat_ToBigInteger(8, x));
end;

function TTestSecP256R1Field.GenerateMultiplyInputB_OpenSSLBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat_Create(8);
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[3] := 1;
  x[7] := $FFFFFFFF;

  result := FE(Nat_ToBigInteger(8, x));
end;

function TTestSecP256R1Field.GenerateSquareInput_OpenSSLBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat_Create(8);
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[4] := 2;
  x[7] := $FFFFFFFF;

  result := FE(Nat_ToBigInteger(8, x));
end;

procedure TTestSecP256R1Field.TestSquare_OpenSSLBug;
var
  Count, i: Int32;
  x, z: IECFieldElement;
  bigX, bigR, bigZ: TBigInteger;
begin
  Count := 100;
  i := 0;

  while i < Count do
  begin
    x := GenerateSquareInput_OpenSSLBug();

    bigX := x.ToBigInteger();
    bigR := bigX.Multiply(bigX).&Mod(FQ);

    z := x.Square();
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);
    System.Inc(i);
  end;
end;

procedure TTestSecP256R1Field.TestMultiply_OpenSSLBug;
var
  x, y, z: IECFieldElement;
  bigR, bigX, bigY, bigZ: TBigInteger;
  Count, i: Int32;
begin
  Count := 100;
  i := 0;

  while i < Count do
  begin
    x := GenerateMultiplyInputA_OpenSSLBug();
    y := GenerateMultiplyInputB_OpenSSLBug();

    bigX := x.ToBigInteger();
    bigY := y.ToBigInteger();
    bigR := bigX.Multiply(bigY).&Mod(FQ);

    z := x.Multiply(y);
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);
    System.Inc(i);
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSecP256R1Field);
{$ELSE}
  RegisterTest(TTestSecP256R1Field.Suite);
{$ENDIF FPC}

end.
