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

unit GF256AesTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpGF256Aes,
  CryptoLibTestBase;

type
  TTestGF256Aes = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestMul;
    procedure TestInv;
  end;

implementation

{ TTestGF256Aes }

procedure TTestGF256Aes.TestMul;
begin
  if TGF256Aes.Mul($02, $03) <> $06 then
    Fail('Mul($02, $03) failed');
  if TGF256Aes.Mul($57, $83) <> $C1 then
    Fail('Mul($57, $83) failed');
end;

procedure TTestGF256Aes.TestInv;
var
  LA: Int32;
begin
  for LA := 1 to 255 do
  begin
    if TGF256Aes.Mul(LA, TGF256Aes.Inv(LA)) <> 1 then
      Fail(Format('Inv round-trip failed for $%x', [LA]));
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGF256Aes);
{$ELSE}
  RegisterTest(TTestGF256Aes.Suite);
{$ENDIF FPC}

end.
