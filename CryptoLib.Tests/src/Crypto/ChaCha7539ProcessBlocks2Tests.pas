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

unit ChaCha7539ProcessBlocks2Tests;

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
  ClpChaCha7539Engine,
  ClpIChaCha7539Engine,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  CryptoLibTestBase;

type

  TTestChaCha7539ProcessBlocks2 = class(TCryptoLibAlgorithmTestCase)
  published
    procedure Test128ByteProcessBlocks2VsTwoBlockCalls;
  end;

implementation

{ TTestChaCha7539ProcessBlocks2 }

procedure TTestChaCha7539ProcessBlocks2.Test128ByteProcessBlocks2VsTwoBlockCalls;
var
  LKey, LNonce, LIn, LOutA, LOutB: TBytes;
  LParams: IParametersWithIV;
  LA, LB: IChaCha7539Engine;
  LIdx: Int32;
begin
  LKey := DecodeHex('000102030405060708090A0B0C0D0E0F' +
    '101112131415161718191A1B1C1D1E1F');
  LNonce := DecodeHex('00000000000000000000000A');
  LParams := TParametersWithIV.Create(
    TKeyParameter.Create(LKey) as IKeyParameter, LNonce);
  SetLength(LIn, 128);
  for LIdx := 0 to 127 do
  begin
    LIn[LIdx] := Byte(LIdx);
  end;
  SetLength(LOutA, 128);
  SetLength(LOutB, 128);
  LA := TChaCha7539Engine.Create();
  LA.Init(True, LParams);
  LA.ProcessBlocks2(LIn, 0, LOutA, 0);
  LB := TChaCha7539Engine.Create();
  LB.Init(True, LParams);
  LB.ProcessBlock(LIn, 0, LOutB, 0);
  LB.ProcessBlock(LIn, 64, LOutB, 64);
  if not AreEqual(LOutA, LOutB) then
  begin
    Fail('ChaCha7539 128B stream mismatch');
  end;
end;

initialization
{$IFDEF FPC}
  RegisterTest(TTestChaCha7539ProcessBlocks2);
{$ELSE}
  RegisterTest(TTestChaCha7539ProcessBlocks2.Suite);
{$ENDIF FPC}

end.
