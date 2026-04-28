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

unit AesLightTests;

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
  ClpAesLightEngine,
  ClpIBlockCipher,
  AesBlockCipherTestBase;

type

  TTestAesLight = class(TAesBlockCipherTestBase)
  published
    procedure TestBlockCipherVector;
    procedure TestMonteCarloAES;
    procedure TestBadParameters;
  end;

implementation

function CreateAesLightEngine: IBlockCipher;
begin
  Result := TAesLightEngine.Create();
end;

{ TTestAesLight }

procedure TTestAesLight.TestBlockCipherVector;
begin
  RunBlockCipherVectorTests(@CreateAesLightEngine, 'TAesLightEngine');
end;

procedure TTestAesLight.TestMonteCarloAES;
begin
  RunBlockCipherMonteCarloTests(@CreateAesLightEngine, 'TAesLightEngine');
end;

procedure TTestAesLight.TestBadParameters;
begin
  AssertEngineRejectsBadParameters(@CreateAesLightEngine, 'TAesLightEngine');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAesLight);
{$ELSE}
  RegisterTest(TTestAesLight.Suite);
{$ENDIF FPC}

end.
