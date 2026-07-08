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
  BlockCipherTestBase,
  AesBlockCipherTestBase;

type

  TTestAesLight = class(TAesBlockCipherTestBase)
  strict protected
    function GetEngineFactory: TBlockCipherFactory; override;
    function EngineLabel: String; override;
  end;

implementation

function CreateAesLightEngine: IBlockCipher;
begin
  Result := TAesLightEngine.Create();
end;

{ TTestAesLight }

function TTestAesLight.GetEngineFactory: TBlockCipherFactory;
begin
  Result := @CreateAesLightEngine;
end;

function TTestAesLight.EngineLabel: String;
begin
  Result := 'TAesLightEngine';
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAesLight);
{$ELSE}
  RegisterTest(TTestAesLight.Suite);
{$ENDIF FPC}

end.
