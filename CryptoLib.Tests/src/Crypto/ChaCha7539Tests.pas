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

unit ChaCha7539Tests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIStreamCipher,
  ClpChaCha7539Engine,
  StreamCipherTestBase;

type
  // RFC 7539 keystream is validated against fixed vectors through the AEAD suites;
  // here the shared base covers the engine-agnostic properties (whole-vs-chunked,
  // ProcessBytes-vs-ReturnByte, bulk-vs-single-block, SIMD-vs-scalar).
  TTestChaCha7539 = class(TStreamCipherTestBase)
  strict protected
    function GetEngineFactory: TStreamCipherFactory; override;
    function EngineLabel: String; override;
    function KeySizeInBytes: Int32; override;
    function NonceSizeInBytes: Int32; override;
  end;

implementation

function CreateChaCha7539Engine: IStreamCipher;
begin
  Result := TChaCha7539Engine.Create() as IStreamCipher;
end;

{ TTestChaCha7539 }

function TTestChaCha7539.GetEngineFactory: TStreamCipherFactory;
begin
  Result := CreateChaCha7539Engine;
end;

function TTestChaCha7539.EngineLabel: String;
begin
  Result := 'ChaCha7539';
end;

function TTestChaCha7539.KeySizeInBytes: Int32;
begin
  Result := 32;
end;

function TTestChaCha7539.NonceSizeInBytes: Int32;
begin
  Result := 12;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestChaCha7539);
{$ELSE}
  RegisterTest(TTestChaCha7539.Suite);
{$ENDIF FPC}

end.
