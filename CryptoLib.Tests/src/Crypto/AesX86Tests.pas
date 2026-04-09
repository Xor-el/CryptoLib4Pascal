{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit AesX86Tests;

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
  ClpAesEngineX86,
  ClpIAesEngineX86,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpSecureRandom,
  ClpISecureRandom,
  AesBlockCipherTestBase;

type

  TTestAesX86 = class(TAesBlockCipherTestBase)
  strict private
    procedure ImplTestFourBlocks(AForEncryption: Boolean; AKeySizeBytes: Int32);
  published
    procedure TestBlockCipherVectors;
    procedure TestMonteCarloAES;
    procedure TestEngineChecks128;
    procedure TestEngineChecks192;
    procedure TestEngineChecks256;
    procedure TestFourBlocksEncrypt128;
    procedure TestFourBlocksEncrypt192;
    procedure TestFourBlocksEncrypt256;
    procedure TestFourBlocksDecrypt128;
    procedure TestFourBlocksDecrypt192;
    procedure TestFourBlocksDecrypt256;
  end;

implementation

function CreateAesX86Engine: IBlockCipher;
begin
  Result := TAesEngineX86.Create();
end;

{ TTestAesX86 }

procedure TTestAesX86.ImplTestFourBlocks(AForEncryption: Boolean;
  AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LData, LFourOut, LSingleOut, LKey: TBytes;
  LI, LJ: Int32;
  LX86: IAesEngineX86;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LData, 64);
  System.SetLength(LFourOut, 64);
  System.SetLength(LSingleOut, 64);
  System.SetLength(LKey, AKeySizeBytes);

  for LI := 0 to 99 do
  begin
    LRnd.NextBytes(LData);
    LRnd.NextBytes(LKey);
    LX86 := TAesEngineX86.Create();
    LX86.Init(AForEncryption, TKeyParameter.Create(LKey) as IKeyParameter);
    LX86.ProcessFourBlocks(LData, 0, LFourOut, 0);
    for LJ := 0 to 3 do
      LX86.ProcessBlock(LData, LJ * 16, LSingleOut, LJ * 16);
    if not AreEqual(LFourOut, LSingleOut) then
    begin
      Fail(Format(
        'ProcessFourBlocks vs ProcessBlock mismatch (key %d bytes, iteration %d)',
        [AKeySizeBytes, LI]));
    end;
  end;
end;

procedure TTestAesX86.TestBlockCipherVectors;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunBlockCipherVectorTests(@CreateAesX86Engine, 'TAesEngineX86');
end;

procedure TTestAesX86.TestMonteCarloAES;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunBlockCipherMonteCarloTests(@CreateAesX86Engine, 'TAesEngineX86');
end;

procedure TTestAesX86.TestEngineChecks128;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 16);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(TAesEngineX86.Create() as IBlockCipher,
    TKeyParameter.Create(LKey) as IKeyParameter, 'TAesEngineX86 128-bit');
end;

procedure TTestAesX86.TestEngineChecks192;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 24);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(TAesEngineX86.Create() as IBlockCipher,
    TKeyParameter.Create(LKey) as IKeyParameter, 'TAesEngineX86 192-bit');
end;

procedure TTestAesX86.TestEngineChecks256;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 32);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(TAesEngineX86.Create() as IBlockCipher,
    TKeyParameter.Create(LKey) as IKeyParameter, 'TAesEngineX86 256-bit');
end;

procedure TTestAesX86.TestFourBlocksEncrypt128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(True, 16);
end;

procedure TTestAesX86.TestFourBlocksEncrypt192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(True, 24);
end;

procedure TTestAesX86.TestFourBlocksEncrypt256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(True, 32);
end;

procedure TTestAesX86.TestFourBlocksDecrypt128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(False, 16);
end;

procedure TTestAesX86.TestFourBlocksDecrypt192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(False, 24);
end;

procedure TTestAesX86.TestFourBlocksDecrypt256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(False, 32);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAesX86);
{$ELSE}
  RegisterTest(TTestAesX86.Suite);
{$ENDIF FPC}

end.
