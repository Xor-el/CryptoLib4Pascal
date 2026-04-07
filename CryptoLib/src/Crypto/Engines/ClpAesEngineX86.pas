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

unit ClpAesEngineX86;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAesEngine,
  ClpIAesEngineX86,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpAesEngine,
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// AES engine selected when AES-NI is available.
  /// Currently delegates to <see cref="TAesEngine" /> for identical output; the
  /// x86 SIMD include layer can replace the implementation body later.
  /// </summary>
  TAesEngineX86 = class sealed(TInterfacedObject, IAesEngineX86, IBlockCipher)
  strict private
    FImpl: IBlockCipher;
  strict protected
    function GetAlgorithmName: String;
  public
    class function IsSupported: Boolean; static;
    constructor Create();
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function ProcessFourBlocks(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TAesEngineX86 }

class function TAesEngineX86.IsSupported: Boolean;
begin
  Result := TCpuFeatures.HasAESNI();
end;

constructor TAesEngineX86.Create();
begin
  inherited Create();
  FImpl := TAesEngine.Create();
end;

function TAesEngineX86.GetAlgorithmName: String;
begin
  Result := FImpl.AlgorithmName;
end;

function TAesEngineX86.GetBlockSize(): Int32;
begin
  Result := FImpl.GetBlockSize();
end;

procedure TAesEngineX86.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
begin
  FImpl.Init(AForEncryption, AParameters);
end;

function TAesEngineX86.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := FImpl.ProcessBlock(AInput, AInOff, AOutput, AOutOff);
end;

function TAesEngineX86.ProcessFourBlocks(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LO: Int32;
begin
  LO := AOutOff;
  Result := FImpl.ProcessBlock(AInput, AInOff, AOutput, LO);
  System.Inc(LO, 16);
  Result := Result + FImpl.ProcessBlock(AInput, AInOff + 16, AOutput, LO);
  System.Inc(LO, 16);
  Result := Result + FImpl.ProcessBlock(AInput, AInOff + 32, AOutput, LO);
  System.Inc(LO, 16);
  Result := Result + FImpl.ProcessBlock(AInput, AInOff + 48, AOutput, LO);
end;

end.
