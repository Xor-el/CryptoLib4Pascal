{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpRsaEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpICipherParameters,
  ClpIRsa,
  ClpRsaCoreEngine,
  ClpIAsymmetricBlockCipher,
  ClpIRsaEngine,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Basic RSA engine implementing IAsymmetricBlockCipher.
  /// Wraps an IRsa implementation for byte[] processing.
  /// </summary>
  TRsaEngine = class(TInterfacedObject, IAsymmetricBlockCipher, IRsaEngine)

  strict private
  var
    FCore: IRsa;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;

  public
    constructor Create(); overload;
    constructor Create(const rsa: IRsa); overload;

    procedure Init(forEncryption: Boolean;
      const parameters: ICipherParameters);

    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;

  end;

implementation

{ TRsaEngine }

constructor TRsaEngine.Create;
begin
  Create(TRsaCoreEngine.Create() as IRsa);
end;

constructor TRsaEngine.Create(const rsa: IRsa);
begin
  inherited Create();
  FCore := rsa;
end;

function TRsaEngine.GetAlgorithmName: String;
begin
  Result := 'RSA';
end;

procedure TRsaEngine.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
begin
  FCore.Init(forEncryption, parameters);
end;

function TRsaEngine.GetInputBlockSize: Int32;
begin
  Result := FCore.InputBlockSize;
end;

function TRsaEngine.GetOutputBlockSize: Int32;
begin
  Result := FCore.OutputBlockSize;
end;

function TRsaEngine.ProcessBlock(const inBuf: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  input, output: TBigInteger;
begin
  input := FCore.ConvertInput(inBuf, inOff, inLen);
  output := FCore.ProcessBlock(input);
  Result := FCore.ConvertOutput(output);
end;

end.
