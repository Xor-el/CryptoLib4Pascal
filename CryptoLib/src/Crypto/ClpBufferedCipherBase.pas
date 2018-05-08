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

unit ClpBufferedCipherBase;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpIBufferedCipherBase,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooSmall = 'Output Buffer too Short';

type
  TBufferedCipherBase = class abstract(TInterfacedObject, IBufferedCipherBase,
    IBufferedCipher)

  strict private
    class var

      FEmptyBuffer: TCryptoLibByteArray;

    class function GetEmptyBuffer: TCryptoLibByteArray; static; inline;

    class constructor CreateBufferedCipherBase();

  strict protected

    class property EmptyBuffer: TCryptoLibByteArray read GetEmptyBuffer;

  public

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
      virtual; abstract;

    function GetBlockSize(): Int32; virtual; abstract;

    function GetOutputSize(inputLen: Int32): Int32; virtual; abstract;
    function GetUpdateOutputSize(inputLen: Int32): Int32; virtual; abstract;

    function ProcessByte(input: Byte): TCryptoLibByteArray; overload;
      virtual; abstract;

    function ProcessByte(input: Byte; output: TCryptoLibByteArray;
      outOff: Int32): Int32; overload; virtual;

    function ProcessBytes(input: TCryptoLibByteArray): TCryptoLibByteArray;
      overload; virtual;

    function ProcessBytes(input: TCryptoLibByteArray; inOff, length: Int32)
      : TCryptoLibByteArray; overload; virtual; abstract;

    function ProcessBytes(input, output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload; virtual;

    function ProcessBytes(input: TCryptoLibByteArray; inOff: Int32;
      length: Int32; output: TCryptoLibByteArray; outOff: Int32): Int32;
      overload; virtual;

    function DoFinal(): TCryptoLibByteArray; overload; virtual; abstract;

    function DoFinal(input: TCryptoLibByteArray): TCryptoLibByteArray;
      overload; virtual;

    function DoFinal(input: TCryptoLibByteArray; inOff, length: Int32)
      : TCryptoLibByteArray; overload; virtual; abstract;

    function DoFinal(output: TCryptoLibByteArray; outOff: Int32): Int32;
      overload; virtual;

    function DoFinal(input, output: TCryptoLibByteArray; outOff: Int32): Int32;
      overload; virtual;

    function DoFinal(input: TCryptoLibByteArray; inOff, length: Int32;
      output: TCryptoLibByteArray; outOff: Int32): Int32; overload; virtual;

    procedure Reset(); virtual; abstract;

    function GetAlgorithmName: String; virtual; abstract;
    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TBufferedCipherBase }

class constructor TBufferedCipherBase.CreateBufferedCipherBase;
begin
  System.SetLength(FEmptyBuffer, 0);
end;

function TBufferedCipherBase.DoFinal(output: TCryptoLibByteArray;
  outOff: Int32): Int32;
var
  outBytes: TCryptoLibByteArray;
begin
  outBytes := DoFinal();
  if ((outOff + System.length(outBytes)) > System.length(output)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  end;
  System.Move(outBytes[0], output[outOff], System.length(outBytes));
  result := System.length(outBytes);
end;

function TBufferedCipherBase.DoFinal(input: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  result := DoFinal(input, 0, System.length(input));
end;

function TBufferedCipherBase.DoFinal(input: TCryptoLibByteArray;
  inOff, length: Int32; output: TCryptoLibByteArray; outOff: Int32): Int32;
var
  len: Int32;
begin
  len := ProcessBytes(input, inOff, length, output, outOff);
  len := len + DoFinal(output, outOff + len);
  result := len;
end;

function TBufferedCipherBase.DoFinal(input, output: TCryptoLibByteArray;
  outOff: Int32): Int32;
begin
  result := DoFinal(input, 0, System.length(input), output, outOff);
end;

class function TBufferedCipherBase.GetEmptyBuffer: TCryptoLibByteArray;
begin
  result := FEmptyBuffer;
end;

function TBufferedCipherBase.ProcessByte(input: Byte;
  output: TCryptoLibByteArray; outOff: Int32): Int32;
var
  outBytes: TCryptoLibByteArray;
begin
  outBytes := ProcessByte(input);
  if (outBytes = Nil) then
  begin
    result := 0;
    Exit;
  end;
  if ((outOff + System.length(outBytes)) > System.length(output)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  end;
  System.Move(outBytes[0], output[outOff], System.length(outBytes));
  result := System.length(outBytes);
end;

function TBufferedCipherBase.ProcessBytes(input: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  result := ProcessBytes(input, 0, System.length(input));
end;

function TBufferedCipherBase.ProcessBytes(input: TCryptoLibByteArray;
  inOff, length: Int32; output: TCryptoLibByteArray; outOff: Int32): Int32;
var
  outBytes: TCryptoLibByteArray;
begin
  outBytes := ProcessBytes(input, inOff, length);
  if (outBytes = Nil) then
  begin
    result := 0;
    Exit;
  end;
  if ((outOff + System.length(outBytes)) > System.length(output)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  end;
  System.Move(outBytes[0], output[outOff], System.length(outBytes));
  result := System.length(outBytes);
end;

function TBufferedCipherBase.ProcessBytes(input, output: TCryptoLibByteArray;
  outOff: Int32): Int32;
begin
  result := ProcessBytes(input, 0, System.length(input), output, outOff);
end;

end.
