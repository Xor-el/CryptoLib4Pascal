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

unit ClpPrehash;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  HlpIHash,
  ClpIDigest,
  ClpIPrehash,
  ClpCryptoLibTypes;

resourcestring
  SNotSupported = 'not supported';
  SIncorrectPrehashSize = 'Incorrect prehash size';

type
  /// <summary>
  /// A digest that stores pre-hashed data.
  /// Used for "raw" signature operations where the data has already been hashed.
  /// </summary>
  TPrehash = class sealed(TInterfacedObject, IDigest, IPrehash)

  strict private
  var
    FAlgorithmName: String;
    FDigestSize: Int32;
    FBuffer: TMemoryStream;

    function GetAlgorithmName: String;

  public
    class function ForDigest(const digest: IDigest): IPrehash; static;
    class function ForParameters(const digestName: String;
      digestSize: Int32): IPrehash; static;

    constructor Create(const algorithmName: String; digestSize: Int32);
    destructor Destroy; override;

    function GetUnderlyingIHash: IHash;
    function GetDigestSize: Int32;
    function GetByteLength: Int32;

    procedure Update(input: Byte);
    procedure BlockUpdate(const input: TCryptoLibByteArray; inOff, len: Int32);
    function DoFinal: TCryptoLibByteArray; overload;
    function DoFinal(const output: TCryptoLibByteArray; outOff: Int32): Int32; overload;
    procedure Reset;
    function Clone: IDigest;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TPrehash }

class function TPrehash.ForDigest(const digest: IDigest): IPrehash;
begin
  Result := ForParameters(digest.AlgorithmName, digest.GetDigestSize());
end;

class function TPrehash.ForParameters(const digestName: String;
  digestSize: Int32): IPrehash;
begin
  Result := TPrehash.Create(digestName, digestSize);
end;

constructor TPrehash.Create(const algorithmName: String; digestSize: Int32);
begin
  inherited Create();
  FAlgorithmName := algorithmName;
  FDigestSize := digestSize;
  FBuffer := TMemoryStream.Create();
end;

destructor TPrehash.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TPrehash.GetAlgorithmName: String;
begin
  Result := FAlgorithmName;
end;

function TPrehash.GetUnderlyingIHash: IHash;
begin
  // Prehash doesn't have an underlying IHash
  Result := nil;
end;

function TPrehash.GetDigestSize: Int32;
begin
  Result := FDigestSize;
end;

function TPrehash.GetByteLength: Int32;
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SNotSupported);
end;

procedure TPrehash.Update(input: Byte);
begin
  if FBuffer.Size < FDigestSize then
    FBuffer.Write(input, 1);
end;

procedure TPrehash.BlockUpdate(const input: TCryptoLibByteArray;
  inOff, len: Int32);
var
  writeLen: Int32;
begin
  writeLen := len;
  if FBuffer.Size + writeLen > FDigestSize then
    writeLen := FDigestSize - FBuffer.Size;
  if writeLen > 0 then
    FBuffer.Write(input[inOff], writeLen);
end;

function TPrehash.DoFinal: TCryptoLibByteArray;
begin
  try
    if FBuffer.Size <> FDigestSize then
      raise EInvalidOperationCryptoLibException.CreateRes(@SIncorrectPrehashSize);
    SetLength(Result, FDigestSize);
    FBuffer.Position := 0;
    FBuffer.Read(Result[0], FDigestSize);
  finally
    Reset();
  end;
end;

function TPrehash.DoFinal(const output: TCryptoLibByteArray;
  outOff: Int32): Int32;
begin
  try
    if FBuffer.Size <> FDigestSize then
      raise EInvalidOperationCryptoLibException.CreateRes(@SIncorrectPrehashSize);
    FBuffer.Position := 0;
    FBuffer.Read(output[outOff], FDigestSize);
    Result := FDigestSize;
  finally
    Reset();
  end;
end;

procedure TPrehash.Reset;
begin
  FBuffer.Clear;
end;

function TPrehash.Clone: IDigest;
var
  cloned: TPrehash;
begin
  cloned := TPrehash.Create(FAlgorithmName, FDigestSize);
  FBuffer.Position := 0;
  cloned.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  Result := cloned;
end;

end.
