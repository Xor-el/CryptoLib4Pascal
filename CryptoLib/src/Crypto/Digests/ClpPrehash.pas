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
  ClpDigest,
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
  TPrehash = class sealed(TDigest, IDigest, IPrehash)

  strict private
  var
    FAlgorithmName: String;
    FDigestSize: Int32;
    FBuffer: TMemoryStream;

    strict protected
    function GetAlgorithmName: String; override;
    /// <summary>
    /// Gets the Underlying <b>IHash</b> Instance
    /// </summary>
    function GetUnderlyingHasher: IHash; override;

  public
    class function ForDigest(const ADigest: IDigest): IPrehash; static;
    class function ForParameters(const ADigestName: String;
      ADigestSize: Int32): IPrehash; static;

    constructor Create(const AAlgorithmName: String; ADigestSize: Int32);
    destructor Destroy; override;

    function GetDigestSize: Int32; override;
    function GetByteLength: Int32; override;

    procedure Update(AInput: Byte);
    procedure BlockUpdate(const input: TCryptoLibByteArray; AInOff, ALen: Int32);
    function DoFinal: TCryptoLibByteArray; overload; override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; override;
    procedure Reset; override;
    function Clone: IDigest; override;

    property AlgorithmName: String read GetAlgorithmName;
    property UnderlyingHasher: IHash read GetUnderlyingHasher;

  end;

implementation

{ TPrehash }

class function TPrehash.ForDigest(const ADigest: IDigest): IPrehash;
begin
  Result := ForParameters(ADigest.AlgorithmName, ADigest.GetDigestSize());
end;

class function TPrehash.ForParameters(const ADigestName: String;
  ADigestSize: Int32): IPrehash;
begin
  Result := TPrehash.Create(ADigestName, ADigestSize);
end;

constructor TPrehash.Create(const AAlgorithmName: String; ADigestSize: Int32);
begin
  inherited Create();
  FAlgorithmName := AAlgorithmName;
  FDigestSize := ADigestSize;
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

function TPrehash.GetUnderlyingHasher: IHash;
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

procedure TPrehash.Update(AInput: Byte);
begin
  if FBuffer.Size < FDigestSize then
    FBuffer.Write(AInput, 1);
end;

procedure TPrehash.BlockUpdate(const input: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LWriteLen: Int32;
begin
  LWriteLen := ALen;
  if FBuffer.Size + LWriteLen > FDigestSize then
    LWriteLen := FDigestSize - FBuffer.Size;
  if LWriteLen > 0 then
    FBuffer.Write(input[AInOff], LWriteLen);
end;

function TPrehash.DoFinal: TCryptoLibByteArray;
begin
  System.SetLength(Result, FDigestSize);
  DoFinal(Result, 0);
end;

function TPrehash.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  try
    if FBuffer.Size <> FDigestSize then
      raise EInvalidOperationCryptoLibException.CreateRes(@SIncorrectPrehashSize);
    FBuffer.Position := 0;
    FBuffer.Read(AOutput[AOutOff], FDigestSize);
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
  LCloned: TPrehash;
begin
  LCloned := TPrehash.Create(FAlgorithmName, FDigestSize);
  FBuffer.Position := 0;
  LCloned.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  Result := LCloned;
end;

end.
