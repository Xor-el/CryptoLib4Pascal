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

unit ClpDigest;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  HlpIHash,
  ClpIDigest,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output Buffer Too Short';

type

  /// <summary>
  /// Hash Wrapper For the Proper Implementation in HashLib4Pascal
  /// </summary>
  TDigest = class(TInterfacedObject, IDigest)

  strict private

    class var FNameMap: TDictionary<string, string>;

    class function NormalizeHashLibName(const AName: string): string; static;

    constructor Create(); overload;

  strict protected
  var
    FHash: IHash;

    function GetAlgorithmName: string; virtual;
    /// <summary>
    /// Gets the Underlying <b>IHash</b> Instance
    /// </summary>
    function GetUnderlyingHasher: IHash; virtual;

  public
    class constructor Create; overload;
    class destructor Destroy;

    constructor Create(const AHash: IHash); overload;

    /// <summary>
    /// the size, in bytes, of the digest produced by this message digest.
    /// </summary>
    function GetDigestSize(): Int32; virtual;

    /// <summary>
    /// the size, in bytes, of the internal buffer used by this digest.
    /// </summary>
    function GetByteLength(): Int32; virtual;

    /// <summary>
    /// update the message digest with a single byte.
    /// </summary>
    procedure Update(AInput: Byte);

    /// <summary>
    /// update the message digest with a block of bytes.
    /// </summary>
    /// <param name="AInput">
    /// the byte array containing the data.
    /// </param>
    /// <param name="AInOff">
    /// the offset into the byte array where the data starts.
    /// </param>
    /// <param name="ALen">
    /// the length of the data.
    /// </param>
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32);

    function DoFinal: TCryptoLibByteArray; overload; virtual;

    /// <summary>
    /// Close the digest, producing the final digest value. The doFinal call
    /// leaves the digest reset.
    /// </summary>
    /// <param name="AOutput">
    /// the array the digest is to be copied into.
    /// </param>
    /// <param name="AOutOff">
    /// the offset into the out array the digest is to start at.
    /// </param>
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; virtual;

    /// <summary>
    /// Resets the digest back to it's initial state.
    /// </summary>
    procedure Reset(); virtual;

    /// <summary>
    /// Clone the digest instance
    /// </summary>
    function Clone(): IDigest; virtual;

    /// <summary>
    /// the algorithm name
    /// </summary>
    property AlgorithmName: String read GetAlgorithmName;

    property UnderlyingHasher: IHash read GetUnderlyingHasher;

  end;

implementation

{ TDigest }

class constructor TDigest.Create;
begin
  FNameMap := TDictionary<string, string>.Create;

  FNameMap.Add('Tiger_3_128', 'Tiger');
  FNameMap.Add('Tiger_3_160', 'Tiger');
  FNameMap.Add('Tiger_3_192', 'Tiger');
  FNameMap.Add('Tiger_4_128', 'Tiger');
  FNameMap.Add('Tiger_4_160', 'Tiger');
  FNameMap.Add('Tiger_4_192', 'Tiger');
  FNameMap.Add('Tiger_5_128', 'Tiger');
  FNameMap.Add('Tiger_5_160', 'Tiger');
  FNameMap.Add('Tiger_5_192', 'Tiger');

  FNameMap.Add('MD2', 'MD2');
  FNameMap.Add('MD4', 'MD4');
  FNameMap.Add('MD5', 'MD5');

  FNameMap.Add('SHA0', 'SHA-0');
  FNameMap.Add('SHA1', 'SHA-1');
  FNameMap.Add('SHA2_224', 'SHA-224');
  FNameMap.Add('SHA2_256', 'SHA-256');
  FNameMap.Add('SHA2_384', 'SHA-384');
  FNameMap.Add('SHA2_512', 'SHA-512');
  FNameMap.Add('SHA2_512_224', 'SHA-512/224');
  FNameMap.Add('SHA2_512_256', 'SHA-512/256');

  FNameMap.Add('WhirlPool', 'Whirlpool');

  FNameMap.Add('Gost', 'Gost3411');

  FNameMap.Add('GOST3411_2012_256', 'GOST3411-2012-256');
  FNameMap.Add('GOST3411_2012_512', 'GOST3411-2012-512');

  FNameMap.Add('RIPEMD', 'RIPEMD');
  FNameMap.Add('RIPEMD128', 'RIPEMD128');
  FNameMap.Add('RIPEMD160', 'RIPEMD160');
  FNameMap.Add('RIPEMD256', 'RIPEMD256');
  FNameMap.Add('RIPEMD320', 'RIPEMD320');

  FNameMap.Add('Keccak_224', 'Keccak-224');
  FNameMap.Add('Keccak_256', 'Keccak-256');
  FNameMap.Add('Keccak_288', 'Keccak-288');
  FNameMap.Add('Keccak_384', 'Keccak-384');
  FNameMap.Add('Keccak_512', 'Keccak-512');

  FNameMap.Add('SHA3_224', 'SHA3-224');
  FNameMap.Add('SHA3_256', 'SHA3-256');
  FNameMap.Add('SHA3_384', 'SHA3-384');
  FNameMap.Add('SHA3_512', 'SHA3-512');

  FNameMap.Add('Shake_128', 'SHAKE128');
  FNameMap.Add('Shake_256', 'SHAKE256');

  FNameMap.Add('Blake2B_160', 'BLAKE2b');
  FNameMap.Add('Blake2B_256', 'BLAKE2b');
  FNameMap.Add('Blake2B_384', 'BLAKE2b');
  FNameMap.Add('Blake2B_512', 'BLAKE2b');

  FNameMap.Add('Blake2S_128', 'BLAKE2s');
  FNameMap.Add('Blake2S_160', 'BLAKE2s');
  FNameMap.Add('Blake2S_224', 'BLAKE2s');
  FNameMap.Add('Blake2S_256', 'BLAKE2s');

  FNameMap.Add('Blake3_256', 'BLAKE3');
end;

class destructor TDigest.Destroy;
begin
  FNameMap.Free;
end;

class function TDigest.NormalizeHashLibName(const AName: string): string;
begin
  // HashLib4Pascal names are typically class-like (e.g., "TSHA2_256", "TKeccak_256", ...)
  if (AName <> '') and (AName[1] = 'T') then
    Result := Copy(AName, 2, System.Length(AName) - 1)
  else
    Result := AName;
end;

function TDigest.GetAlgorithmName: string;
var
  LRawName, LNormalized, LMapped: String;
begin
  LRawName := FHash.Name;
  LNormalized := NormalizeHashLibName(LRawName);

  // Default/fallback is the normalized HashLib name (without the leading 'T')
  Result := LNormalized;

  // If we have a canonical CryptoLib name, return it
  if FNameMap.TryGetValue(Result, LMapped) then
    Result := LMapped;
end;

function TDigest.GetByteLength: Int32;
begin
  Result := FHash.BlockSize;
end;

function TDigest.GetDigestSize: Int32;
begin
  Result := FHash.HashSize;
end;

function TDigest.GetUnderlyingHasher: IHash;
begin
  Result := FHash;
end;

procedure TDigest.Reset;
begin
  FHash.Initialize;
end;

procedure TDigest.BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32);
begin
  FHash.TransformBytes(AInput, AInOff, ALen);
end;

constructor TDigest.Create;
begin
  inherited Create;
end;

constructor TDigest.Create(const AHash: IHash);
begin
  inherited Create();
  FHash := AHash;
  FHash.Initialize;
end;

function TDigest.DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBuf: TCryptoLibByteArray;
begin
  if (System.Length(AOutput) - AOutOff) < GetDigestSize() then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  LBuf := FHash.TransformFinal.GetBytes();
  System.Move(LBuf[0], AOutput[AOutOff], System.Length(LBuf) * System.SizeOf(Byte));
  Result := System.Length(LBuf);
end;

function TDigest.DoFinal: TCryptoLibByteArray;
begin
  System.SetLength(Result, GetDigestSize);
  DoFinal(Result, 0);
end;

procedure TDigest.Update(AInput: Byte);
begin
  FHash.TransformUntyped(AInput, System.SizeOf(Byte));
end;

function TDigest.Clone(): IDigest;
var
 LDigest: TDigest;
begin
  LDigest := TDigest.Create();
  LDigest.FHash := FHash.Clone();
  Result := LDigest;
end;

end.
