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

unit ClpOaepEncoding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpICipherParameters,
  ClpIDigest,
  ClpDigestUtilities,
  ClpIAsymmetricBlockCipher,
  ClpIOaepEncoding,
  ClpISecureRandom,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpCryptoLibTypes;

resourcestring
  SInputDataTooLong = 'Input data too long';
  SDataWrong = 'Data wrong';

type
  /// <summary>
  /// Optimal Asymmetric Encryption Padding (OAEP) - see PKCS #1 V 2.
  /// </summary>
  TOaepEncoding = class(TInterfacedObject, IAsymmetricBlockCipher, IOaepEncoding)

  strict private
  var
    FEngine: IAsymmetricBlockCipher;
    FMgf1Hash: IDigest;
    FDefHash: TCryptoLibByteArray;
    FRandom: ISecureRandom;
    FForEncryption: Boolean;

    function EncodeBlock(const AInBytes: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;
    function DecodeBlock(const AInBytes: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

    procedure MaskGeneratorFunction(
      const AZ: TCryptoLibByteArray; AZOff, AZLen: Int32;
      const AMask: TCryptoLibByteArray; AMaskOff, AMaskLen: Int32);

    function GetReducedBlockSize(ABlockSize: Int32): Int32; inline;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function GetUnderlyingCipher: IAsymmetricBlockCipher;

  public
    constructor Create(const ACipher: IAsymmetricBlockCipher); overload;
    constructor Create(const ACipher: IAsymmetricBlockCipher;
      const AHash: IDigest); overload;
    constructor Create(const ACipher: IAsymmetricBlockCipher;
      const AHash: IDigest;
      const AEncodingParams: TCryptoLibByteArray); overload;
    constructor Create(const ACipher: IAsymmetricBlockCipher;
      const AHash, AMgf1Hash: IDigest;
      const AEncodingParams: TCryptoLibByteArray); overload;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function ProcessBlock(const AInBuf: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;

  end;

implementation

{ TOaepEncoding }

constructor TOaepEncoding.Create(const ACipher: IAsymmetricBlockCipher);
begin
  Create(ACipher, TDigestUtilities.GetDigest('SHA-1'), nil);
end;

constructor TOaepEncoding.Create(const ACipher: IAsymmetricBlockCipher;
  const AHash: IDigest);
begin
  Create(ACipher, AHash, nil);
end;

constructor TOaepEncoding.Create(const ACipher: IAsymmetricBlockCipher;
  const AHash: IDigest; const AEncodingParams: TCryptoLibByteArray);
begin
  Create(ACipher, AHash, AHash, AEncodingParams);
end;

constructor TOaepEncoding.Create(const ACipher: IAsymmetricBlockCipher;
  const AHash, AMgf1Hash: IDigest; const AEncodingParams: TCryptoLibByteArray);
begin
  inherited Create();
  FEngine := ACipher;
  FMgf1Hash := AMgf1Hash;
  SetLength(FDefHash, AHash.GetDigestSize);

  AHash.Reset();
  if AEncodingParams <> nil then
  begin
    AHash.BlockUpdate(AEncodingParams, 0, System.Length(AEncodingParams));
  end;
  AHash.DoFinal(FDefHash, 0);
end;

function TOaepEncoding.GetAlgorithmName: String;
begin
  Result := FEngine.AlgorithmName + '/OAEPPadding';
end;

function TOaepEncoding.GetUnderlyingCipher: IAsymmetricBlockCipher;
begin
  Result := FEngine;
end;

procedure TOaepEncoding.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LInitRandom: ISecureRandom;
begin
  TParameterUtilities.GetRandom(AParameters, LInitRandom);

  if AForEncryption then
    FRandom := TCryptoServicesRegistrar.GetSecureRandom(LInitRandom)
  else
    FRandom := nil;

  FForEncryption := AForEncryption;
  FEngine.Init(AForEncryption, AParameters);
end;

function TOaepEncoding.GetReducedBlockSize(ABlockSize: Int32): Int32;
begin
  Result := ABlockSize - 1 - 2 * System.Length(FDefHash);
end;

function TOaepEncoding.GetInputBlockSize: Int32;
begin
  if FForEncryption then
    Result := GetReducedBlockSize(FEngine.InputBlockSize)
  else
    Result := FEngine.InputBlockSize;
end;

function TOaepEncoding.GetOutputBlockSize: Int32;
begin
  if FForEncryption then
    Result := FEngine.OutputBlockSize
  else
    Result := GetReducedBlockSize(FEngine.OutputBlockSize);
end;

function TOaepEncoding.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
begin
  if FForEncryption then
    Result := EncodeBlock(AInBuf, AInOff, AInLen)
  else
    Result := DecodeBlock(AInBuf, AInOff, AInLen);
end;

function TOaepEncoding.EncodeBlock(const AInBytes: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LInBlockSize, LDefHashLen: Int32;
  LBlock: TCryptoLibByteArray;
begin
  LInBlockSize := FEngine.InputBlockSize;
  LDefHashLen := System.Length(FDefHash);

  if AInLen > GetReducedBlockSize(LInBlockSize) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputDataTooLong);
  end;

  SetLength(LBlock, LInBlockSize);

  System.Move(AInBytes[AInOff], LBlock[System.Length(LBlock) - AInLen], AInLen);

  LBlock[System.Length(LBlock) - AInLen - 1] := $01;

  System.Move(FDefHash[0], LBlock[LDefHashLen], LDefHashLen);

  FRandom.NextBytes(LBlock, 0, LDefHashLen);

  FMgf1Hash.Reset();

  MaskGeneratorFunction(LBlock, 0, LDefHashLen,
    LBlock, LDefHashLen, System.Length(LBlock) - LDefHashLen);

  MaskGeneratorFunction(LBlock, LDefHashLen, System.Length(LBlock) - LDefHashLen,
    LBlock, 0, LDefHashLen);

  Result := FEngine.ProcessBlock(LBlock, 0, System.Length(LBlock));
end;

function TOaepEncoding.DecodeBlock(const AInBytes: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LOutBlockSize, LDefHashLen, LWrongMask, LCopyLen: Int32;
  LBlock, LData: TCryptoLibByteArray;
  LStart, LIndex, LOctet, LShouldSetMask: Int32;
  LI: Int32;
begin
  LOutBlockSize := FEngine.OutputBlockSize;
  LDefHashLen := System.Length(FDefHash);

  LWrongMask := TBitOperations.Asr32(GetReducedBlockSize(LOutBlockSize), 31);

  SetLength(LBlock, LOutBlockSize);
  LData := FEngine.ProcessBlock(AInBytes, AInOff, AInLen);

  LWrongMask := LWrongMask or TBitOperations.Asr32((System.Length(LBlock) - System.Length(LData)), 31);

  LCopyLen := System.Length(LData);
  if LCopyLen > System.Length(LBlock) then
    LCopyLen := System.Length(LBlock);

  System.Move(LData[0], LBlock[System.Length(LBlock) - LCopyLen], LCopyLen);
  TArrayUtilities.Fill<Byte>(LData, 0, System.Length(LData), Byte(0));

  FMgf1Hash.Reset();

  MaskGeneratorFunction(LBlock, LDefHashLen, System.Length(LBlock) - LDefHashLen,
    LBlock, 0, LDefHashLen);

  MaskGeneratorFunction(LBlock, 0, LDefHashLen,
    LBlock, LDefHashLen, System.Length(LBlock) - LDefHashLen);

  for LI := 0 to LDefHashLen - 1 do
  begin
    LWrongMask := LWrongMask or (FDefHash[LI] xor LBlock[LDefHashLen + LI]);
  end;

  LStart := -1;
  for LIndex := 2 * LDefHashLen to System.Length(LBlock) - 1 do
  begin
    LOctet := LBlock[LIndex];
    LShouldSetMask := TBitOperations.Asr32((-LOctet) and LStart, 31);
    LStart := LStart + (LIndex and LShouldSetMask);
  end;

  LWrongMask := LWrongMask or TBitOperations.Asr32(LStart, 31);
  Inc(LStart);
  LWrongMask := LWrongMask or (LBlock[LStart] xor 1);

  if LWrongMask <> 0 then
  begin
    TArrayUtilities.Fill<Byte>(LBlock, 0, System.Length(LBlock), Byte(0));
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataWrong);
  end;

  Inc(LStart);

  SetLength(Result, System.Length(LBlock) - LStart);
  System.Move(LBlock[LStart], Result[0], System.Length(Result));
  TArrayUtilities.Fill<Byte>(LBlock, 0, System.Length(LBlock), Byte(0));
end;

procedure TOaepEncoding.MaskGeneratorFunction(
  const AZ: TCryptoLibByteArray; AZOff, AZLen: Int32;
  const AMask: TCryptoLibByteArray; AMaskOff, AMaskLen: Int32);
var
  LDigestSize, LCounter, LMaskPos, LMaskEnd, LMaskLimit, LXorLen: Int32;
  LHash, LC: TCryptoLibByteArray;
  LI: Int32;
begin
  LDigestSize := FMgf1Hash.GetDigestSize;
  SetLength(LHash, LDigestSize);
  SetLength(LC, 4);
  LCounter := 0;

  LMaskEnd := AMaskOff + AMaskLen;
  LMaskLimit := LMaskEnd - LDigestSize;
  LMaskPos := AMaskOff;

  while LMaskPos < LMaskLimit do
  begin
    LC[0] := Byte(LCounter shr 24);
    LC[1] := Byte(LCounter shr 16);
    LC[2] := Byte(LCounter shr 8);
    LC[3] := Byte(LCounter);

    FMgf1Hash.Reset();
    FMgf1Hash.BlockUpdate(AZ, AZOff, AZLen);
    FMgf1Hash.BlockUpdate(LC, 0, 4);
    FMgf1Hash.DoFinal(LHash, 0);

    for LI := 0 to LDigestSize - 1 do
    begin
      AMask[LMaskPos + LI] := AMask[LMaskPos + LI] xor LHash[LI];
    end;

    Inc(LMaskPos, LDigestSize);
    Inc(LCounter);
  end;

  if LMaskPos < LMaskEnd then
  begin
    LC[0] := Byte(LCounter shr 24);
    LC[1] := Byte(LCounter shr 16);
    LC[2] := Byte(LCounter shr 8);
    LC[3] := Byte(LCounter);

    FMgf1Hash.Reset();
    FMgf1Hash.BlockUpdate(AZ, AZOff, AZLen);
    FMgf1Hash.BlockUpdate(LC, 0, 4);
    FMgf1Hash.DoFinal(LHash, 0);

    LXorLen := LMaskEnd - LMaskPos;
    for LI := 0 to LXorLen - 1 do
    begin
      AMask[LMaskPos + LI] := AMask[LMaskPos + LI] xor LHash[LI];
    end;
  end;
end;

end.
