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

unit ClpPssSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  HlpIHashInfo,
  ClpICipherParameters,
  ClpIAsymmetricBlockCipher,
  ClpIDigest,
  ClpISigner,
  ClpIPssSigner,
  ClpIRsaParameters,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpParameterUtilities,
  ClpBigInteger,
  ClpCryptoLibTypes;

resourcestring
  SKeyTooSmall = 'key too small for specified hash and salt lengths';

type
  /// <summary>
  /// RSA-PSS as described in PKCS# 1 v 2.1.
  /// <para>
  /// Note: the usual value for the salt length is the number of
  /// bytes in the hash function.
  /// </para>
  /// </summary>
  TPssSigner = class(TInterfacedObject, ISigner, IPssSigner)

  public
  const
    TrailerImplicit = Byte($BC);

  strict private
  var
    FContentDigest1, FContentDigest2: IDigest;
    FMgfDigest: IDigest;
    FCipher: IAsymmetricBlockCipher;
    FRandom: ISecureRandom;
    FHLen: Int32;
    FMgfhLen: Int32;
    FSLen: Int32;
    FSSet: Boolean;
    FEmBits: Int32;
    FSalt: TCryptoLibByteArray;
    FMDash: TCryptoLibByteArray;
    FBlock: TCryptoLibByteArray;
    FTrailer: Byte;

    procedure ClearBlock(const ABlock: TCryptoLibByteArray);
    procedure ItoOSP(AI: Int32; const ASP: TCryptoLibByteArray);
    function MaskGeneratorFunction(const AZ: TCryptoLibByteArray;
      AZOff, AZLen, ALength: Int32): TCryptoLibByteArray;
    function MaskGeneratorFunction1(const AZ: TCryptoLibByteArray;
      AZOff, AZLen, ALength: Int32): TCryptoLibByteArray;

  strict protected
    function GetAlgorithmName: String;

  public
    /// <summary>
    /// Create a raw signer for pre-hashed data with default salt length.
    /// </summary>
    class function CreateRawSigner(const cipher: IAsymmetricBlockCipher;
      const digest: IDigest): IPssSigner; overload; static;

    /// <summary>
    /// Create a raw signer for pre-hashed data with specified salt length.
    /// </summary>
    class function CreateRawSigner(const cipher: IAsymmetricBlockCipher;
      const digest: IDigest; saltLen: Int32): IPssSigner; overload; static;

    /// <summary>
    /// Create a raw signer for pre-hashed data with separate content/MGF digests.
    /// </summary>
    class function CreateRawSigner(const cipher: IAsymmetricBlockCipher;
      const contentDigest, mgfDigest: IDigest; saltLen: Int32;
      trailer: Byte): IPssSigner; overload; static;

    /// <summary>
    /// Create a raw signer for pre-hashed data with fixed salt.
    /// </summary>
    class function CreateRawSigner(const cipher: IAsymmetricBlockCipher;
      const contentDigest, mgfDigest: IDigest;
      const salt: TCryptoLibByteArray; trailer: Byte): IPssSigner; overload; static;

    constructor Create(const cipher: IAsymmetricBlockCipher;
      const digest: IDigest); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const digest: IDigest; saltLen: Int32); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const digest: IDigest; const salt: TCryptoLibByteArray); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const contentDigest, mgfDigest: IDigest; saltLen: Int32); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const contentDigest, mgfDigest: IDigest;
      const salt: TCryptoLibByteArray); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const digest: IDigest; saltLen: Int32; trailer: Byte); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const contentDigest, mgfDigest: IDigest; saltLen: Int32;
      trailer: Byte); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const contentDigest1, contentDigest2, mgfDigest: IDigest;
      saltLen: Int32; const salt: TCryptoLibByteArray;
      trailer: Byte); overload;

    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);
    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature: TCryptoLibByteArray;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

uses
  ClpPrehash;

{ TPssSigner }

class function TPssSigner.CreateRawSigner(const cipher: IAsymmetricBlockCipher;
  const digest: IDigest): IPssSigner;
begin
  Result := TPssSigner.Create(cipher, TPrehash.ForDigest(digest), digest, digest,
    digest.GetDigestSize(), nil, TrailerImplicit);
end;

class function TPssSigner.CreateRawSigner(const cipher: IAsymmetricBlockCipher;
  const digest: IDigest; saltLen: Int32): IPssSigner;
begin
  Result := TPssSigner.Create(cipher, TPrehash.ForDigest(digest), digest, digest,
    saltLen, nil, TrailerImplicit);
end;

class function TPssSigner.CreateRawSigner(const cipher: IAsymmetricBlockCipher;
  const contentDigest, mgfDigest: IDigest; saltLen: Int32;
  trailer: Byte): IPssSigner;
begin
  Result := TPssSigner.Create(cipher, TPrehash.ForDigest(contentDigest),
    contentDigest, mgfDigest, saltLen, nil, trailer);
end;

class function TPssSigner.CreateRawSigner(const cipher: IAsymmetricBlockCipher;
  const contentDigest, mgfDigest: IDigest; const salt: TCryptoLibByteArray;
  trailer: Byte): IPssSigner;
begin
  Result := TPssSigner.Create(cipher, TPrehash.ForDigest(contentDigest),
    contentDigest, mgfDigest, System.Length(salt), salt, trailer);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const digest: IDigest);
begin
  Create(cipher, digest, digest.GetDigestSize());
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const digest: IDigest; saltLen: Int32);
begin
  Create(cipher, digest, saltLen, TrailerImplicit);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const digest: IDigest; const salt: TCryptoLibByteArray);
begin
  Create(cipher, digest, digest, digest, System.Length(salt), salt, TrailerImplicit);
  //Create(cipher, digest.Clone, digest.Clone, digest.Clone, System.Length(salt), salt, TrailerImplicit);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const contentDigest, mgfDigest: IDigest; saltLen: Int32);
begin
  Create(cipher, contentDigest, mgfDigest, saltLen, TrailerImplicit);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const contentDigest, mgfDigest: IDigest;
  const salt: TCryptoLibByteArray);
begin
  Create(cipher, contentDigest, contentDigest, mgfDigest, System.Length(salt),
    salt, TrailerImplicit);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const digest: IDigest; saltLen: Int32; trailer: Byte);
begin
  Create(cipher, digest, digest, saltLen, trailer);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const contentDigest, mgfDigest: IDigest; saltLen: Int32; trailer: Byte);
begin
  Create(cipher, contentDigest, contentDigest, mgfDigest, saltLen, nil, trailer);
end;

constructor TPssSigner.Create(const cipher: IAsymmetricBlockCipher;
  const contentDigest1, contentDigest2, mgfDigest: IDigest;
  saltLen: Int32; const salt: TCryptoLibByteArray; trailer: Byte);
begin
  inherited Create();

  FCipher := cipher;
  FContentDigest1 := contentDigest1;
  FContentDigest2 := contentDigest2;
  FMgfDigest := mgfDigest;
  FHLen := contentDigest2.GetDigestSize();
  FMgfhLen := mgfDigest.GetDigestSize();
  FSLen := saltLen;
  FSSet := salt <> nil;
  if FSSet then
  begin
    FSalt := System.Copy(salt);
  end
  else
  begin
    SetLength(FSalt, saltLen);
  end;
  SetLength(FMDash, 8 + saltLen + FHLen);
  FTrailer := trailer;
end;

function TPssSigner.GetAlgorithmName: String;
begin
  Result := FMgfDigest.AlgorithmName + 'withRSAandMGF1';
end;

procedure TPssSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LKParams: ICipherParameters;
  LProvidedRandom: ISecureRandom;
  LKParam: IRsaKeyParameters;
  LBlinding: IRsaBlindingParameters;
begin
  FCipher.Init(AForSigning, AParameters);

  LKParams := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

  if AForSigning then
  begin
    if LProvidedRandom <> nil then
      FRandom := LProvidedRandom
    else
      FRandom := TSecureRandom.Create();
  end
  else
    FRandom := nil;

  if Supports(LKParams, IRsaBlindingParameters, LBlinding) then
  begin
    LKParam := LBlinding.PublicKey;
  end
  else
  begin
    LKParam := LKParams as IRsaKeyParameters;
  end;

  FEmBits := LKParam.Modulus.BitLength - 1;

  if FEmBits < ((8 * FHLen) + (8 * FSLen) + 9) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKeyTooSmall);
  end;

  SetLength(FBlock, (FEmBits + 7) div 8);
  ClearBlock(FBlock);
end;

procedure TPssSigner.ClearBlock(const ABlock: TCryptoLibByteArray);
begin
  if ABlock <> nil then
    FillChar(ABlock[0], System.Length(ABlock), 0);
end;

procedure TPssSigner.Update(AInput: Byte);
begin
  FContentDigest1.Update(AInput);
end;

procedure TPssSigner.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32);
begin
  FContentDigest1.BlockUpdate(AInput, AInOff, ALength);
end;

function TPssSigner.GenerateSignature: TCryptoLibByteArray;
var
  LH, LDbMask: TCryptoLibByteArray;
  LFirstByteMask: UInt32;
  LI: Int32;
begin
  if FContentDigest1.GetDigestSize() <> FHLen then
  begin
    raise EInvalidOperationCryptoLibException.Create('Digest size mismatch');
  end;

  // Ensure block is zero-initialized before use
  ClearBlock(FBlock);

  // PSS requires first 8 bytes of mDash to be zeros (padding1)
  FillChar(FMDash[0], 8, 0);

  FContentDigest1.DoFinal(FMDash, System.Length(FMDash) - FHLen - FSLen);

  if FSLen <> 0 then
  begin
    if not FSSet then
    begin
      FRandom.NextBytes(FSalt);
    end;
    System.Move(FSalt[0], FMDash[System.Length(FMDash) - FSLen], FSLen);
  end;

  SetLength(LH, FHLen);

  FContentDigest2.BlockUpdate(FMDash, 0, System.Length(FMDash));
  FContentDigest2.DoFinal(LH, 0);

  FBlock[System.Length(FBlock) - FSLen - 1 - FHLen - 1] := $01;
  System.Move(FSalt[0], FBlock[System.Length(FBlock) - FSLen - FHLen - 1], FSLen);

  LDbMask := MaskGeneratorFunction(LH, 0, System.Length(LH),
    System.Length(FBlock) - FHLen - 1);
  for LI := 0 to System.Length(LDbMask) - 1 do
  begin
    FBlock[LI] := FBlock[LI] xor LDbMask[LI];
  end;

  System.Move(LH[0], FBlock[System.Length(FBlock) - FHLen - 1], System.Length(LH));

  LFirstByteMask := $FF shr ((System.Length(FBlock) * 8) - FEmBits);

  FBlock[0] := FBlock[0] and Byte(LFirstByteMask);
  FBlock[System.Length(FBlock) - 1] := FTrailer;

  Result := FCipher.ProcessBlock(FBlock, 0, System.Length(FBlock));

  ClearBlock(FBlock);
end;

function TPssSigner.GetMaxSignatureSize: Int32;
begin
  Result := FCipher.OutputBlockSize;
end;

function TPssSigner.VerifySignature(
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LB, LDbMask: TCryptoLibByteArray;
  LFirstByteMask: UInt32;
  LI, LJ: Int32;
begin
  if FContentDigest1.GetDigestSize() <> FHLen then
  begin
    raise EInvalidOperationCryptoLibException.Create('Digest size mismatch');
  end;

  // PSS requires first 8 bytes of mDash to be zeros (padding1)
  FillChar(FMDash[0], 8, 0);

  FContentDigest1.DoFinal(FMDash, System.Length(FMDash) - FHLen - FSLen);

  LB := FCipher.ProcessBlock(ASignature, 0, System.Length(ASignature));
  
  FillChar(FBlock[0], System.Length(FBlock) - System.Length(LB), 0);
  System.Move(LB[0], FBlock[System.Length(FBlock) - System.Length(LB)],
    System.Length(LB));

  LFirstByteMask := $FF shr ((System.Length(FBlock) * 8) - FEmBits);

  if (FBlock[0] <> Byte(FBlock[0] and LFirstByteMask)) or
     (FBlock[System.Length(FBlock) - 1] <> FTrailer) then
  begin
    ClearBlock(FBlock);
    Result := False;
    Exit;
  end;

  LDbMask := MaskGeneratorFunction(FBlock, System.Length(FBlock) - FHLen - 1,
    FHLen, System.Length(FBlock) - FHLen - 1);

  for LI := 0 to System.Length(LDbMask) - 1 do
  begin
    FBlock[LI] := FBlock[LI] xor LDbMask[LI];
  end;

  FBlock[0] := FBlock[0] and Byte(LFirstByteMask);

  for LI := 0 to System.Length(FBlock) - FHLen - FSLen - 3 do
  begin
    if FBlock[LI] <> 0 then
    begin
      ClearBlock(FBlock);
      Result := False;
      Exit;
    end;
  end;

  if FBlock[System.Length(FBlock) - FHLen - FSLen - 2] <> $01 then
  begin
    ClearBlock(FBlock);
    Result := False;
    Exit;
  end;

  if FSSet then
  begin
    System.Move(FSalt[0], FMDash[System.Length(FMDash) - FSLen], FSLen);
  end
  else
  begin
    System.Move(FBlock[System.Length(FBlock) - FSLen - FHLen - 1],
      FMDash[System.Length(FMDash) - FSLen], FSLen);
  end;

  FContentDigest2.BlockUpdate(FMDash, 0, System.Length(FMDash));
  FContentDigest2.DoFinal(FMDash, System.Length(FMDash) - FHLen);

  LI := System.Length(FBlock) - FHLen - 1;
  LJ := System.Length(FMDash) - FHLen;
  while LJ < System.Length(FMDash) do
  begin
    if (FBlock[LI] xor FMDash[LJ]) <> 0 then
    begin
      ClearBlock(FMDash);
      ClearBlock(FBlock);
      Result := False;
      Exit;
    end;
    Inc(LI);
    Inc(LJ);
  end;

  ClearBlock(FMDash);
  ClearBlock(FBlock);

  Result := True;
end;

procedure TPssSigner.Reset;
begin
  FContentDigest1.Reset();
end;

procedure TPssSigner.ItoOSP(AI: Int32; const ASP: TCryptoLibByteArray);
begin
  ASP[0] := Byte(UInt32(AI) shr 24);
  ASP[1] := Byte(UInt32(AI) shr 16);
  ASP[2] := Byte(UInt32(AI) shr 8);
  ASP[3] := Byte(UInt32(AI) shr 0);
end;

function TPssSigner.MaskGeneratorFunction(const AZ: TCryptoLibByteArray;
  AZOff, AZLen, ALength: Int32): TCryptoLibByteArray;
var
  LMask: TCryptoLibByteArray;
  LXof: IXOF;
begin
  // Check if mgfDigest wraps an XOF hash
  if Supports(FMgfDigest.GetUnderlyingIHash, IXOF, LXof) then
  begin
    SetLength(LMask, ALength);
    LXof.XOFSizeInBits := ALength * 8;
    LXof.Initialize;
    LXof.TransformBytes(AZ, AZOff, AZLen);
    LMask := LXof.TransformFinal.GetBytes();
    Result := LMask;
    Exit;
  end;

  Result := MaskGeneratorFunction1(AZ, AZOff, AZLen, ALength);
end;

function TPssSigner.MaskGeneratorFunction1(const AZ: TCryptoLibByteArray;
  AZOff, AZLen, ALength: Int32): TCryptoLibByteArray;
var
  LMask, LHashBuf, LC: TCryptoLibByteArray;
  LCounter: Int32;
begin
  SetLength(LMask, ALength);
  SetLength(LHashBuf, FMgfhLen);
  SetLength(LC, 4);
  LCounter := 0;

  FMgfDigest.Reset();

  while LCounter < (ALength div FMgfhLen) do
  begin
    ItoOSP(LCounter, LC);

    FMgfDigest.BlockUpdate(AZ, AZOff, AZLen);
    FMgfDigest.BlockUpdate(LC, 0, System.Length(LC));
    FMgfDigest.DoFinal(LHashBuf, 0);

    System.Move(LHashBuf[0], LMask[LCounter * FMgfhLen], System.Length(LHashBuf));
    Inc(LCounter);
  end;

  if (LCounter * FMgfhLen) < ALength then
  begin
    ItoOSP(LCounter, LC);

    FMgfDigest.BlockUpdate(AZ, AZOff, AZLen);
    FMgfDigest.BlockUpdate(LC, 0, System.Length(LC));
    FMgfDigest.DoFinal(LHashBuf, 0);

    System.Move(LHashBuf[0], LMask[LCounter * FMgfhLen],
      System.Length(LMask) - (LCounter * FMgfhLen));
  end;

  Result := LMask;
end;

end.
