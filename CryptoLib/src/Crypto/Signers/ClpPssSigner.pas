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
  ClpIRsaKeyParameters,
  ClpIRsaBlindingParameters,
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
    FhLen: Int32;
    FMgfhLen: Int32;
    FsLen: Int32;
    FSSet: Boolean;
    FEmBits: Int32;
    FSalt: TCryptoLibByteArray;
    FmDash: TCryptoLibByteArray;
    FBlock: TCryptoLibByteArray;
    FTrailer: Byte;

    procedure ClearBlock(const block: TCryptoLibByteArray);
    procedure ItoOSP(i: Int32; const sp: TCryptoLibByteArray);
    function MaskGeneratorFunction(const Z: TCryptoLibByteArray;
      zOff, zLen, length: Int32): TCryptoLibByteArray;
    function MaskGeneratorFunction1(const Z: TCryptoLibByteArray;
      zOff, zLen, length: Int32): TCryptoLibByteArray;

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

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);
    procedure Update(input: Byte);
    procedure BlockUpdate(const input: TCryptoLibByteArray;
      inOff, len: Int32);
    function GenerateSignature: TCryptoLibByteArray;
    function VerifySignature(const signature: TCryptoLibByteArray): Boolean;
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
  FhLen := contentDigest2.GetDigestSize();
  FMgfhLen := mgfDigest.GetDigestSize();
  FsLen := saltLen;
  FSSet := salt <> nil;
  if FSSet then
  begin
    FSalt := System.Copy(salt);
  end
  else
  begin
    SetLength(FSalt, saltLen);
  end;
  SetLength(FmDash, 8 + saltLen + FhLen);
  FTrailer := trailer;
end;

function TPssSigner.GetAlgorithmName: String;
begin
  Result := FMgfDigest.AlgorithmName + 'withRSAandMGF1';
end;

procedure TPssSigner.Init(forSigning: Boolean;
  const parameters: ICipherParameters);
var
  kParams: ICipherParameters;
  providedRandom: ISecureRandom;
  kParam: IRsaKeyParameters;
  blinding: IRsaBlindingParameters;
begin
  FCipher.Init(forSigning, parameters);

  kParams := TParameterUtilities.GetRandom(parameters, providedRandom);

  if forSigning then
  begin
    if providedRandom <> nil then
      FRandom := providedRandom
    else
      FRandom := TSecureRandom.Create();
  end
  else
    FRandom := nil;

  if Supports(kParams, IRsaBlindingParameters, blinding) then
  begin
    kParam := blinding.PublicKey;
  end
  else
  begin
    kParam := kParams as IRsaKeyParameters;
  end;

  FEmBits := kParam.Modulus.BitLength - 1;

  if FEmBits < ((8 * FhLen) + (8 * FsLen) + 9) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKeyTooSmall);
  end;

  // C# creates new array each time, so we must zero it to match behavior
  SetLength(FBlock, (FEmBits + 7) div 8);
  ClearBlock(FBlock);
end;

procedure TPssSigner.ClearBlock(const block: TCryptoLibByteArray);
begin
  if block <> nil then
    FillChar(block[0], System.Length(block), 0);
end;

procedure TPssSigner.Update(input: Byte);
begin
  FContentDigest1.Update(input);
end;

procedure TPssSigner.BlockUpdate(const input: TCryptoLibByteArray;
  inOff, len: Int32);
begin
  FContentDigest1.BlockUpdate(input, inOff, len);
end;

function TPssSigner.GenerateSignature: TCryptoLibByteArray;
var
  h, dbMask: TCryptoLibByteArray;
  firstByteMask: UInt32;
  i: Int32;
begin
  if FContentDigest1.GetDigestSize() <> FhLen then
  begin
    raise EInvalidOperationCryptoLibException.Create('Digest size mismatch');
  end;

  // Ensure block is zero-initialized before use (C# creates new array in Init)
  ClearBlock(FBlock);

  // PSS requires first 8 bytes of mDash to be zeros (padding1)
  FillChar(FmDash[0], 8, 0);

  FContentDigest1.DoFinal(FmDash, System.Length(FmDash) - FhLen - FsLen);

  if FsLen <> 0 then
  begin
    if not FSSet then
    begin
      FRandom.NextBytes(FSalt);
    end;
    System.Move(FSalt[0], FmDash[System.Length(FmDash) - FsLen], FsLen);
  end;

  SetLength(h, FhLen);

  FContentDigest2.BlockUpdate(FmDash, 0, System.Length(FmDash));
  FContentDigest2.DoFinal(h, 0);

  FBlock[System.Length(FBlock) - FsLen - 1 - FhLen - 1] := $01;
  System.Move(FSalt[0], FBlock[System.Length(FBlock) - FsLen - FhLen - 1], FsLen);

  dbMask := MaskGeneratorFunction(h, 0, System.Length(h),
    System.Length(FBlock) - FhLen - 1);
  for i := 0 to System.Length(dbMask) - 1 do
  begin
    FBlock[i] := FBlock[i] xor dbMask[i];
  end;

  System.Move(h[0], FBlock[System.Length(FBlock) - FhLen - 1], System.Length(h));

  firstByteMask := $FF shr ((System.Length(FBlock) * 8) - FEmBits);

  FBlock[0] := FBlock[0] and Byte(firstByteMask);
  FBlock[System.Length(FBlock) - 1] := FTrailer;

  Result := FCipher.ProcessBlock(FBlock, 0, System.Length(FBlock));

  ClearBlock(FBlock);
end;

function TPssSigner.VerifySignature(
  const signature: TCryptoLibByteArray): Boolean;
var
  b, dbMask: TCryptoLibByteArray;
  firstByteMask: UInt32;
  i, j: Int32;
begin
  if FContentDigest1.GetDigestSize() <> FhLen then
  begin
    raise EInvalidOperationCryptoLibException.Create('Digest size mismatch');
  end;

  // PSS requires first 8 bytes of mDash to be zeros (padding1)
  FillChar(FmDash[0], 8, 0);

  FContentDigest1.DoFinal(FmDash, System.Length(FmDash) - FhLen - FsLen);

  b := FCipher.ProcessBlock(signature, 0, System.Length(signature));
  
  FillChar(FBlock[0], System.Length(FBlock) - System.Length(b), 0);
  System.Move(b[0], FBlock[System.Length(FBlock) - System.Length(b)],
    System.Length(b));

  firstByteMask := $FF shr ((System.Length(FBlock) * 8) - FEmBits);

  if (FBlock[0] <> Byte(FBlock[0] and firstByteMask)) or
     (FBlock[System.Length(FBlock) - 1] <> FTrailer) then
  begin
    ClearBlock(FBlock);
    Result := False;
    Exit;
  end;

  dbMask := MaskGeneratorFunction(FBlock, System.Length(FBlock) - FhLen - 1,
    FhLen, System.Length(FBlock) - FhLen - 1);

  for i := 0 to System.Length(dbMask) - 1 do
  begin
    FBlock[i] := FBlock[i] xor dbMask[i];
  end;

  FBlock[0] := FBlock[0] and Byte(firstByteMask);

  for i := 0 to System.Length(FBlock) - FhLen - FsLen - 3 do
  begin
    if FBlock[i] <> 0 then
    begin
      ClearBlock(FBlock);
      Result := False;
      Exit;
    end;
  end;

  if FBlock[System.Length(FBlock) - FhLen - FsLen - 2] <> $01 then
  begin
    ClearBlock(FBlock);
    Result := False;
    Exit;
  end;

  if FSSet then
  begin
    System.Move(FSalt[0], FmDash[System.Length(FmDash) - FsLen], FsLen);
  end
  else
  begin
    System.Move(FBlock[System.Length(FBlock) - FsLen - FhLen - 1],
      FmDash[System.Length(FmDash) - FsLen], FsLen);
  end;

  FContentDigest2.BlockUpdate(FmDash, 0, System.Length(FmDash));
  FContentDigest2.DoFinal(FmDash, System.Length(FmDash) - FhLen);

  i := System.Length(FBlock) - FhLen - 1;
  j := System.Length(FmDash) - FhLen;
  while j < System.Length(FmDash) do
  begin
    if (FBlock[i] xor FmDash[j]) <> 0 then
    begin
      ClearBlock(FmDash);
      ClearBlock(FBlock);
      Result := False;
      Exit;
    end;
    Inc(i);
    Inc(j);
  end;

  ClearBlock(FmDash);
  ClearBlock(FBlock);

  Result := True;
end;

procedure TPssSigner.Reset;
begin
  FContentDigest1.Reset();
end;

procedure TPssSigner.ItoOSP(i: Int32; const sp: TCryptoLibByteArray);
begin
  sp[0] := Byte(UInt32(i) shr 24);
  sp[1] := Byte(UInt32(i) shr 16);
  sp[2] := Byte(UInt32(i) shr 8);
  sp[3] := Byte(UInt32(i) shr 0);
end;

function TPssSigner.MaskGeneratorFunction(const Z: TCryptoLibByteArray;
  zOff, zLen, length: Int32): TCryptoLibByteArray;
var
  mask: TCryptoLibByteArray;
  xof: IXOF;
begin
  // Check if mgfDigest wraps an XOF hash
  if Supports(FMgfDigest.GetUnderlyingIHash, IXOF, xof) then
  begin
    SetLength(mask, length);
    xof.XOFSizeInBits := length * 8;
    xof.Initialize;
    xof.TransformBytes(Z, zOff, zLen);
    mask := xof.TransformFinal.GetBytes();
    Result := mask;
    Exit;
  end;

  Result := MaskGeneratorFunction1(Z, zOff, zLen, length);
end;

function TPssSigner.MaskGeneratorFunction1(const Z: TCryptoLibByteArray;
  zOff, zLen, length: Int32): TCryptoLibByteArray;
var
  mask, hashBuf, C: TCryptoLibByteArray;
  counter: Int32;
begin
  SetLength(mask, length);
  SetLength(hashBuf, FMgfhLen);
  SetLength(C, 4);
  counter := 0;

  FMgfDigest.Reset();

  while counter < (length div FMgfhLen) do
  begin
    ItoOSP(counter, C);

    FMgfDigest.BlockUpdate(Z, zOff, zLen);
    FMgfDigest.BlockUpdate(C, 0, System.Length(C));
    FMgfDigest.DoFinal(hashBuf, 0);

    System.Move(hashBuf[0], mask[counter * FMgfhLen], System.Length(hashBuf));
    Inc(counter);
  end;

  if (counter * FMgfhLen) < length then
  begin
    ItoOSP(counter, C);

    FMgfDigest.BlockUpdate(Z, zOff, zLen);
    FMgfDigest.BlockUpdate(C, 0, System.Length(C));
    FMgfDigest.DoFinal(hashBuf, 0);

    System.Move(hashBuf[0], mask[counter * FMgfhLen],
      System.Length(mask) - (counter * FMgfhLen));
  end;

  Result := mask;
end;

end.
