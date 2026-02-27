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

unit ClpX931Signer;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpIAsymmetricBlockCipher,
  ClpIDigest,
  ClpISigner,
  ClpIRsaParameters,
  ClpIsoTrailers,
  ClpParameterUtilities,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SNoValidTrailer = 'no valid trailer';

type
  /// <summary>
  /// Interface for X9.31 signer.
  /// </summary>
  IX931Signer = interface(ISigner)
    ['{B3C4D5E6-F7A8-9B0C-1D2E-3F4A5B6C7D8E}']
  end;

  /// <summary>
  /// X9.31-1998 - signing using a hash.
  /// <para>
  /// The message digest hash, H, is encapsulated to form a byte string as follows
  /// </para>
  /// <pre>
  /// EB = 06 || PS || 0xBA || H || TRAILER
  /// </pre>
  /// where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|, and TRAILER is the ISO/IEC 10118 part number for the digest. The byte string, EB, is converted to an integer value, the message representative, f.
  /// </summary>
  TX931Signer = class(TInterfacedObject, ISigner, IX931Signer)

  strict private
  var
    FDigest: IDigest;
    FCipher: IAsymmetricBlockCipher;
    FKParam: IRsaKeyParameters;
    FTrailer: Int32;
    FKeyBits: Int32;
    FBlock: TCryptoLibByteArray;

    procedure CreateSignatureBlock;

  strict protected
    function GetAlgorithmName: String;

  public
    /// <summary>
    /// Constructor for a signer with an explicit digest trailer.
    /// </summary>
    /// <param name="ACipher">cipher to use.</param>
    /// <param name="ADigest">digest to sign with.</param>
    constructor Create(const ACipher: IAsymmetricBlockCipher;
      const ADigest: IDigest); overload;

    /// <summary>
    /// Generate a signer with either implicit or explicit trailers for X9.31.
    /// </summary>
    /// <param name="ACipher">base cipher to use for signature creation/verification</param>
    /// <param name="ADigest">digest to use.</param>
    /// <param name="AIsImplicit">whether or not the trailer is implicit or gives the hash.</param>
    constructor Create(const ACipher: IAsymmetricBlockCipher;
      const ADigest: IDigest; AIsImplicit: Boolean); overload;

    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);
    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AOffset, ALength: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature: TCryptoLibByteArray;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TX931Signer }

constructor TX931Signer.Create(const ACipher: IAsymmetricBlockCipher;
  const ADigest: IDigest);
begin
  Create(ACipher, ADigest, False);
end;

constructor TX931Signer.Create(const ACipher: IAsymmetricBlockCipher;
  const ADigest: IDigest; AIsImplicit: Boolean);
begin
  inherited Create();
  FCipher := ACipher;
  FDigest := ADigest;

  if AIsImplicit then
  begin
    FTrailer := TIsoTrailers.TRAILER_IMPLICIT;
  end
  else if TIsoTrailers.NoTrailerAvailable(ADigest) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNoValidTrailer);
  end
  else
  begin
    FTrailer := TIsoTrailers.GetTrailer(ADigest);
  end;
end;

function TX931Signer.GetAlgorithmName: String;
begin
  Result := FDigest.AlgorithmName + 'with' + FCipher.AlgorithmName + '/X9.31';
end;

procedure TX931Signer.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParams: ICipherParameters;
begin
  LKeyParams := TParameterUtilities.IgnoreRandom(AParameters);

  if not Supports(LKeyParams, IRsaKeyParameters, FKParam) then
  begin
    raise EInvalidKeyCryptoLibException.Create('Expected RSA key parameter');
  end;

  FCipher.Init(AForSigning, AParameters);

  FKeyBits := FKParam.Modulus.BitLength;

  System.SetLength(FBlock, (FKeyBits + 7) div 8);

  Reset();
end;

procedure TX931Signer.Update(AInput: Byte);
begin
  FDigest.Update(AInput);
end;

procedure TX931Signer.BlockUpdate(const AInput: TCryptoLibByteArray;
  AOffset, ALength: Int32);
begin
  FDigest.BlockUpdate(AInput, AOffset, ALength);
end;

function TX931Signer.GetMaxSignatureSize: Int32;
begin
  Result := TBigIntegerUtilities.GetUnsignedByteLength(FKParam.Modulus);
end;

function TX931Signer.GenerateSignature: TCryptoLibByteArray;
var
  LSize: Int32;
  LT: TBigInteger;
begin
  CreateSignatureBlock();

  LT := TBigInteger.Create(1, FCipher.ProcessBlock(FBlock, 0,
    System.Length(FBlock)));
  TArrayUtilities.Fill<Byte>(FBlock, 0, System.Length(FBlock), Byte($00));

  LT := LT.Min(FKParam.Modulus.Subtract(LT));

  LSize := TBigIntegerUtilities.GetUnsignedByteLength(FKParam.Modulus);
  Result := TBigIntegerUtilities.AsUnsignedByteArray(LSize, LT);
end;

function TX931Signer.VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
var
  LT, LF: TBigInteger;
  LFBlock: TCryptoLibByteArray;
  LRv: Boolean;
begin
  try
    FBlock := FCipher.ProcessBlock(ASignature, 0, System.Length(ASignature));
  except
    Result := False;
    Exit;
  end;

  LT := TBigInteger.Create(1, FBlock);

  if ((LT.Int32Value and 15) = 12) then
  begin
    LF := LT;
  end
  else
  begin
    LT := FKParam.Modulus.Subtract(LT);
    if ((LT.Int32Value and 15) = 12) then
    begin
      LF := LT;
    end
    else
    begin
      Result := False;
      Exit;
    end;
  end;

  CreateSignatureBlock();

  System.SetLength(LFBlock, System.Length(FBlock));
  LFBlock := TBigIntegerUtilities.AsUnsignedByteArray(System.Length(FBlock), LF);

  LRv := TArrayUtilities.FixedTimeEquals(FBlock, LFBlock);

  TArrayUtilities.Fill<Byte>(FBlock, 0, System.Length(FBlock), Byte($00));
  TArrayUtilities.Fill<Byte>(LFBlock, 0, System.Length(LFBlock), Byte($00));

  Result := LRv;
end;

procedure TX931Signer.Reset;
begin
  FDigest.Reset();
end;

procedure TX931Signer.CreateSignatureBlock;
var
  LDigSize, LDelta, LI: Int32;
begin
  LDigSize := FDigest.GetDigestSize();

  if FTrailer = TIsoTrailers.TRAILER_IMPLICIT then
  begin
    LDelta := System.Length(FBlock) - LDigSize - 1;
    FDigest.DoFinal(FBlock, LDelta);
    FBlock[System.Length(FBlock) - 1] := Byte(TIsoTrailers.TRAILER_IMPLICIT);
  end
  else
  begin
    LDelta := System.Length(FBlock) - LDigSize - 2;
    FDigest.DoFinal(FBlock, LDelta);
    FBlock[System.Length(FBlock) - 2] := Byte(FTrailer shr 8);
    FBlock[System.Length(FBlock) - 1] := Byte(FTrailer);
  end;

  FBlock[0] := $6B;
  LI := LDelta - 2;
  while LI <> 0 do
  begin
    FBlock[LI] := $BB;
    System.Dec(LI);
  end;
  FBlock[LDelta - 1] := $BA;
end;

end.
