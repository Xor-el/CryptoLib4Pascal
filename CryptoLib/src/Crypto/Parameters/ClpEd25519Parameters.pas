{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpEd25519Parameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpEd25519,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIEd25519Parameters,
  ClpKeyGenerationParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPublicKey = 'EOF encountered in middle of Ed25519 public key';
  SInvalidPublicKey = 'invalid public key';
  SMustHaveLengthKeySize = 'must have length %d';
  SEOFInPrivateKey = 'EOF encountered in middle of Ed25519 private key';
  SUnsupportedAlgorithm = 'unsupported algorithm';
  SCtxNotNil = 'ctx must be nil for Ed25519 algorithm';
  SCtxNil = 'ctx must not be nil for Ed25519ctx/Ed25519ph';
  SCtxLength = 'ctx length must be at most 255';
  SMsgLen = 'msgLen must be equal to preHashSize for Ed25519ph algorithm';

type
  /// <summary>
  /// Ed25519 public key (RFC 8032). Wraps a decoded curve point obtained from a 32-byte encoded
  /// representation; the point is validated at construction so that subsequent verifications work
  /// against a known-good key.
  /// </summary>
  TEd25519PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd25519PublicKeyParameters)

  strict private
  var
    FPublicPoint: TEd25519.IPublicPoint;

  public
    /// <summary>Length in bytes of an Ed25519 public key encoding (32).</summary>
    const
    KeySize = Int32(TEd25519.PublicKeySize);

    /// <summary>
    /// Construct from a 32-byte buffer holding the encoded public point.
    /// </summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If <paramref name="ABuf"/> length differs from <see cref="KeySize"/>, or the encoding does
    /// not decode to a valid curve point.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    /// <summary>
    /// Construct from <paramref name="ABuf"/> starting at <paramref name="AOff"/>; reads
    /// <see cref="KeySize"/> bytes.
    /// </summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If the encoded bytes do not decode to a valid curve point.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    /// <summary>Read encoded bytes from <paramref name="AInput"/> and decode them.</summary>
    /// <exception cref="EEndOfStreamCryptoLibException">
    /// If the stream ends before <see cref="KeySize"/> bytes have been read.
    /// </exception>
    /// <exception cref="EArgumentCryptoLibException">
    /// If the encoded bytes do not decode to a valid curve point.
    /// </exception>
    constructor Create(AInput: TStream); overload;
    /// <summary>
    /// Construct from an already-decoded curve point. No further validation is performed.
    /// </summary>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="APublicPoint"/> is nil.
    /// </exception>
    constructor Create(const APublicPoint: TEd25519.IPublicPoint); overload;

    /// <summary>
    /// Write the 32-byte encoded public point into <paramref name="ABuf"/> at <paramref name="AOff"/>.
    /// </summary>
    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    /// <summary>Return a fresh copy of the 32-byte encoded public point.</summary>
    function GetEncoded(): TCryptoLibByteArray; inline;

    /// <summary>
    /// Verify an Ed25519 signature. Selects between pure Ed25519, Ed25519ctx and Ed25519ph based on
    /// <paramref name="AAlgorithm"/>. The pure variant rejects a non-nil context; the context and
    /// prehash variants require a context up to 255 bytes long, and Ed25519ph additionally requires
    /// <paramref name="AMsgLen"/> to equal <see cref="ClpEd25519|TEd25519.PrehashSize"/>.
    /// </summary>
    /// <returns>true if the signature is valid for this key; otherwise false.</returns>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">
    /// If <paramref name="ACtx"/> exceeds 255 bytes, is supplied for pure Ed25519,
    /// <paramref name="AMsgLen"/> is wrong for Ed25519ph, or <paramref name="AAlgorithm"/> is
    /// unrecognised.
    /// </exception>
    function Verify(AAlgorithm: TEd25519.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;

    function Equals(const AOther: IEd25519PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  /// <summary>
  /// Ed25519 private key (RFC 8032). Holds the 32-byte secret seed; the corresponding public key is
  /// derived lazily on first use and cached.
  /// </summary>
  TEd25519PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd25519PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;
    FCachedPublicKey: IEd25519PublicKeyParameters;

  public
    /// <summary>Length in bytes of an Ed25519 private-key seed (32).</summary>
    const
    KeySize = Int32(TEd25519.SecretKeySize);
    /// <summary>Length in bytes of an Ed25519 signature (64).</summary>
    SignatureSize = Int32(TEd25519.SignatureSize);

    /// <summary>Generate a fresh random Ed25519 private key using <paramref name="ARandom"/>.
    /// </summary>
    constructor Create(const ARandom: ISecureRandom); overload;
    /// <summary>Construct from a 32-byte seed buffer.</summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If <paramref name="ABuf"/> length differs from <see cref="KeySize"/>.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    /// <summary>
    /// Construct from <paramref name="ABuf"/> at <paramref name="AOff"/>; reads
    /// <see cref="KeySize"/> bytes.
    /// </summary>
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    /// <summary>Read the 32-byte seed from <paramref name="AInput"/>.</summary>
    /// <exception cref="EEndOfStreamCryptoLibException">
    /// If the stream ends before <see cref="KeySize"/> bytes have been read.
    /// </exception>
    constructor Create(AInput: TStream); overload;

    /// <summary>
    /// Write the 32-byte seed into <paramref name="ABuf"/> at <paramref name="AOff"/>.
    /// </summary>
    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    /// <summary>Return a fresh copy of the 32-byte seed.</summary>
    function GetEncoded(): TCryptoLibByteArray; inline;
    /// <summary>Derive (and cache) the public key corresponding to this private key.</summary>
    function GeneratePublicKey(): IEd25519PublicKeyParameters;

    /// <summary>
    /// Compute an Ed25519 signature. Selects between pure Ed25519, Ed25519ctx and Ed25519ph based on
    /// <paramref name="AAlgorithm"/>. The pure variant rejects a non-nil context; the context and
    /// prehash variants require a context up to 255 bytes long, and Ed25519ph additionally requires
    /// <paramref name="AMsgLen"/> to equal <see cref="ClpEd25519|TEd25519.PrehashSize"/>.
    /// </summary>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">
    /// If <paramref name="ACtx"/> exceeds 255 bytes, is supplied for pure Ed25519,
    /// <paramref name="AMsgLen"/> is wrong for Ed25519ph, or <paramref name="AAlgorithm"/> is
    /// unrecognised.
    /// </exception>
    procedure Sign(AAlgorithm: TEd25519.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32);

    function Equals(const AOther: IEd25519PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  /// <summary>
  /// Key generation parameters for Ed25519 (RFC 8032). Carries the <see cref="ISecureRandom"/> used for
  /// seed generation; the strength is fixed at 256 bits.
  /// </summary>
  TEd25519KeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IEd25519KeyGenerationParameters)

  public
    /// <summary>
    /// Construct using <paramref name="ARandom"/> as the entropy source for the 32-byte seed.
    /// </summary>
    constructor Create(const ARandom: ISecureRandom);
  end;

implementation

{ TEd25519PublicKeyParameters }

constructor TEd25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TEd25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
var
  LPoint: TEd25519.IPublicPoint;
begin
  inherited Create(False);
  LPoint := TEd25519.ValidatePublicKeyPartialExport(ABuf, AOff);
  if LPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := LPoint;
end;

constructor TEd25519PublicKeyParameters.Create(AInput: TStream);
var
  LData: TCryptoLibByteArray;
  LPoint: TEd25519.IPublicPoint;
begin
  inherited Create(False);
  System.SetLength(LData, KeySize);
  if KeySize <> TStreamUtilities.ReadFully(AInput, LData) then
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPublicKey);
  LPoint := TEd25519.ValidatePublicKeyPartialExport(LData, 0);
  if LPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := LPoint;
end;

constructor TEd25519PublicKeyParameters.Create(const APublicPoint: TEd25519.IPublicPoint);
begin
  inherited Create(False);
  if APublicPoint = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := APublicPoint;
end;

procedure TEd25519PublicKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  TEd25519.EncodePublicPoint(FPublicPoint, ABuf, AOff);
end;

function TEd25519PublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  System.SetLength(Result, KeySize);
  Encode(Result, 0);
end;

function TEd25519PublicKeyParameters.Verify(AAlgorithm: TEd25519.TAlgorithm;
  const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;
var
  LEd25519: TEd25519;
begin
  LEd25519 := TEd25519.Create();
  try
    case AAlgorithm of
      TEd25519.TAlgorithm.Ed25519:
        begin
          if ACtx <> nil then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidPublicKey);
          Result := LEd25519.Verify(ASig, ASigOff, FPublicPoint, AMsg, AMsgOff,
            AMsgLen);
        end;
      TEd25519.TAlgorithm.Ed25519ctx:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes
              (@SInvalidPublicKey);
          Result := LEd25519.Verify(ASig, ASigOff, FPublicPoint, ACtx, AMsg,
            AMsgOff, AMsgLen);
        end;
      TEd25519.TAlgorithm.Ed25519ph:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes
              (@SInvalidPublicKey);
          if TEd25519.PrehashSize <> AMsgLen then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes
              (@SInvalidPublicKey);
          Result := LEd25519.VerifyPreHash(ASig, ASigOff, FPublicPoint, ACtx,
            AMsg, AMsgOff);
        end
    else
      raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidPublicKey);
    end;
  finally
    LEd25519.Free;
  end;
end;

function TEd25519PublicKeyParameters.Equals(const AOther: IEd25519PublicKeyParameters): Boolean;
var
  LEncoded, LOtherEncoded: TCryptoLibByteArray;
begin
  if (AOther = Self as IEd25519PublicKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  LEncoded := GetEncoded();
  LOtherEncoded := AOther.GetEncoded();
  Result := TArrayUtilities.FixedTimeEquals(LEncoded, LOtherEncoded);
end;

function TEd25519PublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(GetEncoded());
end;

{ TEd25519PrivateKeyParameters }

function TEd25519PrivateKeyParameters.GeneratePublicKey: IEd25519PublicKeyParameters;
var
  LEd25519: TEd25519;
  LPoint: TEd25519.IPublicPoint;
begin
  if FCachedPublicKey = nil then
  begin
    LEd25519 := TEd25519.Create();
    try
      LPoint := LEd25519.GeneratePublicKey(FData, 0);
      FCachedPublicKey := TEd25519PublicKeyParameters.Create(LPoint);
    finally
      LEd25519.Free;
    end;
  end;
  Result := FCachedPublicKey;
end;

function TEd25519PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

constructor TEd25519PrivateKeyParameters.Create(const ARandom: ISecureRandom);
var
  LEd25519: TEd25519;
begin
  inherited Create(True);
  System.SetLength(FData, KeySize);
  LEd25519 := TEd25519.Create();
  try
    LEd25519.GeneratePrivateKey(ARandom, FData);
  finally
    LEd25519.Free;
  end;
end;

constructor TEd25519PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TEd25519PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(True);
  System.SetLength(FData, KeySize);
  System.Move(ABuf[AOff], FData[0], KeySize * System.SizeOf(Byte));
end;

constructor TEd25519PrivateKeyParameters.Create(AInput: TStream);
begin
  inherited Create(True);
  System.SetLength(FData, KeySize);
  if KeySize <> TStreamUtilities.ReadFully(AInput, FData) then
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPrivateKey);
end;

procedure TEd25519PrivateKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TEd25519PrivateKeyParameters.Equals(const AOther: IEd25519PrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IEd25519PrivateKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.FixedTimeEquals(FData, AOther.GetEncoded());
end;

function TEd25519PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

procedure TEd25519PrivateKeyParameters.Sign(AAlgorithm: TEd25519.TAlgorithm;
  const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LPublicKey: IEd25519PublicKeyParameters;
  LPk: TCryptoLibByteArray;
  LEd25519: TEd25519;
begin
  LPublicKey := GeneratePublicKey();
  System.SetLength(LPk, TEd25519.PublicKeySize);
  LPublicKey.Encode(LPk, 0);

  LEd25519 := TEd25519.Create();
  try
    case AAlgorithm of
      TEd25519.TAlgorithm.Ed25519:
        begin
          if ACtx <> nil then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCtxNotNil);
          LEd25519.Sign(FData, 0, LPk, 0, AMsg, AMsgOff, AMsgLen, ASig, ASigOff);
        end;

      TEd25519.TAlgorithm.Ed25519ctx:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCtxLength);
          LEd25519.Sign(FData, 0, LPk, 0, ACtx, AMsg, AMsgOff, AMsgLen, ASig,
            ASigOff);
        end;

      TEd25519.TAlgorithm.Ed25519ph:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCtxLength);
          if TEd25519.PrehashSize <> AMsgLen then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SMsgLen);
          LEd25519.SignPrehash(FData, 0, LPk, 0, ACtx, AMsg, AMsgOff, ASig,
            ASigOff);
        end
    else
      raise EInvalidOperationCryptoLibException.CreateRes(@SUnsupportedAlgorithm);
    end;
  finally
    LEd25519.Free;
  end;
end;

{ TEd25519KeyGenerationParameters }

constructor TEd25519KeyGenerationParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(ARandom, 256);
end;

end.
