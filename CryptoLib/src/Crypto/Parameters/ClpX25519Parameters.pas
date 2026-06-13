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

unit ClpX25519Parameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpX25519,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIX25519Parameters,
  ClpKeyGenerationParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPublicKey = 'EOF encountered in middle of X25519 public key';
  SMustHaveLengthKeySize = 'must have length %d';
  SEOFInPrivateKey = 'EOF encountered in middle of X25519 private key';
  SAgreementCalculationFailed = 'X25519 agreement failed';

type
  /// <summary>
  /// X25519 public key (RFC 7748). Holds the 32-byte u-coordinate of the peer's curve point. The
  /// encoding is stored verbatim; validation of the point is performed during scalar multiplication
  /// in the agreement primitive.
  /// </summary>
  TX25519PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX25519PublicKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;

  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public
    /// <summary>Length in bytes of an X25519 public key encoding (32).</summary>
    const
    KeySize = Int32(TX25519.PointSize);

    /// <summary>Construct from a 32-byte buffer holding the encoded u-coordinate.</summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If <paramref name="ABuf"/> length differs from <see cref="KeySize"/>.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    /// <summary>
    /// Construct from <paramref name="ABuf"/> at <paramref name="AOff"/>; reads
    /// <see cref="KeySize"/> bytes.
    /// </summary>
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    /// <summary>Read the 32-byte encoded u-coordinate from <paramref name="AInput"/>.</summary>
    /// <exception cref="EEndOfStreamCryptoLibException">
    /// If the stream ends before <see cref="KeySize"/> bytes have been read.
    /// </exception>
    constructor Create(AInput: TStream); overload;

    /// <summary>
    /// Write the 32-byte encoded u-coordinate into <paramref name="ABuf"/> at <paramref name="AOff"/>.
    /// </summary>
    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    /// <summary>Return a fresh copy of the 32-byte encoded u-coordinate.</summary>
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Equals(const AOther: IX25519PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  /// <summary>
  /// X25519 private key (RFC 7748). Holds the 32-byte clamped scalar used in Curve25519
  /// Diffie-Hellman.
  /// </summary>
  TX25519PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX25519PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;

  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public
    /// <summary>Length in bytes of an X25519 private-key scalar (32).</summary>
    const
    KeySize = Int32(TX25519.ScalarSize);
    /// <summary>Length in bytes of the shared secret produced by an X25519 agreement (32).</summary>
    SecretSize = Int32(TX25519.PointSize);

    /// <summary>Generate a fresh random X25519 private key using <paramref name="ARandom"/>.
    /// </summary>
    constructor Create(const ARandom: ISecureRandom); overload;
    /// <summary>Construct from a 32-byte scalar buffer.</summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If <paramref name="ABuf"/> length differs from <see cref="KeySize"/>.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    /// <summary>
    /// Construct from <paramref name="ABuf"/> at <paramref name="AOff"/>; reads
    /// <see cref="KeySize"/> bytes.
    /// </summary>
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    /// <summary>Read the 32-byte scalar from <paramref name="AInput"/>.</summary>
    /// <exception cref="EEndOfStreamCryptoLibException">
    /// If the stream ends before <see cref="KeySize"/> bytes have been read.
    /// </exception>
    constructor Create(AInput: TStream); overload;

    /// <summary>
    /// Write the 32-byte scalar into <paramref name="ABuf"/> at <paramref name="AOff"/>.
    /// </summary>
    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    /// <summary>Return a fresh copy of the 32-byte scalar.</summary>
    function GetEncoded(): TCryptoLibByteArray; inline;
    /// <summary>Compute the public key (u-coordinate) corresponding to this scalar.</summary>
    function GeneratePublicKey(): IX25519PublicKeyParameters; inline;
    /// <summary>
    /// Perform an X25519 Diffie-Hellman agreement against <paramref name="APublicKey"/> and write the
    /// resulting <see cref="SecretSize"/>-byte shared secret into <paramref name="ABuf"/> starting at
    /// <paramref name="AOff"/>.
    /// </summary>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the agreement produces an all-zero secret (degenerate peer key).
    /// </exception>
    procedure GenerateSecret(const APublicKey: IX25519PublicKeyParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    function Equals(const AOther: IX25519PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  /// <summary>
  /// Key generation parameters for X25519 (RFC 7748). Carries the <see cref="ISecureRandom"/> used for
  /// scalar generation; the strength is fixed at 255 bits.
  /// </summary>
  TX25519KeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IX25519KeyGenerationParameters)

  public
    /// <summary>
    /// Construct using <paramref name="ARandom"/> as the entropy source for the 32-byte scalar.
    /// </summary>
    constructor Create(const ARandom: ISecureRandom);
  end;

implementation

{ TX25519PublicKeyParameters }

class function TX25519PublicKeyParameters.Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  if System.Length(ABuf) <> TX25519PublicKeyParameters.KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [TX25519PublicKeyParameters.KeySize]);
  Result := ABuf;
end;

function TX25519PublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

constructor TX25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  Create(TX25519PublicKeyParameters.Validate(ABuf), 0);
end;

constructor TX25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(False);
  System.SetLength(FData, TX25519PublicKeyParameters.KeySize);
  System.Move(ABuf[AOff], FData[0], TX25519PublicKeyParameters.KeySize * System.SizeOf(Byte));
end;

constructor TX25519PublicKeyParameters.Create(AInput: TStream);
begin
  inherited Create(False);
  System.SetLength(FData, KeySize);
  if (KeySize <> TStreamUtilities.ReadFully(AInput, FData)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPublicKey);
  end;
end;

procedure TX25519PublicKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TX25519PublicKeyParameters.Equals(const AOther: IX25519PublicKeyParameters): Boolean;
begin
  if (AOther = Self as IX25519PublicKeyParameters) then
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

function TX25519PublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

{ TX25519PrivateKeyParameters }

function TX25519PrivateKeyParameters.GeneratePublicKey: IX25519PublicKeyParameters;
var
  LPublicKey: TCryptoLibByteArray;
begin
  System.SetLength(LPublicKey, TX25519.PointSize);
  TX25519.GeneratePublicKey(FData, 0, LPublicKey, 0);
  Result := TX25519PublicKeyParameters.Create(LPublicKey, 0);
end;

procedure TX25519PrivateKeyParameters.GenerateSecret(const APublicKey: IX25519PublicKeyParameters;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LEncoded: TCryptoLibByteArray;
begin
  System.SetLength(LEncoded, TX25519.PointSize);
  APublicKey.Encode(LEncoded, 0);
  if (not TX25519.CalculateAgreement(FData, 0, LEncoded, 0, ABuf, AOff)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SAgreementCalculationFailed);
  end;
end;

function TX25519PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

class function TX25519PrivateKeyParameters.Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  if System.Length(ABuf) <> TX25519PrivateKeyParameters.KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [TX25519PrivateKeyParameters.KeySize]);
  Result := ABuf;
end;

constructor TX25519PrivateKeyParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(True);
  System.SetLength(FData, TX25519PrivateKeyParameters.KeySize);
  TX25519.GeneratePrivateKey(ARandom, FData);
end;

constructor TX25519PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  Create(TX25519PrivateKeyParameters.Validate(ABuf), 0);
end;

constructor TX25519PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(True);
  System.SetLength(FData, TX25519PrivateKeyParameters.KeySize);
  System.Move(ABuf[AOff], FData[0], TX25519PrivateKeyParameters.KeySize * System.SizeOf(Byte));
end;

constructor TX25519PrivateKeyParameters.Create(AInput: TStream);
begin
  inherited Create(True);
  System.SetLength(FData, TX25519PrivateKeyParameters.KeySize);
  if (TX25519PrivateKeyParameters.KeySize <> TStreamUtilities.ReadFully(AInput, FData)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPrivateKey);
  end;
end;

procedure TX25519PrivateKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], TX25519PrivateKeyParameters.KeySize * System.SizeOf(Byte));
end;

function TX25519PrivateKeyParameters.Equals(const AOther: IX25519PrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IX25519PrivateKeyParameters) then
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

function TX25519PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

{ TX25519KeyGenerationParameters }

constructor TX25519KeyGenerationParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(ARandom, 255);
end;

end.
