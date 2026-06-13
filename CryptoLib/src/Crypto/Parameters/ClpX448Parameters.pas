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

unit ClpX448Parameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpX448,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIX448Parameters,
  ClpKeyGenerationParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPublicKey = 'EOF encountered in middle of X448 public key';
  SMustHaveLengthKeySize = 'must have length %d';
  SEOFInPrivateKey = 'EOF encountered in middle of X448 private key';
  SAgreementCalculationFailed = 'X448 agreement failed';

type
  /// <summary>
  /// X448 public key (RFC 7748). Holds the 56-byte u-coordinate of the peer's curve point. The
  /// encoding is stored verbatim; validation of the point is performed during scalar multiplication
  /// in the agreement primitive.
  /// </summary>
  TX448PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX448PublicKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;

  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public
    /// <summary>Length in bytes of an X448 public key encoding (56).</summary>
    const
    KeySize = Int32(TX448.PointSize);

    /// <summary>Construct from a 56-byte buffer holding the encoded u-coordinate.</summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If <paramref name="ABuf"/> length differs from <see cref="KeySize"/>.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    /// <summary>
    /// Construct from <paramref name="ABuf"/> at <paramref name="AOff"/>; reads
    /// <see cref="KeySize"/> bytes.
    /// </summary>
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    /// <summary>Read the 56-byte encoded u-coordinate from <paramref name="AInput"/>.</summary>
    /// <exception cref="EEndOfStreamCryptoLibException">
    /// If the stream ends before <see cref="KeySize"/> bytes have been read.
    /// </exception>
    constructor Create(AInput: TStream); overload;

    /// <summary>
    /// Write the 56-byte encoded u-coordinate into <paramref name="ABuf"/> at <paramref name="AOff"/>.
    /// </summary>
    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    /// <summary>Return a fresh copy of the 56-byte encoded u-coordinate.</summary>
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Equals(const AOther: IX448PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  /// <summary>
  /// X448 private key (RFC 7748). Holds the 56-byte clamped scalar used in Curve448
  /// Diffie-Hellman.
  /// </summary>
  TX448PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX448PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;

  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public
    /// <summary>Length in bytes of an X448 private-key scalar (56).</summary>
    const
    KeySize = Int32(TX448.ScalarSize);
    /// <summary>Length in bytes of the shared secret produced by an X448 agreement (56).</summary>
    SecretSize = Int32(TX448.PointSize);

    /// <summary>Generate a fresh random X448 private key using <paramref name="ARandom"/>.
    /// </summary>
    constructor Create(const ARandom: ISecureRandom); overload;
    /// <summary>Construct from a 56-byte scalar buffer.</summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// If <paramref name="ABuf"/> length differs from <see cref="KeySize"/>.
    /// </exception>
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    /// <summary>
    /// Construct from <paramref name="ABuf"/> at <paramref name="AOff"/>; reads
    /// <see cref="KeySize"/> bytes.
    /// </summary>
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    /// <summary>Read the 56-byte scalar from <paramref name="AInput"/>.</summary>
    /// <exception cref="EEndOfStreamCryptoLibException">
    /// If the stream ends before <see cref="KeySize"/> bytes have been read.
    /// </exception>
    constructor Create(AInput: TStream); overload;

    /// <summary>
    /// Write the 56-byte scalar into <paramref name="ABuf"/> at <paramref name="AOff"/>.
    /// </summary>
    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    /// <summary>Return a fresh copy of the 56-byte scalar.</summary>
    function GetEncoded(): TCryptoLibByteArray; inline;
    /// <summary>Compute the public key (u-coordinate) corresponding to this scalar.</summary>
    function GeneratePublicKey(): IX448PublicKeyParameters; inline;
    /// <summary>
    /// Perform an X448 Diffie-Hellman agreement against <paramref name="APublicKey"/> and write the
    /// resulting <see cref="SecretSize"/>-byte shared secret into <paramref name="ABuf"/> starting at
    /// <paramref name="AOff"/>.
    /// </summary>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the agreement produces an all-zero secret (degenerate peer key).
    /// </exception>
    procedure GenerateSecret(const APublicKey: IX448PublicKeyParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    function Equals(const AOther: IX448PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  /// <summary>
  /// Key generation parameters for X448 (RFC 7748). Carries the <see cref="ISecureRandom"/> used for
  /// scalar generation; the strength is fixed at 448 bits.
  /// </summary>
  TX448KeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IX448KeyGenerationParameters)

  public
    /// <summary>
    /// Construct using <paramref name="ARandom"/> as the entropy source for the 56-byte scalar.
    /// </summary>
    constructor Create(const ARandom: ISecureRandom);
  end;

implementation

{ TX448PublicKeyParameters }

class function TX448PublicKeyParameters.Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  if System.Length(ABuf) <> TX448PublicKeyParameters.KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [TX448PublicKeyParameters.KeySize]);
  Result := ABuf;
end;

function TX448PublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

constructor TX448PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  Create(TX448PublicKeyParameters.Validate(ABuf), 0);
end;

constructor TX448PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(False);
  System.SetLength(FData, TX448PublicKeyParameters.KeySize);
  System.Move(ABuf[AOff], FData[0], TX448PublicKeyParameters.KeySize * System.SizeOf(Byte));
end;

constructor TX448PublicKeyParameters.Create(AInput: TStream);
begin
  inherited Create(False);
  System.SetLength(FData, KeySize);
  if (KeySize <> TStreamUtilities.ReadFully(AInput, FData)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPublicKey);
  end;
end;

procedure TX448PublicKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TX448PublicKeyParameters.Equals(const AOther: IX448PublicKeyParameters): Boolean;
begin
  if (AOther = Self as IX448PublicKeyParameters) then
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

function TX448PublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

{ TX448PrivateKeyParameters }

function TX448PrivateKeyParameters.GeneratePublicKey: IX448PublicKeyParameters;
var
  LPublicKey: TCryptoLibByteArray;
begin
  System.SetLength(LPublicKey, TX448.PointSize);
  TX448.GeneratePublicKey(FData, 0, LPublicKey, 0);
  Result := TX448PublicKeyParameters.Create(LPublicKey, 0);
end;

procedure TX448PrivateKeyParameters.GenerateSecret(const APublicKey: IX448PublicKeyParameters;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LEncoded: TCryptoLibByteArray;
begin
  System.SetLength(LEncoded, TX448.PointSize);
  APublicKey.Encode(LEncoded, 0);
  if (not TX448.CalculateAgreement(FData, 0, LEncoded, 0, ABuf, AOff)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SAgreementCalculationFailed);
  end;
end;

function TX448PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

class function TX448PrivateKeyParameters.Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  if System.Length(ABuf) <> TX448PrivateKeyParameters.KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [TX448PrivateKeyParameters.KeySize]);
  Result := ABuf;
end;

constructor TX448PrivateKeyParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(True);
  System.SetLength(FData, TX448PrivateKeyParameters.KeySize);
  TX448.GeneratePrivateKey(ARandom, FData);
end;

constructor TX448PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  Create(TX448PrivateKeyParameters.Validate(ABuf), 0);
end;

constructor TX448PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(True);
  System.SetLength(FData, TX448PrivateKeyParameters.KeySize);
  System.Move(ABuf[AOff], FData[0], TX448PrivateKeyParameters.KeySize * System.SizeOf(Byte));
end;

constructor TX448PrivateKeyParameters.Create(AInput: TStream);
begin
  inherited Create(True);
  System.SetLength(FData, TX448PrivateKeyParameters.KeySize);
  if (TX448PrivateKeyParameters.KeySize <> TStreamUtilities.ReadFully(AInput, FData)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPrivateKey);
  end;
end;

procedure TX448PrivateKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], TX448PrivateKeyParameters.KeySize * System.SizeOf(Byte));
end;

function TX448PrivateKeyParameters.Equals(const AOther: IX448PrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IX448PrivateKeyParameters) then
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

function TX448PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

{ TX448KeyGenerationParameters }

constructor TX448KeyGenerationParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(ARandom, 448);
end;

end.
