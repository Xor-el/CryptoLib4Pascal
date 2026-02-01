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

unit ClpX25519PrivateKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpX25519,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIX25519PrivateKeyParameters,
  ClpIX25519PublicKeyParameters,
  ClpX25519PublicKeyParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPrivateKey = 'EOF encountered in middle of X25519 private key';
  SAgreementCalculationFailed = 'X25519 Agreement Failed';
  SMustHaveLengthKeySize = 'must have length %d';

type
  TX25519PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX25519PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;
  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public

    const
    KeySize = Int32(TX25519.ScalarSize);
    SecretSize = Int32(TX25519.PointSize);

    constructor Create(const ARandom: ISecureRandom); overload;
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;

    procedure Encode(const buf: TCryptoLibByteArray; off: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;
    function GeneratePublicKey(): IX25519PublicKeyParameters; inline;
    procedure GenerateSecret(const publicKey: IX25519PublicKeyParameters;
      const buf: TCryptoLibByteArray; off: Int32);

    function Equals(const other: IX25519PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TX25519PrivateKeyParameters }

function TX25519PrivateKeyParameters.GeneratePublicKey
  : IX25519PublicKeyParameters;
var
  publicKey: TCryptoLibByteArray;
begin
  System.SetLength(publicKey, TX25519.PointSize);
  TX25519.GeneratePublicKey(FData, 0, publicKey, 0);
  result := TX25519PublicKeyParameters.Create(publicKey, 0);
end;

procedure TX25519PrivateKeyParameters.GenerateSecret(const publicKey
  : IX25519PublicKeyParameters; const buf: TCryptoLibByteArray; off: Int32);
var
  encoded: TCryptoLibByteArray;
begin
  System.SetLength(encoded, TX25519.PointSize);
  publicKey.Encode(encoded, 0);
  if (not(TX25519.CalculateAgreement(FData, 0, encoded, 0, buf, off))) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SAgreementCalculationFailed);
  end;
end;

function TX25519PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  result := System.Copy(FData);
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
  Inherited Create(true);
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
  Inherited Create(true);
  System.SetLength(FData, TX25519PrivateKeyParameters.KeySize);
  System.Move(ABuf[AOff], FData[0], TX25519PrivateKeyParameters.KeySize * System.SizeOf(Byte));
end;

constructor TX25519PrivateKeyParameters.Create(AInput: TStream);
begin
  Inherited Create(true);
  System.SetLength(FData, TX25519PrivateKeyParameters.KeySize);
  if (TX25519PrivateKeyParameters.KeySize <> TStreamUtilities.ReadFully(AInput, FData)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPrivateKey);
  end;
end;

procedure TX25519PrivateKeyParameters.Encode(const buf: TCryptoLibByteArray;
  off: Int32);
begin
  System.Move(FData[0], buf[off], TX25519PrivateKeyParameters.KeySize * System.SizeOf(Byte));
end;

function TX25519PrivateKeyParameters.Equals(const other
  : IX25519PrivateKeyParameters): Boolean;
begin
  if (other = Self as IX25519PrivateKeyParameters) then
  begin
    result := true;
    Exit;
  end;

  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := TArrayUtilities.FixedTimeEquals(FData, other.GetEncoded())
end;

function TX25519PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := TArrayUtilities.GetArrayHashCode(FData);
end;

end.
