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

unit ClpX25519PublicKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpX25519,
  ClpAsymmetricKeyParameter,
  ClpIX25519PublicKeyParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPublicKey = 'EOF encountered in middle of X25519 public key';
  SMustHaveLengthKeySize = 'must have length %d';

type
  TX25519PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX25519PublicKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;
  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public

    const
    KeySize = Int32(TX25519.PointSize);

    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Equals(const other: IX25519PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TX25519PublicKeyParameters }

class function TX25519PublicKeyParameters.Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  if System.Length(ABuf) <> TX25519PublicKeyParameters.KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize, [TX25519PublicKeyParameters.KeySize]);
  Result := ABuf;
end;

function TX25519PublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  result := System.Copy(FData);
end;

constructor TX25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  Create(TX25519PublicKeyParameters.Validate(ABuf), 0);
end;

constructor TX25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  Inherited Create(false);
  System.SetLength(FData, TX25519PublicKeyParameters.KeySize);
  System.Move(ABuf[AOff], FData[0], TX25519PublicKeyParameters.KeySize * System.SizeOf(Byte));
end;

constructor TX25519PublicKeyParameters.Create(AInput: TStream);
begin
  Inherited Create(false);
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

function TX25519PublicKeyParameters.Equals(const other
  : IX25519PublicKeyParameters): Boolean;
begin
  if (other = Self as IX25519PublicKeyParameters) then
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

function TX25519PublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := TArrayUtilities.GetArrayHashCode(FData);
end;

end.
