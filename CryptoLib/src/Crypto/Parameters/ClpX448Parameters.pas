{ *********************************************************************************** }
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
  SAgreementCalculationFailed = 'X448 Agreement Failed';

type
  TX448PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX448PublicKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;

  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public
    const
    KeySize = Int32(TX448.PointSize);

    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Equals(const AOther: IX448PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  TX448PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IX448PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;

  class function Validate(const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; static;

  public
    const
    KeySize = Int32(TX448.ScalarSize);
    SecretSize = Int32(TX448.PointSize);

    constructor Create(const ARandom: ISecureRandom); overload;
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;
    function GeneratePublicKey(): IX448PublicKeyParameters; inline;
    procedure GenerateSecret(const APublicKey: IX448PublicKeyParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    function Equals(const AOther: IX448PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  TX448KeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IX448KeyGenerationParameters)

  public
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
