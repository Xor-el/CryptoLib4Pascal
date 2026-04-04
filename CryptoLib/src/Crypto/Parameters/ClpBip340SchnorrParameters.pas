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

unit ClpBip340SchnorrParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsymmetricKeyParameter,
  ClpIECParameters,
  ClpIECCommon,
  ClpIBip340SchnorrParameters,
  ClpKeyGenerationParameters,
  ClpBip340SchnorrUtilities,
  ClpECUtilities,
  ClpECParameters,
  ClpECAlgorithms,
  ClpIX9ECAsn1Objects,
  ClpBigInteger,
  ClpArrayUtilities,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SMustHaveLengthKeySize = 'must have length %d';
  SInvalidPublicKey = 'invalid public key';
  SInvalidPrivateKey = 'invalid private key (zero or >= n)';

type
  TBip340SchnorrPublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IBip340SchnorrPublicKeyParameters)
  strict private
    var
      FPubKey: TCryptoLibByteArray;
  public
    const
      KeySize = Int32(TBip340SchnorrUtilities.BIP340_PUBKEY_SIZE);

    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Equals(const AOther: IBip340SchnorrPublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  TBip340SchnorrPrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IBip340SchnorrPrivateKeyParameters)
  strict private
    var
      FData: TCryptoLibByteArray;
      FCachedPublicKey: IBip340SchnorrPublicKeyParameters;
  public
    const
      KeySize = Int32(TBip340SchnorrUtilities.BIP340_SECKEY_SIZE);

    constructor Create(const ARandom: ISecureRandom); overload;
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;
    function GeneratePublicKey(): IBip340SchnorrPublicKeyParameters;

    function Equals(const AOther: IBip340SchnorrPrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  TBip340SchnorrKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IBip340SchnorrKeyGenerationParameters)
  public
    constructor Create(const ARandom: ISecureRandom);
  end;

implementation

{ TBip340SchnorrPublicKeyParameters }

constructor TBip340SchnorrPublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TBip340SchnorrPublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
begin
  inherited Create(False);
  if (ABuf = nil) or (System.Length(ABuf) - AOff < KeySize) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
  System.SetLength(FPubKey, KeySize);
  System.Move(ABuf[AOff], FPubKey[0], KeySize * System.SizeOf(Byte));
  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
    raise EInvalidOperationCryptoLibException.Create('secp256k1 curve not found');
  LDomain := TECDomainParameters.FromX9ECParameters(LX9);
  TBip340SchnorrUtilities.LiftX(LDomain, FPubKey);
end;

procedure TBip340SchnorrPublicKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FPubKey[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TBip340SchnorrPublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FPubKey);
end;

function TBip340SchnorrPublicKeyParameters.Equals(const AOther: IBip340SchnorrPublicKeyParameters): Boolean;
var
  LEncoded, LOtherEncoded: TCryptoLibByteArray;
begin
  if (AOther = Self as IBip340SchnorrPublicKeyParameters) then
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

function TBip340SchnorrPublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(GetEncoded());
end;

{ TBip340SchnorrPrivateKeyParameters }

function TBip340SchnorrPrivateKeyParameters.GeneratePublicKey: IBip340SchnorrPublicKeyParameters;
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
  LD: TBigInteger;
  LP: IECPoint;
  LPubBytes: TCryptoLibByteArray;
begin
  if FCachedPublicKey = nil then
  begin
    LX9 := TECUtilities.FindECCurveByName('secp256k1');
    if LX9 = nil then
      raise EInvalidOperationCryptoLibException.Create('secp256k1 curve not found');
    LDomain := TECDomainParameters.FromX9ECParameters(LX9);
    LD := TBigInteger.Create(1, FData).&Mod(LDomain.N);
    if (LD.SignValue = 0) or (LD.CompareTo(LDomain.N) >= 0) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidPrivateKey);
    LP := TECAlgorithms.ReferenceMultiply(LDomain.G, LD).Normalize();
    if (not TBip340SchnorrUtilities.HasEvenY(LP)) then
      LP := LP.Negate();
    LPubBytes := TBip340SchnorrUtilities.BytesFromPoint(LP);
    FCachedPublicKey := TBip340SchnorrPublicKeyParameters.Create(LPubBytes);
  end;
  Result := FCachedPublicKey;
end;

constructor TBip340SchnorrPrivateKeyParameters.Create(const ARandom: ISecureRandom);
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
  LN: TBigInteger;
  LD: TBigInteger;
begin
  inherited Create(True);
  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
    raise EInvalidOperationCryptoLibException.Create('secp256k1 curve not found');
  LDomain := TECDomainParameters.FromX9ECParameters(LX9);
  LN := LDomain.N;
  System.SetLength(FData, KeySize);
  repeat
    ARandom.NextBytes(FData);
    LD := TBigInteger.Create(1, FData).&Mod(LN);
  until (LD.SignValue > 0) and (LD.CompareTo(LN) < 0);
end;

constructor TBip340SchnorrPrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TBip340SchnorrPrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
  LD: TBigInteger;
begin
  inherited Create(True);
  if (ABuf = nil) or (System.Length(ABuf) - AOff < KeySize) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPrivateKey);
  System.SetLength(FData, KeySize);
  System.Move(ABuf[AOff], FData[0], KeySize * System.SizeOf(Byte));
  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
    raise EInvalidOperationCryptoLibException.Create('secp256k1 curve not found');
  LDomain := TECDomainParameters.FromX9ECParameters(LX9);
  LD := TBigInteger.Create(1, FData).&Mod(LDomain.N);
  if (LD.SignValue = 0) or (LD.CompareTo(LDomain.N) >= 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPrivateKey);
end;

procedure TBip340SchnorrPrivateKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TBip340SchnorrPrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

function TBip340SchnorrPrivateKeyParameters.Equals(const AOther: IBip340SchnorrPrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IBip340SchnorrPrivateKeyParameters) then
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

function TBip340SchnorrPrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

{ TBip340SchnorrKeyGenerationParameters }

constructor TBip340SchnorrKeyGenerationParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(ARandom, 256);
end;

end.
