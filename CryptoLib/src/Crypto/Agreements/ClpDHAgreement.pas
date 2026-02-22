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

unit ClpDHAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpISecureRandom,
  ClpCryptoServicesRegistrar,
  ClpICipherParameters,
  ClpIDHAgreement,
  ClpIDHParameters,
  ClpDHParameters,
  ClpDHGenerators,
  ClpIDHGenerators,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes;

resourcestring
  SDHPublicKeyWrongParameter =
    'Diffie-Hellman Public Key has Wrong Parameters.';
  SNotDHPrivateKeyParameters = 'DHEngine Expects DHPrivateKeyParameters';
  SMessageNotInitialized = 'Message not Initialised';
  SSharedKeyInvalid = 'Shared Key Can''t be 1';
  SDHPublicKeyWeak = 'Diffie-Hellman Public Key is Weak';
  SDHPublicKeyNil = 'DH Public Key Parameter Cannot be Nil';

type
  /// <summary>
  /// <para>
  /// a Diffie-Hellman key exchange engine.
  /// </para>
  /// <para>
  /// note: This uses MTI/A0 key agreement in order to make the key
  /// agreement secure against passive attacks. If you're doing
  /// Diffie-Hellman and both parties have long term public keys you
  /// should look at using this. For further information have a look at
  /// RFC 2631.
  /// </para>
  /// <para>
  /// It's possible to extend this to more than two parties as well, for
  /// the moment that is left as an exercise for the reader.
  /// </para>
  /// </summary>
  TDHAgreement = class(TInterfacedObject, IDHAgreement)

  strict private
  var
    FKey: IDHPrivateKeyParameters;
    FDhParams: IDHParameters;
    FPrivateValue: TBigInteger;
    FRandom: ISecureRandom;

  public
    /// <summary>
    /// initialise the agreement engine.
    /// </summary>
    procedure Init(const AParameters: ICipherParameters);

    /// <summary>
    /// calculate our initial message.
    /// </summary>
    function CalculateMessage(): TBigInteger;

    /// <summary>
    /// given a message from a given party and the corresponding public key
    /// calculate the next message in the agreement sequence. In this case
    /// this will represent the shared secret.
    /// </summary>
    function CalculateAgreement(const APub: IDHPublicKeyParameters;
      const AMessage: TBigInteger): TBigInteger;

  end;

implementation

{ TDHAgreement }

function TDHAgreement.CalculateAgreement(const APub: IDHPublicKeyParameters;
  const AMessage: TBigInteger): TBigInteger;
var
  LP, LPeerY: TBigInteger;
begin
  if (APub = nil) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SDHPublicKeyNil);

  if not AMessage.IsInitialized then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SMessageNotInitialized);

  if not APub.Parameters.Equals(FDhParams) then
    raise EArgumentCryptoLibException.CreateRes(@SDHPublicKeyWrongParameter);

  LP := FDhParams.P;

  LPeerY := APub.Y;

  if ((not LPeerY.IsInitialized) or (LPeerY.CompareTo(TBigInteger.One) <= 0) or
    (LPeerY.CompareTo(LP.Subtract(TBigInteger.One)) >= 0)) then
    raise EArgumentCryptoLibException.CreateRes(@SDHPublicKeyWeak);

  Result := LPeerY.ModPow(FPrivateValue, LP);

  if Result.Equals(TBigInteger.One) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSharedKeyInvalid);

  Result := AMessage.ModPow(FKey.X, LP).Multiply(Result).&Mod(LP);
end;

function TDHAgreement.CalculateMessage: TBigInteger;
var
  LDHGen: IDHKeyPairGenerator;
  LGenParams: IDHKeyGenerationParameters;
  LDHPair: IAsymmetricCipherKeyPair;
  LDHPriv: IDHPrivateKeyParameters;
  LDHPub: IDHPublicKeyParameters;
begin
  LDHGen := TDHKeyPairGenerator.Create();

  LGenParams := TDHKeyGenerationParameters.Create(FRandom, FDhParams);
  LDHGen.Init(LGenParams);

  LDHPair := LDHGen.GenerateKeyPair();

  if not Supports(LDHPair.Private, IDHPrivateKeyParameters, LDHPriv) then
    raise EInvalidCastCryptoLibException.CreateRes(@SNotDHPrivateKeyParameters);
  FPrivateValue := LDHPriv.X;

  if not Supports(LDHPair.Public, IDHPublicKeyParameters, LDHPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SDHPublicKeyWrongParameter);
  Result := LDHPub.Y;
end;

procedure TDHAgreement.Init(const AParameters: ICipherParameters);
var
  LKParam: IAsymmetricKeyParameter;
  LRParam: IParametersWithRandom;
  LDHPriv: IDHPrivateKeyParameters;
begin
  if Supports(AParameters, IParametersWithRandom, LRParam) then
  begin
    FRandom := LRParam.Random;
    if not Supports(LRParam.Parameters, IAsymmetricKeyParameter, LKParam) then
      raise EArgumentCryptoLibException.CreateRes(@SNotDHPrivateKeyParameters);
  end
  else
  begin
    FRandom := TCryptoServicesRegistrar.GetSecureRandom();
    if not Supports(AParameters, IAsymmetricKeyParameter, LKParam) then
      raise EArgumentCryptoLibException.CreateRes(@SNotDHPrivateKeyParameters);
  end;

  if not Supports(LKParam, IDHPrivateKeyParameters, LDHPriv) then
    raise EArgumentCryptoLibException.CreateRes(@SNotDHPrivateKeyParameters);

  FKey := LDHPriv;
  FDhParams := FKey.Parameters;
end;

end.
