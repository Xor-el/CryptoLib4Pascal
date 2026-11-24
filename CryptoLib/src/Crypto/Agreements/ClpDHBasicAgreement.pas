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

unit ClpDHBasicAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpISecureRandom,
  ClpCryptoServicesRegistrar,
  ClpICipherParameters,
  ClpIBasicAgreement,
  ClpIDHBasicAgreement,
  ClpIDHParameters,
  ClpDHParameters,
  ClpIParametersWithRandom,
  ClpCryptoLibExceptions;

resourcestring
  SDHPublicKeyWrongParameter =
    'Diffie-Hellman public key has wrong parameters';
  SNotDHPrivateKeyParameters = 'DHEngine expects DHPrivateKeyParameters';
  SAlgorithmNotInitialized = 'agreement algorithm not initialized';
  SSharedKeyInvalid = 'shared key cannot be 1';

type
  /// <summary>
  /// <para>
  /// a Diffie-Hellman key agreement class.
  /// </para>
  /// <para>
  /// note: This is only the basic algorithm, it doesn't take advantage
  /// of long term public keys if they are available. See the DHAgreement
  /// class for a "better" implementation.
  /// </para>
  /// </summary>
  TDHBasicAgreement = class(TInterfacedObject, IDHBasicAgreement,
    IBasicAgreement)

  strict private
  var
    FKey: IDHPrivateKeyParameters;
    FDhParams: IDHParameters;
    FRandom: ISecureRandom;

  public
    /// <summary>
    /// initialise the agreement engine.
    /// </summary>
    procedure Init(const AParameters: ICipherParameters); virtual;

    /// <summary>
    /// return the field size for the agreement algorithm in bytes.
    /// </summary>
    function GetFieldSize(): Int32; virtual;

    /// <summary>
    /// given a short term public key from a given party calculate the next
    /// message in the agreement sequence.
    /// </summary>
    function CalculateAgreement(const APubKey: ICipherParameters): TBigInteger; virtual;

  end;

implementation

{ TDHBasicAgreement }

function TDHBasicAgreement.CalculateAgreement(const APubKey: ICipherParameters)
  : TBigInteger;
var
  LPub: IDHPublicKeyParameters;
  LPubConcrete: TDHPublicKeyParameters;
  LP, LPeerY: TBigInteger;
begin
  if (FKey = nil) then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SAlgorithmNotInitialized);

  if not Supports(APubKey, IDHPublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SDHPublicKeyWrongParameter);

  if not LPub.Parameters.Equals(FDhParams) then
    raise EArgumentCryptoLibException.CreateRes(@SDHPublicKeyWrongParameter);

  LP := FDhParams.P;

  // a normally-constructed public key already validated its Y (range, and subgroup when q is present); Y is
  // overridable, so re-validate by construction unless pub is exactly the base type
  LPubConcrete := LPub as TDHPublicKeyParameters;
  if LPubConcrete.ClassType = TDHPublicKeyParameters then
    LPeerY := LPub.Y
  else
    LPeerY := TDHPublicKeyParameters.Create(LPub.Y, FDhParams).Y;

  // the exponent is our private value, long lived for static-static agreement, and the peer chooses the base,
  // so blind the base: the variable-time ModPow's timing could otherwise be accumulated against the key
  Result := TBigIntegerUtilities.ModPowBaseBlinded(LP, LPeerY, FKey.X, FRandom);

  if Result.Equals(TBigInteger.One) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSharedKeyInvalid);
end;

function TDHBasicAgreement.GetFieldSize: Int32;
begin
  Result := (FKey.Parameters.P.BitLength + 7) div 8;
end;

procedure TDHBasicAgreement.Init(const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LWithRandom: IParametersWithRandom;
  LDHPriv: IDHPrivateKeyParameters;
begin
  if Supports(AParameters, IParametersWithRandom, LWithRandom) then
  begin
    FRandom := LWithRandom.Random;
    LParameters := LWithRandom.Parameters;
  end
  else
  begin
    FRandom := TCryptoServicesRegistrar.GetSecureRandom();
    LParameters := AParameters;
  end;

  if not Supports(LParameters, IDHPrivateKeyParameters, LDHPriv) then
    raise EArgumentCryptoLibException.CreateRes(@SNotDHPrivateKeyParameters);

  FKey := LDHPriv;
  FDhParams := FKey.Parameters;
end;

end.
