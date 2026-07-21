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
  ClpICipherParameters,
  ClpIBasicAgreement,
  ClpIDHBasicAgreement,
  ClpIDHParameters,
  ClpIParametersWithRandom,
  ClpCryptoLibExceptions;

resourcestring
  SDHPublicKeyWrongParameter =
    'Diffie-Hellman public key has wrong parameters';
  SNotDHPrivateKeyParameters = 'DHEngine expects DHPrivateKeyParameters';
  SAlgorithmNotInitialized = 'agreement algorithm not initialized';
  SSharedKeyInvalid = 'shared key cannot be 1';
  SDHPublicKeyWeak = 'Diffie-Hellman public key is weak';

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

  LPeerY := LPub.Y;

  if ((not LPeerY.IsInitialized) or (LPeerY.CompareTo(TBigInteger.One) <= 0) or
    (LPeerY.CompareTo(LP.Subtract(TBigInteger.One)) >= 0)) then
    raise EArgumentCryptoLibException.CreateRes(@SDHPublicKeyWeak);

  Result := LPeerY.ModPow(FKey.X, LP);

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
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithRandom, LWithRandom) then
    LParameters := LWithRandom.Parameters;

  if not Supports(LParameters, IDHPrivateKeyParameters, LDHPriv) then
    raise EArgumentCryptoLibException.CreateRes(@SNotDHPrivateKeyParameters);

  FKey := LDHPriv;
  FDhParams := FKey.Parameters;
end;

end.
