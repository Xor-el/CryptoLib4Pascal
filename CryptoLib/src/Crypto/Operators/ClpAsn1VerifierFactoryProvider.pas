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

unit ClpAsn1VerifierFactoryProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIVerifierFactoryProvider,
  ClpIVerifierFactory,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpAsn1VerifierFactory,
  ClpX509SignatureUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Provider class which supports dynamic creation of signature verifiers.
  /// </summary>
  TAsn1VerifierFactoryProvider = class sealed(TInterfacedObject, IVerifierFactoryProvider)

  strict private
  var
    FPublicKey: IAsymmetricKeyParameter;

  public
    constructor Create(const APublicKey: IAsymmetricKeyParameter);

    function CreateVerifierFactory(AAlgorithmDetails: TObject): IVerifierFactory;

    /// <summary>
    /// Allows enumeration of the signature names supported by the verifier provider.
    /// </summary>
    function SignatureAlgNames: TCryptoLibStringArray;
  end;

implementation

{ TAsn1VerifierFactoryProvider }

constructor TAsn1VerifierFactoryProvider.Create(const APublicKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  if APublicKey = nil then
    raise EArgumentNilCryptoLibException.Create('publicKey');
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Key for verifying must be public');

  FPublicKey := APublicKey;
end;

function TAsn1VerifierFactoryProvider.CreateVerifierFactory(AAlgorithmDetails: TObject): IVerifierFactory;
var
  LAlgID: IAlgorithmIdentifier;
begin
  if not Supports(AAlgorithmDetails, IAlgorithmIdentifier, LAlgID) then
    raise EInvalidCastCryptoLibException.Create('algorithmDetails must be IAlgorithmIdentifier');

  Result := TAsn1VerifierFactory.Create(LAlgID, FPublicKey);
end;

function TAsn1VerifierFactoryProvider.SignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509SignatureUtilities.GetSigNames();
end;

end.
