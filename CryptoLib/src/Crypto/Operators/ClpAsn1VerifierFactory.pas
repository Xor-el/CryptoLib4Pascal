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

unit ClpAsn1VerifierFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIVerifierFactory,
  ClpIX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIVerifier,
  ClpIStreamCalculator,
  ClpISigner,
  ClpX509SignatureUtilities,
  ClpSignerUtilities,
  ClpDefaultVerifierCalculator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Verifier class for signature verification in ASN.1 based profiles.
  /// </summary>
  TAsn1VerifierFactory = class sealed(TInterfacedObject, IVerifierFactory)

  strict private
  var
    FAlgID: IAlgorithmIdentifier;
    FAlgorithm: String;
    FPublicKey: IAsymmetricKeyParameter;

  strict protected
    function GetAlgorithmDetails: IAlgorithmIdentifier;

  public
    constructor Create(const AAlgorithm: String;
      const APublicKey: IAsymmetricKeyParameter); overload;
    constructor Create(const AAlgorithm: IAlgorithmIdentifier;
      const APublicKey: IAsymmetricKeyParameter); overload;

    function CreateCalculator: IStreamCalculator<IVerifier>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
  end;

implementation

{ TAsn1VerifierFactory }

constructor TAsn1VerifierFactory.Create(const AAlgorithm: String;
  const APublicKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.Create('algorithm');
  if APublicKey = nil then
    raise EArgumentNilCryptoLibException.Create('publicKey');
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Key for verifying must be public');

  FAlgID := TX509SignatureUtilities.GetSigAlgID(AAlgorithm);
  FAlgorithm := AAlgorithm;
  FPublicKey := APublicKey;
end;

constructor TAsn1VerifierFactory.Create(const AAlgorithm: IAlgorithmIdentifier;
  const APublicKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('algorithm');
  if APublicKey = nil then
    raise EArgumentNilCryptoLibException.Create('publicKey');
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Key for verifying must be public');

  FAlgID := AAlgorithm;
  FAlgorithm := TX509SignatureUtilities.GetSignatureName(AAlgorithm);
  FPublicKey := APublicKey;
end;

function TAsn1VerifierFactory.GetAlgorithmDetails: IAlgorithmIdentifier;
begin
  Result := FAlgID;
end;

function TAsn1VerifierFactory.CreateCalculator: IStreamCalculator<IVerifier>;
var
  LSigner: ISigner;
begin
  LSigner := TSignerUtilities.InitSigner(FAlgorithm, False, FPublicKey, nil);
  Result := TDefaultVerifierCalculator.Create(LSigner);
end;

end.
