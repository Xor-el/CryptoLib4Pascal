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

unit ClpAsn1SignatureFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpISignatureFactory,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpISecureRandom,
  ClpIBlockResult,
  ClpIStreamCalculator,
  ClpISigner,
  ClpX509SignatureUtilities,
  ClpSignerUtilities,
  ClpDefaultSignatureCalculator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Calculator factory class for signature generation in ASN.1 based profiles.
  /// </summary>
  TAsn1SignatureFactory = class sealed(TInterfacedObject, ISignatureFactory)

  strict private
  var
    FAlgID: IAlgorithmIdentifier;
    FAlgorithm: String;
    FPrivateKey: IAsymmetricKeyParameter;
    FRandom: ISecureRandom;

  strict protected
    function GetAlgorithmDetails: IAlgorithmIdentifier;

  public
    constructor Create(const AAlgorithm: String;
      const APrivateKey: IAsymmetricKeyParameter); overload;
    constructor Create(const AAlgorithm: String;
      const APrivateKey: IAsymmetricKeyParameter;
      const ARandom: ISecureRandom); overload;
    constructor Create(const AAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsymmetricKeyParameter); overload;
    constructor Create(const AAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsymmetricKeyParameter;
      const ARandom: ISecureRandom); overload;

    function CreateCalculator: IStreamCalculator<IBlockResult>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;

    /// <summary>
    /// Allows enumeration of the signature names supported.
    /// </summary>
    class function SignatureAlgNames: TCryptoLibStringArray; static;
  end;

implementation

{ TAsn1SignatureFactory }

constructor TAsn1SignatureFactory.Create(const AAlgorithm: String;
  const APrivateKey: IAsymmetricKeyParameter);
begin
  Create(AAlgorithm, APrivateKey, nil);
end;

constructor TAsn1SignatureFactory.Create(const AAlgorithm: String;
  const APrivateKey: IAsymmetricKeyParameter; const ARandom: ISecureRandom);
begin
  inherited Create();
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.Create('algorithm');
  if APrivateKey = nil then
    raise EArgumentNilCryptoLibException.Create('privateKey');
  if not APrivateKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Key for signing must be private');

  FAlgID := TX509SignatureUtilities.GetSigAlgID(AAlgorithm);
  FAlgorithm := AAlgorithm;
  FPrivateKey := APrivateKey;
  FRandom := ARandom;
end;

constructor TAsn1SignatureFactory.Create(const AAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsymmetricKeyParameter);
begin
  Create(AAlgorithm, APrivateKey, nil);
end;

constructor TAsn1SignatureFactory.Create(const AAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsymmetricKeyParameter; const ARandom: ISecureRandom);
begin
  inherited Create();
  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('algorithm');
  if APrivateKey = nil then
    raise EArgumentNilCryptoLibException.Create('privateKey');
  if not APrivateKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Key for signing must be private');

  FAlgID := AAlgorithm;
  FAlgorithm := TX509SignatureUtilities.GetSignatureName(AAlgorithm);
  FPrivateKey := APrivateKey;
  FRandom := ARandom;
end;

function TAsn1SignatureFactory.GetAlgorithmDetails: IAlgorithmIdentifier;
begin
  Result := FAlgID;
end;

function TAsn1SignatureFactory.CreateCalculator: IStreamCalculator<IBlockResult>;
var
  LSigner: ISigner;
begin
  LSigner := TSignerUtilities.InitSigner(FAlgorithm, True, FPrivateKey, FRandom);
  Result := TDefaultSignatureCalculator.Create(LSigner);
end;

class function TAsn1SignatureFactory.SignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509SignatureUtilities.GetSigNames();
end;

end.
