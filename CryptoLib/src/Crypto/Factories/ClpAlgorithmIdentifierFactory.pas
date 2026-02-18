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

unit ClpAlgorithmIdentifierFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpNistObjectIdentifiers,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating AlgorithmIdentifier instances for encryption algorithms.
  /// </summary>
  TAlgorithmIdentifierFactory = class sealed(TObject)
  public
    /// <summary>
    /// Create an AlgorithmIdentifier for the passed in encryption algorithm.
    /// </summary>
    class function GenerateEncryptionAlgID(const AEncryptionOID: IDerObjectIdentifier;
      AKeySize: Int32; const ARandom: ISecureRandom): IAlgorithmIdentifier; static;
  end;

implementation

{ TAlgorithmIdentifierFactory }

class function TAlgorithmIdentifierFactory.GenerateEncryptionAlgID(
  const AEncryptionOID: IDerObjectIdentifier; AKeySize: Int32;
  const ARandom: ISecureRandom): IAlgorithmIdentifier;
var
  LIv: TCryptoLibByteArray;
begin
  if AEncryptionOID.Equals(TNistObjectIdentifiers.IdAes128Cbc)
    or AEncryptionOID.Equals(TNistObjectIdentifiers.IdAes192Cbc)
    or AEncryptionOID.Equals(TNistObjectIdentifiers.IdAes256Cbc) then
  begin
    System.SetLength(LIv, 16);
    ARandom.NextBytes(LIv);
    Result := TAlgorithmIdentifier.Create(AEncryptionOID,
      TDerOctetString.Create(LIv) as IDerOctetString);
  end
  else
  begin
    raise EInvalidOperationCryptoLibException.Create('unable to match algorithm: ' + AEncryptionOID.Id);
  end;
end;

end.
