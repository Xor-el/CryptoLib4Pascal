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

unit ClpDefaultMacAlgorithmFinder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpOiwObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpCollectionUtilities,
  ClpCryptoLibComparers,
  ClpIMacAlgorithmFinder,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Default implementation of IMacAlgorithmFinder that maps MAC names to algorithm identifiers.
  /// </summary>
  TDefaultMacAlgorithmFinder = class sealed(TInterfacedObject, IMacAlgorithmFinder)
  strict private
    class var
      FInstance: IMacAlgorithmFinder;
      FMacNameToAlgIDs: TDictionary<String, IAlgorithmIdentifier>;
    class constructor Create;
    class destructor Destroy;
  public
    class property Instance: IMacAlgorithmFinder read FInstance;
    function Find(const AMacName: String): IAlgorithmIdentifier;
  end;

implementation

{ TDefaultMacAlgorithmFinder }

class constructor TDefaultMacAlgorithmFinder.Create;
begin
  FMacNameToAlgIDs := TDictionary<String, IAlgorithmIdentifier>.Create(
  TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  FMacNameToAlgIDs.Add('HMACSHA1',
  TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1) as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA224',
  TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha224, TDerNull.Instance)
      as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA256',
  TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha256, TDerNull.Instance)
      as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA384',
  TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha384, TDerNull.Instance)
      as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA512',
  TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha512, TDerNull.Instance)
      as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA512-224',
  TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha512_224, TDerNull.Instance)
      as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA512-256',
  TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha512_256, TDerNull.Instance)
      as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA3-224',
  TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdHMacWithSha3_224) as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA3-256',
  TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdHMacWithSha3_256) as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA3-384',
  TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdHMacWithSha3_384) as IAlgorithmIdentifier);
  FMacNameToAlgIDs.Add('HMACSHA3-512',
  TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdHMacWithSha3_512) as IAlgorithmIdentifier);

  FInstance := TDefaultMacAlgorithmFinder.Create;
end;

class destructor TDefaultMacAlgorithmFinder.Destroy;
begin
  FInstance := nil;
  FMacNameToAlgIDs.Free;
end;

function TDefaultMacAlgorithmFinder.Find(const AMacName: String): IAlgorithmIdentifier;
begin
  Result := TCollectionUtilities.GetValueOrNull<String, IAlgorithmIdentifier>(
    FMacNameToAlgIDs, AMacName);
end;

end.
