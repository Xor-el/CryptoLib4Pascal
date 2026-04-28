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

unit ClpIDigestAlgorithmFinder;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for a finder of digest algorithm identifiers used with signatures.
  /// </summary>
  IDigestAlgorithmFinder = interface
    ['{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}']

    /// <summary>
    /// Find the digest algorithm identifier that matches with the passed in signature algorithm identifier.
    /// </summary>
    /// <param name="ASignatureAlgorithm">the signature algorithm of interest.</param>
    /// <returns>an algorithm identifier for the corresponding digest.</returns>
    function Find(const ASignatureAlgorithm: IAlgorithmIdentifier): IAlgorithmIdentifier; overload;

    /// <summary>
    /// Find the digest algorithm identifier that matches with the passed in digest OID.
    /// </summary>
    /// <param name="ADigestOid">the OID of the digest algorithm of interest.</param>
    /// <returns>an algorithm identifier for the digest OID.</returns>
    function Find(const ADigestOid: IDerObjectIdentifier): IAlgorithmIdentifier; overload;

    /// <summary>
    /// Find the digest algorithm identifier that matches with the passed in digest name.
    /// </summary>
    /// <param name="ADigestName">the name of the digest algorithm of interest.</param>
    /// <returns>an algorithm identifier for the digest name, or nil if not found.</returns>
    function Find(const ADigestName: String): IAlgorithmIdentifier; overload;
  end;

implementation

end.
