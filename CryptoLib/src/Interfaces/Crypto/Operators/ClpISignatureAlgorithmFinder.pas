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

unit ClpISignatureAlgorithmFinder;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Finder for signature algorithm identifiers from signature algorithm names.
  /// </summary>
  ISignatureAlgorithmFinder = interface
    ['{6FB0D062-E975-4502-8946-49F1986E66B1}']

    /// <summary>
    /// Find the signature algorithm identifier that matches with the passed in signature name.
    /// </summary>
    /// <param name="ASignatureName">the name of the signature algorithm of interest.</param>
    /// <returns>an algorithm identifier for the signature name.</returns>
    function Find(const ASignatureName: String): IAlgorithmIdentifier;
  end;

implementation

end.
