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

unit ClpIMacAlgorithmFinder;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Finder for MAC algorithm identifiers from MAC algorithm names.
  /// </summary>
  IMacAlgorithmFinder = interface
    ['{47533909-145A-4A4D-92E1-7CA040A4F151}']

    /// <summary>
    /// Find the MAC algorithm identifier that matches with the passed in MAC name.
    /// </summary>
    /// <param name="AMacName">the name of the MAC algorithm of interest.</param>
    /// <returns>an algorithm identifier for the MAC name, or nil if not found.</returns>
    function Find(const AMacName: String): IAlgorithmIdentifier;
  end;

implementation

end.
