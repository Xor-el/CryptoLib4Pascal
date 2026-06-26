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

unit ClpIDrbgProvider;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIEntropySource,
  ClpISP80090Drbg;

type
  /// <summary>Factory for SP 800-90A DRBG instances.</summary>
  IDrbgProvider = interface(IInterface)
    ['{0E5BD1F7-4FE8-4304-901B-95E76A46E7E1}']

    /// <summary>
    /// Create a new <see cref="ISP80090Drbg"/> bound to the given entropy source.
    /// </summary>
    /// <param name="AEntropySource">Entropy source for seeding and reseeding.</param>
    /// <returns>A new DRBG instance.</returns>
    function Get(const AEntropySource: IEntropySource): ISP80090Drbg;
  end;

implementation

end.
