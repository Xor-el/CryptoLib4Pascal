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

unit ClpIEntropySourceProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIEntropySource;

type
  /// <summary>Provider of entropy sources for DRBG seeding and reseeding.</summary>
  IEntropySourceProvider = interface(IInterface)
    ['{F5C8B3A2-4D6E-5A7F-8B2C-3E9F1D4A5B67}']

    /// <summary>
    /// Return an <see cref="IEntropySource"/> that supplies the requested number of
    /// bits per <see cref="IEntropySource.GetEntropy"/> call.
    /// </summary>
    /// <param name="ABitsRequired">Number of bits of entropy required per fetch.</param>
    /// <returns>A new entropy source configured for the requested bit length.</returns>
    function Get(ABitsRequired: Int32): IEntropySource;
  end;

implementation

end.
