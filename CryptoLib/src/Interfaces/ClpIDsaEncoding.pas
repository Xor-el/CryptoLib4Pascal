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

unit ClpIDsaEncoding;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// An interface for different encoding formats for DSA signatures.
  /// </summary>
  IDsaEncoding = interface(IInterface)
    ['{1331AB87-6BD4-46AF-A45D-440295E11AD7}']

    /// <summary>Decode the (r, s) pair of a DSA signature.</summary>
    /// <param name="n">The order of the group that r, s belong to.</param>
    /// <param name="encoding">An encoding of the (r, s) pair of a DSA signature.</param>
    /// <returns>The (r, s) of a DSA signature, stored in an array of exactly two elements, r followed by s.</returns>
    function Decode(const n: TBigInteger; const encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;
    /// <summary>Encode the (r, s) pair of a DSA signature.</summary>
    /// <param name="n">The order of the group that r, s belong to.</param>
    /// <param name="r">The r value of a DSA signature.</param>
    /// <param name="s">The s value of a DSA signature.</param>
    /// <returns>An encoding of the DSA signature given by the provided (r, s) pair.</returns>
    function Encode(const n, r, s: TBigInteger): TCryptoLibByteArray;

  end;

implementation

end.
