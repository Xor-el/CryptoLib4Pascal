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

unit ClpISchnorrEncoding;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// An interface for different encoding formats for Schnorr signatures.
  /// </summary>
  ISchnorrEncoding = interface(IInterface)
    ['{CC5ECEFB-D806-402F-9F86-8D17EC61BE00}']

    /// <summary>Decode the (r, s) pair of a Schnorr signature.</summary>
    /// <param name="n">The order of the group that r, s belong to.</param>
    /// <param name="encoding">An encoding of the (r, s) pair of a Schnorr signature.</param>
    /// <returns>The (r, s) of a Schnorr signature, stored in an array of exactly two elements, r followed by s.</returns>
    function Decode(const n: TBigInteger; const encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;
    /// <summary>Encode the (r, s) pair of a Schnorr signature.</summary>
    /// <param name="n">The order of the group that r, s belong to.</param>
    /// <param name="r">The r value of a Schnorr signature.</param>
    /// <param name="s">The s value of a Schnorr signature.</param>
    /// <returns>An encoding of the Schnorr signature given by the provided (r, s) pair.</returns>
    function Encode(const n, r, s: TBigInteger): TCryptoLibByteArray;

  end;

implementation

end.
