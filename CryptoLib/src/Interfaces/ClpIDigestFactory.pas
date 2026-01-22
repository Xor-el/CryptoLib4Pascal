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

unit ClpIDigestFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for operator factories that create stream-based digest calculators.
  /// </summary>
  IDigestFactory = interface
    ['{F1A2B3C4-D5E6-7890-ABCD-EF0123456789}']

    /// <summary>The algorithm details object for calculators made by this factory.</summary>
    function GetAlgorithmDetails: IAlgorithmIdentifier;

    /// <summary>Return the size of the digest associated with this factory.</summary>
    /// <returns>The length of the digest produced by this calculators from this factory in bytes.</returns>
    function GetDigestLength: Int32;

    /// <summary>
    /// Create a stream calculator for the digest associated with this factory. The stream
    /// calculator is used for the actual operation of entering the data to be digested
    /// and producing the digest block.
    /// </summary>
    /// <returns>A calculator producing an IBlockResult with the final digest in it.</returns>
    function CreateCalculator: IStreamCalculator<IBlockResult>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
    property DigestLength: Int32 read GetDigestLength;
  end;

implementation

end.
