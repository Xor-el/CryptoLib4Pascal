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

unit ClpIMacFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for operator factories that create stream-based MAC calculators.
  /// </summary>
  IMacFactory = interface
    ['{A2B3C4D5-E6F7-8901-BCDE-F0123456789A}']

    /// <summary>The algorithm details object for this calculator.</summary>
    function GetAlgorithmDetails: IAlgorithmIdentifier;

    /// <summary>
    /// Create a stream calculator for this MAC calculator. The stream
    /// calculator is used for the actual operation of entering the data to be MACed
    /// and producing the MAC block.
    /// </summary>
    /// <returns>A calculator producing an IBlockResult with a MAC in it.</returns>
    function CreateCalculator: IStreamCalculator<IBlockResult>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
  end;

implementation

end.
