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

unit ClpICipherBuilder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpICipher,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for cipher builders.
  /// </summary>
  ICipherBuilder = interface(IInterface)
    ['{B3AE4C39-D253-4F4E-BCEE-E8D361334034}']

    /// <summary>
    /// Return the algorithm and parameter details associated with any cipher built.
    /// </summary>
    function GetAlgorithmDetails: IAlgorithmIdentifier;

    /// <summary>
    /// Return the maximum output size that a given input will produce.
    /// </summary>
    function GetMaxOutputSize(AInputLen: Int32): Int32;

    /// <summary>
    /// Build a cipher that operates on the passed in stream.
    /// </summary>
    function BuildCipher(const AStream: TStream): ICipher;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
  end;

implementation

end.
