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

unit ClpISignatureFactory;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for operators that serve as stream-based signature calculators.
  /// </summary>
  ISignatureFactory = interface
    ['{891A7077-58D2-4CBF-B509-2C651C004932}']

    /// <summary>
    /// The algorithm details object for this calculator.
    /// </summary>
    function GetAlgorithmDetails: IAlgorithmIdentifier;

    /// <summary>
    /// Create a stream calculator for this signature calculator.
    /// </summary>
    function CreateCalculator: IStreamCalculator<IBlockResult>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
  end;

implementation

end.
