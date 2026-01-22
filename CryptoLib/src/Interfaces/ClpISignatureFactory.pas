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

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCalculator,
  ClpIBlockResult;

type
  /// <summary>
  /// Base interface for operators that serve as stream-based signature calculators.
  /// </summary>
  ISignatureFactory = interface
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789ABC}']

    /// <summary>
    /// The algorithm details object for this calculator.
    /// </summary>
    function GetAlgorithmDetails: TObject;

    /// <summary>
    /// Create a stream calculator for this signature calculator.
    /// </summary>
    function CreateCalculator: IStreamCalculator<IBlockResult>;

    property AlgorithmDetails: TObject read GetAlgorithmDetails;
  end;

implementation

end.
