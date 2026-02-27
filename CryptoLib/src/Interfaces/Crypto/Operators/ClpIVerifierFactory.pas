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

unit ClpIVerifierFactory;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCalculator,
  ClpIVerifier,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for operators that serve as stream-based signature verifiers.
  /// </summary>
  IVerifierFactory = interface
    ['{2212002D-33CE-488F-8510-9B22B216FD74}']

    /// <summary>
    /// The algorithm details object for this verifier.
    /// </summary>
    function GetAlgorithmDetails: IAlgorithmIdentifier;

    /// <summary>
    /// Create a stream calculator for this verifier.
    /// </summary>
    function CreateCalculator: IStreamCalculator<IVerifier>;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
  end;

implementation

end.
