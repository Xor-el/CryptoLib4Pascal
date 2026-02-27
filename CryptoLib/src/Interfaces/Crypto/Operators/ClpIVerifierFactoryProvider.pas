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

unit ClpIVerifierFactoryProvider;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIVerifierFactory,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Base interface for a provider to support the dynamic creation of signature verifiers.
  /// </summary>
  IVerifierFactoryProvider = interface
    ['{484B3126-A8AA-4512-91F2-1EFCAC0DAD4E}']

    /// <summary>
    /// Return a signature verifier for signature algorithm described in the passed in algorithm details object.
    /// </summary>
    function CreateVerifierFactory(AAlgorithmDetails: IAlgorithmIdentifier): IVerifierFactory;
  end;

implementation

end.
