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

unit ClpIECVarBaseVerifier;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECCommon;

type
  /// <summary>
  /// Variable-time double-scalar multiply for a public (non-secret) verify:
  /// AR := AU1*AP + AU2*AQ. Registered per curve and reached ONLY from the
  /// signature-verify path (<c>TECAlgorithms.SumOfTwoMultiplies</c>); never from
  /// <c>Curve.CreateDefaultMultiplier</c> or any secret-scalar route, so its
  /// data-dependent branching is confined to public inputs.
  /// </summary>
  IECVarBaseVerifier = interface(IInterface)
    ['{7F2A9C34-1E5B-4D82-9A6F-3C8B0D71E426}']

    function SumOfTwoMultiplies(const AP: IECPoint; const AU1: TBigInteger;
      const AQ: IECPoint; const AU2: TBigInteger): IECPoint;
  end;

implementation

end.
