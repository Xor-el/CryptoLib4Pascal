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

unit ClpIParametersWithIV;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Parameter bundle tying an IV/nonce to inner cipher parameters (for example a wrapping key parameter).
  /// </summary>
  IParametersWithIV = interface(ICipherParameters)
    ['{9EC8D509-C7FA-4A25-AB5A-CD0B2EA57591}']

    /// <summary>Retrieve a freshly allocated copy of the IV material.</summary>
    function GetIV(): TCryptoLibByteArray;
    /// <summary>Underlying parameters excluding the IV (may be nil for key reuse stubs).</summary>
    function GetParameters: ICipherParameters;
    property Parameters: ICipherParameters read GetParameters;
    /// <summary>Erase buffered IV bytes when supported by implementations.</summary>
    procedure Clear();

  end;

implementation

end.
