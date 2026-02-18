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

unit ClpIOpenSslPbeParametersGenerator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPbeParametersGenerator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// OpenSSL PEM PBE parameters generator (MD5, iteration 1).
  /// </summary>
  IOpenSslPbeParametersGenerator = interface(IPbeParametersGenerator)
    ['{E2B126F8-5EF0-47C0-ABDE-1F5DB3AF3B85}']

    /// <summary>
    /// Initialise - iteration count is fixed at 1 for this algorithm.
    /// </summary>
    procedure Init(const APassword, ASalt: TCryptoLibByteArray);
  end;

implementation

end.
