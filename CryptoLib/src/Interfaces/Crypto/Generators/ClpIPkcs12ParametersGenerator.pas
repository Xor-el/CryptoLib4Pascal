{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIPkcs12ParametersGenerator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPbeParametersGenerator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Generator for PBE derived keys and IVs as defined by Pkcs 12 V1.0.
  /// </summary>
  IPkcs12ParametersGenerator = interface(IPbeParametersGenerator)

    ['{71A37282-A7EB-4141-A18B-34CC4C9D3844}']

  end;

implementation

end.
