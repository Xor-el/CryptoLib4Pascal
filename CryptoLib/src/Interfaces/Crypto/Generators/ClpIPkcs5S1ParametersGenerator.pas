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

unit ClpIPkcs5S1ParametersGenerator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPbeParametersGenerator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Generator for PBE derived keys and IVs as defined by Pkcs 5 V2.0 Scheme 1.
  /// </summary>
  IPkcs5S1ParametersGenerator = interface(IPbeParametersGenerator)

    ['{B811D103-99A1-4279-9635-3555FC06D40E}']

  end;

implementation

end.
