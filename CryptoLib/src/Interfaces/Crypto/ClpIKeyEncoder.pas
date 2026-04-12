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

unit ClpIKeyEncoder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricKeyParameter,
  ClpCryptoLibTypes;

type
  IKeyEncoder = interface(IInterface)
    ['{CB751E36-F07C-46B7-B799-F20D0E7E888A}']

    function GetEncoded(const AKeyParameter: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
  end;

implementation

end.
