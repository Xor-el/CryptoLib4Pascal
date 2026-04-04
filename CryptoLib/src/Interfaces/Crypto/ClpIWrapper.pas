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

unit ClpIWrapper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  IWrapper = interface(IInterface)
    ['{0F84381A-51D3-4DB1-9758-ED018F0770AF}']

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(AForWrapping: Boolean; const AParameters: ICipherParameters);

    function Wrap(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;

    function Unwrap(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;

  end;

implementation

end.
