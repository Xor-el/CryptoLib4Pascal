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

unit ClpIEntropySource;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>Base interface describing an entropy source for a DRBG.</summary>
  IEntropySource = interface(IInterface)
    ['{E4B7A291-3C5D-4F6E-9A1B-2D8E7F0C3A56}']

    function GetIsPredictionResistant: Boolean;
    property IsPredictionResistant: Boolean read GetIsPredictionResistant;

    function GetEntropy: TCryptoLibByteArray;

    function GetEntropySize: Int32;
    property EntropySize: Int32 read GetEntropySize;
  end;

implementation

end.
