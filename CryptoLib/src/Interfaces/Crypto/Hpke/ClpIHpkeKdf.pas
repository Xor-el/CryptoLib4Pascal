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

unit ClpIHpkeKdf;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// RFC 9180 sec. 4 labeled KDF (LabeledExtract / LabeledExpand) over HKDF.
  /// </summary>
  IHpkeKdf = interface(IInterface)
    ['{4C7B1E90-3B4A-4E52-9E1C-7F2D6A9B0C11}']

    function GetHashSize(): Int32;

    function LabeledExtract(const ASalt, ASuiteId: TCryptoLibByteArray;
      const ALabel: String; const AIkm: TCryptoLibByteArray)
      : TCryptoLibByteArray;

    function LabeledExpand(const APrk, ASuiteId: TCryptoLibByteArray;
      const ALabel: String; const AInfo: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;

    function Extract(const ASalt, AIkm: TCryptoLibByteArray)
      : TCryptoLibByteArray;

    function Expand(const APrk, AInfo: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;

    property HashSize: Int32 read GetHashSize;
  end;

implementation

end.
