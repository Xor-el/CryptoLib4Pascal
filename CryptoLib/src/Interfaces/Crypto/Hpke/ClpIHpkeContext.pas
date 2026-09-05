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

unit ClpIHpkeContext;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stateful HPKE encryption / decryption context (RFC 9180 sec. 5.1),
  /// produced by one of the HPKE setup factories.
  /// </summary>
  IHpkeContext = interface(IInterface)
    ['{9D3A6E11-8C42-4B57-B1F0-2A7C5E8D9012}']

    function Seal(const AAad, APt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Seal(const AAad, APt: TCryptoLibByteArray; APtOff, APtLen: Int32)
      : TCryptoLibByteArray; overload;

    function Open(const AAad, ACt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Open(const AAad, ACt: TCryptoLibByteArray; ACtOff, ACtLen: Int32)
      : TCryptoLibByteArray; overload;

    function Export(const AExporterContext: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;

    function Extract(const ASalt, AIkm: TCryptoLibByteArray)
      : TCryptoLibByteArray;

    function Expand(const APrk, AInfo: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;
  end;

  /// <summary>
  /// Sender-side context that also carries the KEM encapsulation to transmit
  /// to the recipient.
  /// </summary>
  IHpkeContextWithEncapsulation = interface(IHpkeContext)
    ['{5B8F2C70-1E93-4A48-9D62-3F7A0B1C4D33}']

    function GetEncapsulation(): TCryptoLibByteArray;
  end;

implementation

end.
