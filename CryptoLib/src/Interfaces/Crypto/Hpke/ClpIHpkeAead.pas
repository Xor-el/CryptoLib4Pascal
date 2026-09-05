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

unit ClpIHpkeAead;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// RFC 9180 sec. 5.2 AEAD wrapper. Holds the derived key and base nonce and
  /// applies the nonce-XOR-sequence construction on each Seal / Open.
  /// </summary>
  IHpkeAead = interface(IInterface)
    ['{2A5F9C34-6D18-4B27-9C4E-1E8B7A0D5F22}']

    function Seal(const AAad, APt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Seal(const AAad, APt: TCryptoLibByteArray; APtOff, APtLen: Int32)
      : TCryptoLibByteArray; overload;

    function Open(const AAad, ACt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Open(const AAad, ACt: TCryptoLibByteArray; ACtOff, ACtLen: Int32)
      : TCryptoLibByteArray; overload;
  end;

implementation

end.
