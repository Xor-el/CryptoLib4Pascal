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

unit ClpAbstractPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPacketCipher,
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Family-neutral root for the packet ciphers (see <see cref="IPacketCipher"/>).
  /// Holds only the parameter-object entry point as the single customization
  /// point; each family (AEAD, plain block modes) supplies its own unpack and
  /// seal/open. Adds no cryptography of its own.
  /// </summary>
  TAbstractPacketCipher = class abstract(TInterfacedObject, IPacketCipher)
  public
    function ProcessPacket(AForEncryption: Boolean;
      const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; virtual; abstract;
  end;

implementation

end.
