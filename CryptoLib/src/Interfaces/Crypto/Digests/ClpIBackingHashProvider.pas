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

unit ClpIBackingHashProvider;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  HlpIHash;

type
  /// <summary>
  /// Internal capability interface exposing the HashLib4Pascal <c>IHash</c> that
  /// backs a digest. This is an implementation detail of the HashLib-backed
  /// digests (TDigest and its descendants) and is deliberately NOT part of the
  /// public <c>IDigest</c> contract; only the in-tree HMAC / PBKDF2 bridges query
  /// it (via <c>Supports</c>) because HashLib's own HMAC / PBKDF2 constructors
  /// require an <c>IHash</c>. Digests without a backing hash (e.g. a prehash
  /// digest) return nil, and callers must treat that as "not backing-hash
  /// capable".
  /// </summary>
  IBackingHashProvider = interface(IInterface)
    ['{2A9F7C64-4B1E-4D0A-9E3C-7F5B8D2A1C60}']

    function GetBackingHash: IHash;

    property BackingHash: IHash read GetBackingHash;
  end;

implementation

end.
