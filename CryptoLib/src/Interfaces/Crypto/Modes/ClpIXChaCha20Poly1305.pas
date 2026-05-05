{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIXChaCha20Poly1305;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIChaCha20Poly1305;

type
  IXChaCha20Poly1305 = interface(IChaCha20Poly1305)
    ['{B2C4E6D8-0A1C-4E5F-9A8B-7C6D5E4F3A2B}']

  end;

implementation

end.
