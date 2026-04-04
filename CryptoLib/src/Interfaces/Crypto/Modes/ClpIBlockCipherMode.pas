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

unit ClpIBlockCipherMode;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher;

type
  /// <summary>
  /// Base interface for block cipher modes of operation.
  /// </summary>
  IBlockCipherMode = interface(IBlockCipher)
    ['{9F477798-A0B0-48A1-AECC-46E7DA8B327E}']

    /// <summary>Return the underlying block cipher that this mode wraps.</summary>
    function GetUnderlyingCipher: IBlockCipher;

    /// <summary>Indicates whether this cipher mode can handle partial blocks.</summary>
    function GetIsPartialBlockOkay: Boolean;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;

    /// <summary>
    /// Reset the cipher mode to the same state as it was after the last init (if there was one).
    /// </summary>
    procedure Reset();
  end;

implementation

end.
