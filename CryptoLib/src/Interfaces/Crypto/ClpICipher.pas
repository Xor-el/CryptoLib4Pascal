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

unit ClpICipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes;

type
  /// <summary>
  /// Base interface for a cipher that does not require data to be block aligned.
  /// In cases where the underlying algorithm is block based, these ciphers may
  /// add or remove padding as needed.
  /// </summary>
  ICipher = interface(IInterface)
    ['{62C86317-0D55-48B7-A704-40883099D9B4}']

    /// <summary>
    /// Return the size of the output buffer required for a Write() plus a
    /// close() with the write() being passed inputLen bytes.
    /// </summary>
    function GetMaxOutputSize(AInputLen: Int32): Int32;

    /// <summary>
    /// Return the size of the output buffer required for a write() with the write() being
    /// passed inputLen bytes and just updating the cipher output.
    /// </summary>
    function GetUpdateOutputSize(AInputLen: Int32): Int32;

    /// <summary>
    /// Gets the stream for reading/writing data processed/to be processed.
    /// </summary>
    function GetStream: TStream;

    property Stream: TStream read GetStream;
  end;

implementation

end.
