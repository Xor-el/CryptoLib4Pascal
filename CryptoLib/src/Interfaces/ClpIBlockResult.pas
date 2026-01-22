{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIBlockResult;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for operators that reduce their input to a single block.
  /// </summary>
  IBlockResult = interface
    ['{A1B2C3D4-E5F6-7890-ABCD-EF0123456789}']

    /// <summary>
    /// Return the final result of the operation.
    /// </summary>
    function Collect: TCryptoLibByteArray; overload;
    /// <summary>
    /// Store the final result of the operation by copying it into the destination array.
    /// </summary>
    function Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32; overload;
    /// <summary>
    /// Return an upper limit for the size of the result.
    /// </summary>
    function GetMaxResultLength: Int32;
  end;

implementation

end.
