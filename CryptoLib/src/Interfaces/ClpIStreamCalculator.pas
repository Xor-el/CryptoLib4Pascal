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

unit ClpIStreamCalculator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes;

type
  /// <summary>
  /// Base interface for cryptographic operations such as Hashes, MACs, and Signatures
  /// which reduce a stream of data to a single value.
  /// </summary>
  IStreamCalculator<TResult> = interface
    ['{C3D4E5F6-A7B8-9012-CDEF-0123456789AB}']

    /// <summary>
    /// Return a "sink" stream which only exists to update the implementing object.
    /// </summary>
    function GetStream: TStream;
    /// <summary>
    /// Return the result of processing the stream. This value is only available once the stream
    /// has been closed.
    /// </summary>
    function GetResult: TResult;

    property Stream: TStream read GetStream;
  end;

implementation

end.
