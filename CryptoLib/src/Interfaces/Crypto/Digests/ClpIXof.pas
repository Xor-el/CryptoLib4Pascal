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

unit ClpIXof;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIDigest,
  ClpCryptoLibTypes;

type
  IXof = interface(IDigest)
    ['{FF009632-E66B-454B-90CB-7344F5405602}']

    /// <summary>
    /// Output the results of the final calculation for this XOF to AOutLen
    /// number of bytes. The DoFinal call leaves the XOF reset.
    /// </summary>
    /// <param name="AOutput">output array to write the output bytes to.</param>
    /// <param name="AOutOff">offset to start writing the bytes at.</param>
    /// <param name="AOutLen">the number of output bytes requested.</param>
    /// <returns>the number of bytes written</returns>
    function OutputFinal(const AOutput: TCryptoLibByteArray;
      AOutOff, AOutLen: Int32): Int32;

    /// <summary>
    /// Start outputting the results of the final calculation for this XOF.
    /// Unlike OutputFinal, this method will continue producing output until
    /// the XOF is explicitly reset, or signals otherwise.
    /// </summary>
    /// <param name="AOutput">output array to write the output bytes to.</param>
    /// <param name="AOutOff">offset to start writing the bytes at.</param>
    /// <param name="AOutLen">the number of output bytes requested.</param>
    /// <returns>the number of bytes written</returns>
    function Output(const AOutput: TCryptoLibByteArray;
      AOutOff, AOutLen: Int32): Int32;

  end;

implementation

end.
