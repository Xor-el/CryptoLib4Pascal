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

unit ClpISP80090Drbg;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>Interface to SP 800-90A deterministic random bit generators.</summary>
  ISP80090Drbg = interface(IInterface)
    ['{A6D9C4B3-5E7F-6B8A-9C3D-4F0A2E5B6C78}']

    /// <summary>
    /// Return the block size of the DRBG (in bits produced by each internal round).
    /// </summary>
    function GetBlockSize: Int32;
    property BlockSize: Int32 read GetBlockSize;

    /// <summary>
    /// Populate a passed-in array with random data.
    /// </summary>
    /// <param name="AOutput">Output array for generated bits.</param>
    /// <param name="AOutputOff">Offset into <paramref name="AOutput"/> to start writing.</param>
    /// <param name="AOutputLen">Number of bytes to generate.</param>
    /// <param name="AAdditionalInput">Optional additional input for this step, or <c>nil</c>.</param>
    /// <param name="APredictionResistant">
    /// If <c>true</c>, force a reseed before generating; otherwise <c>false</c>.
    /// </param>
    /// <returns>Number of bits generated, or <c>-1</c> if a reseed is required.</returns>
    function Generate(const AOutput: TCryptoLibByteArray; AOutputOff, AOutputLen: Int32;
      const AAdditionalInput: TCryptoLibByteArray; APredictionResistant: Boolean): Int32;

    /// <summary>Reseed the DRBG.</summary>
    /// <param name="AAdditionalInput">
    /// Optional additional input to mix into the reseed, or <c>nil</c>.
    /// </param>
    procedure Reseed(const AAdditionalInput: TCryptoLibByteArray);
  end;

implementation

end.
