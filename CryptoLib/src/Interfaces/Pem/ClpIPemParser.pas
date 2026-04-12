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

unit ClpIPemParser;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for PEM parser.
  /// </summary>
  IPemParser = interface(IInterface)
    ['{8C91EC3F-A5D3-4714-8A3E-A68C381FF754}']

    /// <summary>
    /// Read a PEM object from the stream and return it as an ASN.1 sequence.
    /// </summary>
    /// <param name="AInStream">The input stream to read from</param>
    /// <returns>An ASN.1 sequence, or nil if no PEM object found</returns>
    function ReadPemObject(const AInStream: TStream): IAsn1Sequence;
  end;

implementation

end.
