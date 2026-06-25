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
  /// <summary>SP 800-90A deterministic random bit generator.</summary>
  ISP80090Drbg = interface(IInterface)
    ['{A6D9C4B3-5E7F-6B8A-9C3D-4F0A2E5B6C78}']

    function GetBlockSize: Int32;
    property BlockSize: Int32 read GetBlockSize;

    function Generate(const AOutput: TCryptoLibByteArray; AOutputOff, AOutputLen: Int32;
      const AAdditionalInput: TCryptoLibByteArray; APredictionResistant: Boolean): Int32;

    procedure Reseed(const AAdditionalInput: TCryptoLibByteArray);
  end;

implementation

end.
