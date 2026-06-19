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

unit ClpISlhDsaCore;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  ISlhDsaAdrs = interface(IInterface)
    ['{C3D4E5F6-A7B8-4901-C234-56789ABC0103}']
    procedure SetLayerAddress(ALayer: UInt32);
    procedure SetTreeAddress(ATree: UInt64);
    procedure SetTreeHeight(AHeight: UInt32);
    procedure SetTreeIndex(AIndex: UInt32);
    function GetTreeIndex: UInt32;
    procedure SetType(AAdrsType: UInt32);
    procedure SetTypeAndClear(AAdrsType: UInt32);
    procedure SetKeyPairAddress(AKeyPairAddr: UInt32);
    function GetKeyPairAddress: UInt32;
    procedure SetHashAddress(AHashAddr: UInt32);
    procedure SetChainAddress(AChainAddr: UInt32);
    function GetValue: TCryptoLibByteArray;
  end;

  ISlhDsaIndexedDigest = interface(IInterface)
    ['{A1B2C3D4-5E6F-4789-A012-3456789A0101}']
    function GetIdxTree: UInt64;
    function GetIdxLeaf: UInt32;
    function GetDigest: TCryptoLibByteArray;
    property IdxTree: UInt64 read GetIdxTree;
    property IdxLeaf: UInt32 read GetIdxLeaf;
    property Digest: TCryptoLibByteArray read GetDigest;
  end;

implementation

end.
