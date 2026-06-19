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

unit ClpISlhDsaEngine;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpISlhDsaCore,
  ClpCryptoLibTypes;

type
  ISlhDsaEngine = interface(IInterface)
    ['{B2C3D4E5-F6A7-4890-B123-456789AB0102}']
    function GetN: Int32;
    function GetWotsW: Int32;
    function GetWotsLogW: Int32;
    function GetWotsLen: Int32;
    function GetWotsLen1: Int32;
    function GetWotsLen2: Int32;
    function GetD: Int32;
    function GetA: Int32;
    function GetK: Int32;
    function GetFH: Int32;
    function GetHPrime: Int32;
    function GetSignatureLength: Int32;
    procedure Init(const APkSeed: TCryptoLibByteArray);
    procedure F(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32);
    procedure H1(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32;
      const AM2: TCryptoLibByteArray; AM2Off: Int32);
    procedure H2(const AAdrs: ISlhDsaAdrs; const AM1: TCryptoLibByteArray; AM1Off: Int32;
      var AM2: TCryptoLibByteArray; AM2Off: Int32);
    function HMsg(const APrf: TCryptoLibByteArray; APrfOff: Int32; const APkSeed, APkRoot: TCryptoLibByteArray;
      const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): ISlhDsaIndexedDigest;
    procedure T_l(const AAdrs: ISlhDsaAdrs; const AM: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
      AOutputOff: Int32);
    procedure Prf(const AAdrs: ISlhDsaAdrs; const ASkSeed: TCryptoLibByteArray; var APrf: TCryptoLibByteArray;
      APrfOff: Int32);
    procedure PrfMsg(const APrf, ARandomiser, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      var AR: TCryptoLibByteArray; AROff: Int32);
    property N: Int32 read GetN;
    property WotsW: Int32 read GetWotsW;
    property WotsLogW: Int32 read GetWotsLogW;
    property WotsLen: Int32 read GetWotsLen;
    property WotsLen1: Int32 read GetWotsLen1;
    property WotsLen2: Int32 read GetWotsLen2;
    property D: Int32 read GetD;
    property A: Int32 read GetA;
    property K: Int32 read GetK;
    property FH: Int32 read GetFH;
    property HPrime: Int32 read GetHPrime;
    property SignatureLength: Int32 read GetSignatureLength;
  end;

implementation

end.
