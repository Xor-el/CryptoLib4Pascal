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

unit ClpIScalarSplitParameters;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IScalarSplitParameters = interface(IInterface)
    ['{C1D2E3F4-A5B6-7890-CDEF-1234567890AB}']
    function GetV1A: TBigInteger;
    function GetV1B: TBigInteger;
    function GetV2A: TBigInteger;
    function GetV2B: TBigInteger;
    function GetG1: TBigInteger;
    function GetG2: TBigInteger;
    function GetBits: Int32;
    property V1A: TBigInteger read GetV1A;
    property V1B: TBigInteger read GetV1B;
    property V2A: TBigInteger read GetV2A;
    property V2B: TBigInteger read GetV2B;
    property G1: TBigInteger read GetG1;
    property G2: TBigInteger read GetG2;
    property Bits: Int32 read GetBits;
  end;

implementation

end.
