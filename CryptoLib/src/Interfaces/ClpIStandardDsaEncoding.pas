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

unit ClpIStandardDsaEncoding;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIAsn1Sequence,
  ClpIDerInteger,
  ClpIDsaEncoding,
  ClpCryptoLibTypes;

type
  IStandardDsaEncoding = interface(IDsaEncoding)
    ['{A8662374-922B-4D72-B956-FE0ED3505C68}']

    function CheckValue(const n, x: TBigInteger): TBigInteger;
    function DecodeValue(const n: TBigInteger; const s: IAsn1Sequence;
      pos: Int32): TBigInteger;
    function EncodeValue(const n, x: TBigInteger): IDerInteger;

    function Decode(const n: TBigInteger; const encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;

    function Encode(const n, r, s: TBigInteger): TCryptoLibByteArray;

  end;

implementation

end.
