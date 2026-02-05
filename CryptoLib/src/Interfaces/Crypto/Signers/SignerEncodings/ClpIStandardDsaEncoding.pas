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

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIDsaEncoding,
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

type
  IStandardDsaEncoding = interface(IDsaEncoding)
    ['{A8662374-922B-4D72-B956-FE0ED3505C68}']

    function CheckValue(const AN, AX: TBigInteger): TBigInteger;
    function DecodeValue(const AN: TBigInteger; const &AS: IAsn1Sequence;
      APos: Int32): TBigInteger;
    function EncodeValue(const AN, AX: TBigInteger): IDerInteger;
  end;

implementation

end.
