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

unit ClpIPlainDsaEncoding;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIDsaEncoding,
  ClpCryptoLibTypes;

type
  IPlainDsaEncoding = interface(IDsaEncoding)
    ['{72DC1571-BE91-461B-BD2F-A0CCAA15DD59}']

    function CheckValue(const AN, AX: TBigInteger): TBigInteger;
    function DecodeValue(const AN: TBigInteger; const ABuf: TCryptoLibByteArray;
      AOff, ALength: Int32): TBigInteger;
    procedure EncodeValue(const AN, AX: TBigInteger;
      const ABuf: TCryptoLibByteArray; AOff, ALength: Int32);
  end;

implementation

end.
