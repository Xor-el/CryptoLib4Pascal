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

unit ClpIPlainSchnorrEncoding;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpISchnorrEncoding,
  ClpCryptoLibTypes;

type
  IPlainSchnorrEncoding = interface(ISchnorrEncoding)
    ['{1C2D1D11-04C4-4438-B728-4BF3ED2F3E99}']

    function CheckValue(const n, x: TBigInteger): TBigInteger;
    function DecodeValue(const n: TBigInteger; const buf: TCryptoLibByteArray;
      off, len: Int32): TBigInteger;
    procedure EncodeValue(const n, x: TBigInteger;
      const buf: TCryptoLibByteArray; off, len: Int32);

    function Decode(const n: TBigInteger; const encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;

    function Encode(const n, r, s: TBigInteger): TCryptoLibByteArray;

  end;

implementation

end.
