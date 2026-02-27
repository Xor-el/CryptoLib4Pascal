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

unit ClpIDsaEncoding;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IDsaEncoding = interface(IInterface)
    ['{1331AB87-6BD4-46AF-A45D-440295E11AD7}']

    function Decode(const AN: TBigInteger; const AEncoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;
    function Encode(const AN, AR, &AS: TBigInteger): TCryptoLibByteArray;
    function GetMaxEncodingSize(const AN: TBigInteger): Int32;
  end;

implementation

end.
