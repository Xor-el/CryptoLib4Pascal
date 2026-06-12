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

unit ClpIF2mFieldData;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpIBinPolyInv;

type
  /// <summary>
  /// Shared field arithmetic data for binary extension fields GF(2^m).
  /// </summary>
  /// <remarks>
  /// Bundles the reduction taps (<c>Ks</c>), multiply/invert primitives (<c>Mul</c>,
  /// <c>Inv</c>), and field degree (<c>M</c>) used by F2m curve field elements.
  /// </remarks>
  IF2mFieldData = interface(IInterface)
    ['{D4E5F6A7-B8C9-4012-DEF0-123456789ABC}']
    function GetM: Int32;
    function GetKs: TCryptoLibInt32Array;
    function GetMul: IBinPolyMul;
    function GetInv: IBinPolyInv;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;
    property M: Int32 read GetM;
    property Ks: TCryptoLibInt32Array read GetKs;
    property Mul: IBinPolyMul read GetMul;
    property Inv: IBinPolyInv read GetInv;
    property K1: Int32 read GetK1;
    property K2: Int32 read GetK2;
    property K3: Int32 read GetK3;
  end;

implementation

end.
