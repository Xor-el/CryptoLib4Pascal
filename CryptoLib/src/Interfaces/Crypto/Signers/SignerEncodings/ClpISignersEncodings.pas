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

unit ClpISignersEncodings;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// An interface for different encoding formats for DSA signatures.
  /// </summary>
  IDsaEncoding = interface(IInterface)
    ['{1331AB87-6BD4-46AF-A45D-440295E11AD7}']

    /// <summary>Decode the (r, s) pair of a DSA signature.</summary>
    /// <param name="n">The order of the group that r, s belong to.</param>
    /// <param name="encoding">An encoding of the (r, s) pair of a DSA signature.</param>
    /// <returns>The (r, s) of a DSA signature, stored in an array of exactly two elements, r followed by s.</returns>
    function Decode(const AN: TBigInteger; const AEncoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;
    /// <summary>Encode the (r, s) pair of a DSA signature.</summary>
    /// <param name="n">The order of the group that r, s belong to.</param>
    /// <param name="r">The r value of a DSA signature.</param>
    /// <param name="s">The s value of a DSA signature.</param>
    /// <returns>An encoding of the DSA signature given by the provided (r, s) pair.</returns>
    function Encode(const AN, AR, &AS: TBigInteger): TCryptoLibByteArray;

    /// <summary>Get the maximum encoding size for a given order.</summary>
    /// <param name="n">The order of the group.</param>
    /// <returns>The maximum size in bytes for an encoding.</returns>
    function GetMaxEncodingSize(const AN: TBigInteger): Int32;

  end;

type
  IStandardDsaEncoding = interface(IDsaEncoding)
    ['{A8662374-922B-4D72-B956-FE0ED3505C68}']

    function CheckValue(const AN, AX: TBigInteger): TBigInteger;
    function DecodeValue(const AN: TBigInteger; const &AS: IAsn1Sequence;
      APos: Int32): TBigInteger;
    function EncodeValue(const AN, AX: TBigInteger): IDerInteger;

  end;

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
