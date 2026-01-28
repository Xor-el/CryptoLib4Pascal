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

unit ClpIAsn1Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIAsn1Core;

type
  /// <summary>
  /// Interface for ASN.1 generators.
  /// </summary>
  IAsn1Generator = interface(IInterface)
    ['{B1C2D3E4-F5A6-B7C8-D9E0-F1A2B3C4D5E6}']
    procedure AddObject(const AObj: IAsn1Encodable);
    function GetRawOutputStream(): TStream;
    procedure Close();
  end;

  /// <summary>
  /// Interface for BER generators.
  /// </summary>
  IBerGenerator = interface(IAsn1Generator)
    ['{C2D3E4F5-A6B7-C8D9-E0F1-A2B3C4D5E6F7}']
    procedure WriteHdr(ATag: Int32);
    procedure WriteBerHeader(ATag: Int32);
    procedure WriteBerBody(AContentStream: TStream);
    procedure WriteBerEnd();
  end;

  /// <summary>
  /// Interface for BER sequence generators.
  /// </summary>
  IBerSequenceGenerator = interface(IBerGenerator)
    ['{5FF489CE-2A51-4FE5-A961-99AE423537CE}']
  end;

  /// <summary>
  /// Interface for BER octet string generators.
  /// </summary>
  IBerOctetStringGenerator = interface(IBerGenerator)
    ['{D3E4F5A6-B7C8-D9E0-F1A2-B3C4D5E6F7A8}']
    function GetOctetOutputStream(): TStream; overload;
    function GetOctetOutputStream(ABufSize: Int32): TStream; overload;
    function GetOctetOutputStream(const ABuf: TCryptoLibByteArray): TStream; overload;
  end;

  /// <summary>
  /// Interface for DER generators.
  /// </summary>
  IDerGenerator = interface(IAsn1Generator)
    ['{E4F5A6B7-C8D9-E0F1-A2B3-C4D5E6F7A8B9}']
    procedure WriteDerEncoded(ATag: Int32; const ABytes: TCryptoLibByteArray);
  end;

  /// <summary>
  /// Interface for DER sequence generators.
  /// </summary>
  IDerSequenceGenerator = interface(IDerGenerator)
    ['{F5A6B7C8-D9E0-F1A2-B3C4-D5E6F7A8B9C0}']
    procedure AddObject(const AObj: IAsn1Object); overload;
  end;

implementation

end.
