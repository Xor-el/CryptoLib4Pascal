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

unit ClpICmsParsers;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIAsn1Parsers,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for CMS ContentInfo parser.
  /// </summary>
  ICmsContentInfoParser = interface(IInterface)
    ['{C93E5F6B-0718-4A2E-8C3D-5F1B9E4A7D2C}']

    function GetContentType: IDerObjectIdentifier;
    function GetContent(ATag: Int32): IAsn1Convertible;

    property ContentType: IDerObjectIdentifier read GetContentType;
  end;

  /// <summary>
  /// Interface for CMS SignedData parser.
  /// </summary>
  ICmsSignedDataParser = interface(IInterface)
    ['{D04F6A7C-1829-4B3F-9D4E-6A2C8B1E5F3D}']

    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1SetParser;
    function GetEncapContentInfo: ICmsContentInfoParser;
    function GetCertificates: IAsn1SetParser;
    function GetCrls: IAsn1SetParser;
    function GetSignerInfos: IAsn1SetParser;

    property Version: IDerInteger read GetVersion;
  end;

implementation

end.
