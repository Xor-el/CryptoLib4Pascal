{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIDerObjectIdentifier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpBigInteger,
  ClpIProxiedInterface,
  ClpCryptoLibTypes;

type
  IDerObjectIdentifier = interface(IAsn1Object)

    ['{8626051F-828D-419B-94E8-65CC0752CCA1}']

    function GetID: String;
    property ID: String read GetID;

    procedure WriteField(outputStream: TStream; fieldValue: Int64); overload;
    procedure WriteField(outputStream: TStream;
      fieldValue: TBigInteger); overload;
    procedure DoOutput(bOut: TMemoryStream); overload;
    function GetBody(): TCryptoLibByteArray;
    procedure Encode(derOut: IDerOutputStream);

    function Asn1GetHashCode(): Int32;
    function Asn1Equals(asn1Object: IAsn1Object): Boolean;

    function Branch(const branchID: String): IDerObjectIdentifier;

    function &On(stem: IDerObjectIdentifier): Boolean;

    function ToString(): String;

  end;

implementation

end.
