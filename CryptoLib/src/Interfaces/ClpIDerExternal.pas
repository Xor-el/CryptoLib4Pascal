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

unit ClpIDerExternal;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIDerInteger,
  ClpIDerObjectIdentifier,
  ClpIProxiedInterface;

type
  IDerExternal = interface(IAsn1Object)

    ['{9AC333C2-0F64-4A5F-BE0A-EBCC2A4E2A00}']

    function GetDataValueDescriptor: IAsn1Object;
    function GetDirectReference: IDerObjectIdentifier;

    function GetEncoding: Int32;
    function GetExternalContent: IAsn1Object;
    function GetIndirectReference: IDerInteger;
    procedure setDataValueDescriptor(const Value: IAsn1Object);
    procedure setDirectReference(const Value: IDerObjectIdentifier);
    procedure setEncoding(const Value: Int32);
    procedure setExternalContent(const Value: IAsn1Object);
    procedure setIndirectReference(const Value: IDerInteger);

    function Asn1GetHashCode(): Int32;
    function Asn1Equals(asn1Object: IAsn1Object): Boolean;

    procedure Encode(derOut: IDerOutputStream);

    property dataValueDescriptor: IAsn1Object read GetDataValueDescriptor
      write setDataValueDescriptor;

    property directReference: IDerObjectIdentifier read GetDirectReference
      write setDirectReference;

    property encoding: Int32 read GetEncoding write setEncoding;

    property ExternalContent: IAsn1Object read GetExternalContent
      write setExternalContent;

    property indirectReference: IDerInteger read GetIndirectReference
      write setIndirectReference;

  end;

implementation

end.
