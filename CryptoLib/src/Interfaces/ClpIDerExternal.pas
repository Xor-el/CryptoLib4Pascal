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
    procedure SetDataValueDescriptor(const Value: IAsn1Object);
    procedure SetDirectReference(const Value: IDerObjectIdentifier);
    procedure SetEncoding(const Value: Int32);
    procedure SetExternalContent(const Value: IAsn1Object);
    procedure SetIndirectReference(const Value: IDerInteger);

    property dataValueDescriptor: IAsn1Object read GetDataValueDescriptor
      write SetDataValueDescriptor;

    property directReference: IDerObjectIdentifier read GetDirectReference
      write SetDirectReference;

    property encoding: Int32 read GetEncoding write SetEncoding;

    property ExternalContent: IAsn1Object read GetExternalContent
      write SetExternalContent;

    property indirectReference: IDerInteger read GetIndirectReference
      write SetIndirectReference;

  end;

implementation

end.
