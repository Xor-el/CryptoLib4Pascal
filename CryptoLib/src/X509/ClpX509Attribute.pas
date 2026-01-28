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

unit ClpX509Attribute;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Class for carrying the values in an X.509 Attribute.
  /// </summary>
  IX509Attribute = interface
    ['{B1C2D3E4-F5A6-7890-BCDE-F12345678901}']

    function GetOid: String;
    function GetValues: TCryptoLibGenericArray<IAsn1Encodable>;
    function ToAsn1Object: IAsn1Object;

    property Oid: String read GetOid;
  end;

  /// <summary>
  /// Implementation of X.509 Attribute.
  /// </summary>
  TX509Attribute = class sealed(TInterfacedObject, IX509Attribute)

  strict private
    FAttr: IAttributeX509;

    function GetOid: String;
    function GetValues: TCryptoLibGenericArray<IAsn1Encodable>;
    function ToAsn1Object: IAsn1Object;

  public
    /// <summary>
    /// Create from an object representing an attribute.
    /// </summary>
    constructor Create(const AAttr: IAsn1Encodable); overload;

    property Oid: String read GetOid;
  end;

implementation

{ TX509Attribute }

constructor TX509Attribute.Create(const AAttr: IAsn1Encodable);
begin
  inherited Create();
  FAttr := TAttributeX509.GetInstance(AAttr);
end;

function TX509Attribute.GetOid: String;
begin
  Result := FAttr.AttrType.Id;
end;

function TX509Attribute.GetValues: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := FAttr.GetAttributeValues;
end;

function TX509Attribute.ToAsn1Object: IAsn1Object;
begin
  Result := FAttr.ToAsn1Object;
end;

end.
