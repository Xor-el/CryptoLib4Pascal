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

unit ClpX509Extension;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Extension,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// An object for the elements in the X.509 V3 extension block.
  /// Note: This is NOT an ASN1Encodable, it's a helper class.
  /// </summary>
  TX509Extension = class(TInterfacedObject, IX509Extension)

  strict private
  var
    FCritical: Boolean;
    FValue: IAsn1OctetString;

  strict protected
    function GetIsCritical: Boolean;
    function GetValue: IAsn1OctetString;
    function GetParsedValue: IAsn1Object;

  public
    /// <summary>
    /// Convert the value of the passed in extension to an object.
    /// </summary>
    class function ConvertValueToObject(const AExt: IX509Extension): IAsn1Object; static;

    constructor Create(const ACritical: IDerBoolean; const AValue: IAsn1OctetString); overload;
    constructor Create(ACritical: Boolean; const AValue: IAsn1OctetString); overload;

    function GetHashCode: Int32;
    function Equals(AObj: TObject): Boolean; reintroduce;

    property IsCritical: Boolean read GetIsCritical;
    property Value: IAsn1OctetString read GetValue;

  end;

implementation

{ TX509Extension }

class function TX509Extension.ConvertValueToObject(const AExt: IX509Extension): IAsn1Object;
begin
  try
    Result := TAsn1Object.FromByteArray(AExt.Value.GetOctets());
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('can''t convert extension: ' + E.Message);
  end;
end;

constructor TX509Extension.Create(const ACritical: IDerBoolean; const AValue: IAsn1OctetString);
begin
  inherited Create();
  if ACritical = nil then
    raise EArgumentNilCryptoLibException.Create('critical');
  if AValue = nil then
    raise EArgumentNilCryptoLibException.Create('value');
  FCritical := ACritical.IsTrue;
  FValue := AValue;
end;

constructor TX509Extension.Create(ACritical: Boolean; const AValue: IAsn1OctetString);
begin
  inherited Create();
  if AValue = nil then
    raise EArgumentNilCryptoLibException.Create('value');
  FCritical := ACritical;
  FValue := AValue;
end;

function TX509Extension.GetIsCritical: Boolean;
begin
  Result := FCritical;
end;

function TX509Extension.GetValue: IAsn1OctetString;
begin
  Result := FValue;
end;

function TX509Extension.GetParsedValue: IAsn1Object;
begin
  Result := ConvertValueToObject(Self);
end;

function TX509Extension.GetHashCode: Int32;
var
  LVH: Int32;
begin
  LVH := FValue.GetHashCode();
  if FCritical then
    Result := LVH
  else
    Result := not LVH;
end;

function TX509Extension.Equals(AObj: TObject): Boolean;
var
  LThat: IX509Extension;
begin
  if not Supports(AObj, IX509Extension, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := FValue.Equals(LThat.Value) and (FCritical = LThat.IsCritical);
end;

end.
