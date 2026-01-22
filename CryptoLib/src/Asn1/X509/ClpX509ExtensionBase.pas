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

unit ClpX509ExtensionBase;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base class for X509 objects that support extensions.
  /// </summary>
  TX509ExtensionBase = class abstract(TInterfacedObject)

  strict protected
    /// <summary>
    /// Get the X509Extensions object for this instance.
    /// </summary>
    function GetX509Extensions: IX509Extensions; virtual; abstract;

    /// <summary>
    /// Get extension OIDs filtered by critical flag.
    /// </summary>
    function GetExtensionOids(ACritical: Boolean): TCryptoLibStringArray; virtual;

  public
    /// <summary>
    /// Get non critical extensions.
    /// </summary>
    /// <returns>An array of non critical extension OID strings.</returns>
    function GetNonCriticalExtensionOids: TCryptoLibStringArray; virtual;

    /// <summary>
    /// Get any critical extensions.
    /// </summary>
    /// <returns>An array of critical extension OID strings.</returns>
    function GetCriticalExtensionOids: TCryptoLibStringArray; virtual;

    /// <summary>
    /// Get extension value by OID.
    /// </summary>
    function GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString; virtual;

    /// <summary>
    /// Get extension by OID.
    /// </summary>
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension; virtual;

    /// <summary>
    /// Get parsed extension value by OID.
    /// </summary>
    function GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object; virtual;

  end;

implementation

{ TX509ExtensionBase }

function TX509ExtensionBase.GetExtensionOids(ACritical: Boolean): TCryptoLibStringArray;
var
  LExtensions: IX509Extensions;
  LOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LExt: IX509Extension;
  LList: TList<String>;
  I: Int32;
begin
  LExtensions := GetX509Extensions();
  if LExtensions = nil then
  begin
    Result := nil;
    Exit;
  end;

  LList := TList<String>.Create();
  try
    LOids := LExtensions.GetExtensionOids;
    for I := 0 to System.Length(LOids) - 1 do
    begin
      LExt := LExtensions.GetExtension(LOids[I]);
      if (LExt <> nil) and (LExt.IsCritical = ACritical) then
      begin
        LList.Add(LOids[I].Id);
      end;
    end;
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
end;

function TX509ExtensionBase.GetNonCriticalExtensionOids: TCryptoLibStringArray;
begin
  Result := GetExtensionOids(False);
end;

function TX509ExtensionBase.GetCriticalExtensionOids: TCryptoLibStringArray;
begin
  Result := GetExtensionOids(True);
end;

function TX509ExtensionBase.GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
var
  LExtensions: IX509Extensions;
begin
  LExtensions := GetX509Extensions();
  if LExtensions = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := LExtensions.GetExtension(AOid);
end;

function TX509ExtensionBase.GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object;
var
  LExtensions: IX509Extensions;
begin
  LExtensions := GetX509Extensions();
  if LExtensions = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := LExtensions.GetExtensionParsedValue(AOid);
end;

function TX509ExtensionBase.GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
var
  LExtensions: IX509Extensions;
begin
  LExtensions := GetX509Extensions();
  if LExtensions = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := LExtensions.GetExtensionValue(AOid);
end;

end.
