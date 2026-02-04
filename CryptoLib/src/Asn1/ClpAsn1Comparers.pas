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

unit ClpAsn1Comparers;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Defaults,
  ClpIAsn1Objects;

type
  /// <summary>
  /// Equality comparer for IDerObjectIdentifier that uses value-based comparison
  /// (Asn1Equals) instead of reference equality. Used with TDictionary.
  /// </summary>
  TOidEqualityComparer = class(TInterfacedObject, IEqualityComparer<IDerObjectIdentifier>)
  strict private
    function Equals(const ALeft, ARight: IDerObjectIdentifier): Boolean; reintroduce;
    function GetHashCode(const AValue: IDerObjectIdentifier): Integer;
  end;

  /// <summary>
  /// Comparer for IDerObjectIdentifier that uses value-based comparison
  /// (Asn1Equals) for equality and ID string comparison for ordering.
  /// Used with TList to ensure Contains, IndexOf, and Remove work correctly.
  /// </summary>
  TOidComparer = class(TInterfacedObject, IComparer<IDerObjectIdentifier>)
  strict private
    function Compare(const ALeft, ARight: IDerObjectIdentifier): Integer;
  end;

  /// <summary>
  /// Static utility class providing ASN.1-related comparers (e.g. OID).
  /// </summary>
  TAsn1Comparers = class sealed(TObject)
  strict private
    class var
      FOidEqualityComparer: IEqualityComparer<IDerObjectIdentifier>;
      FOidComparer: IComparer<IDerObjectIdentifier>;
    class constructor Create;
  public
    /// <summary>
    /// Gets the OID equality comparer for use with TDictionary.
    /// </summary>
    class property OidEqualityComparer: IEqualityComparer<IDerObjectIdentifier> read FOidEqualityComparer;

    /// <summary>
    /// Gets the OID comparer for use with TList.
    /// </summary>
    class property OidComparer: IComparer<IDerObjectIdentifier> read FOidComparer;
  end;

implementation

{ TOidEqualityComparer }

function TOidEqualityComparer.Equals(const ALeft, ARight: IDerObjectIdentifier): Boolean;
begin
  if ALeft = ARight then
  begin
    Result := True;
    Exit;
  end;

  if (ALeft = nil) or (ARight = nil) then
  begin
    Result := False;
    Exit;
  end;

  Result := ALeft.Equals(ARight);
end;

function TOidEqualityComparer.GetHashCode(const AValue: IDerObjectIdentifier): Integer;
begin
  if AValue = nil then
  begin
    Result := 0;
    Exit;
  end;

  Result := AValue.CallAsn1GetHashCode();
end;

{ TOidComparer }

function TOidComparer.Compare(const ALeft, ARight: IDerObjectIdentifier): Integer;
begin
  if (ALeft = nil) and (ARight = nil) then
  begin
    Result := 0;
    Exit;
  end;

  if ALeft = nil then
  begin
    Result := -1;
    Exit;
  end;

  if ARight = nil then
  begin
    Result := 1;
    Exit;
  end;

  if ALeft = ARight then
  begin
    Result := 0;
    Exit;
  end;

  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;

  if ALeft.Id < ARight.Id then
    Result := -1
  else if ALeft.Id > ARight.Id then
    Result := 1
  else
    Result := 0;
end;

{ TAsn1Comparers }

class constructor TAsn1Comparers.Create;
begin
  FOidEqualityComparer := TOidEqualityComparer.Create();
  FOidComparer := TOidComparer.Create();
end;

end.
