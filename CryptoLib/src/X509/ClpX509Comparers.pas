{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpX509Comparers;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Defaults,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Comparer for IX509Certificate that uses the encoded value for equality instead of reference
  /// identity. Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TX509CertificateComparer = class(TInterfacedObject, IComparer<IX509Certificate>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: IX509Certificate): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: IX509Certificate): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Comparer for IX509Crl that uses the encoded value for equality instead of reference identity.
  /// Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TX509CrlComparer = class(TInterfacedObject, IComparer<IX509Crl>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: IX509Crl): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: IX509Crl): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Equality comparer for IX509Certificate that uses the encoded value instead of reference
  /// identity. Used with TCryptoLibHashSet.
  /// </summary>
  TX509CertificateEqualityComparer = class(TInterfacedObject, IEqualityComparer<IX509Certificate>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: IX509Certificate): Boolean; reintroduce;
    function GetHashCode(constref AValue: IX509Certificate): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: IX509Certificate): Boolean; reintroduce;
    function GetHashCode(const AValue: IX509Certificate): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
  end;

  /// <summary>
  /// Static utility class providing X.509-related comparers.
  /// </summary>
  TX509Comparers = class sealed(TObject)
  strict private
    class var
      FCertificateComparer: IComparer<IX509Certificate>;
      FCrlComparer: IComparer<IX509Crl>;
      FCertificateEqualityComparer: IEqualityComparer<IX509Certificate>;
    class constructor Create;
  public
    /// <summary>
    /// Gets the certificate comparer for use with TList.
    /// </summary>
    class property CertificateComparer: IComparer<IX509Certificate> read FCertificateComparer;

    /// <summary>
    /// Gets the CRL comparer for use with TList.
    /// </summary>
    class property CrlComparer: IComparer<IX509Crl> read FCrlComparer;

    /// <summary>
    /// Gets the certificate equality comparer for use with TCryptoLibHashSet.
    /// </summary>
    class property CertificateEqualityComparer: IEqualityComparer<IX509Certificate>
      read FCertificateEqualityComparer;
  end;

implementation

// Lexicographic order on the encodings, shortest first. Only a stable total order for lookup.
function CompareHashCodes(ALeft, ARight: Int64): Integer;
begin
  if ALeft < ARight then
    Result := -1
  else if ALeft > ARight then
    Result := 1
  else
    Result := 0;
end;

{ TX509CertificateComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TX509CertificateComparer.Compare(constref ALeft, ARight: IX509Certificate): Integer;
{$ELSE}
function TX509CertificateComparer.Compare(const ALeft, ARight: IX509Certificate): Integer;
{$ENDIF}
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

  Result := CompareHashCodes(ALeft.GetHashCode(), ARight.GetHashCode());
  if Result = 0 then
    Result := TArrayUtilities.LexicographicCompare(ALeft.GetEncoded(), ARight.GetEncoded());
end;

{ TX509CrlComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TX509CrlComparer.Compare(constref ALeft, ARight: IX509Crl): Integer;
{$ELSE}
function TX509CrlComparer.Compare(const ALeft, ARight: IX509Crl): Integer;
{$ENDIF}
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

  Result := CompareHashCodes(ALeft.GetHashCode(), ARight.GetHashCode());
  if Result = 0 then
    Result := TArrayUtilities.LexicographicCompare(ALeft.GetEncoded(), ARight.GetEncoded());
end;

{ TX509Comparers }

{ TX509CertificateEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TX509CertificateEqualityComparer.Equals(constref ALeft, ARight: IX509Certificate): Boolean;
{$ELSE}
function TX509CertificateEqualityComparer.Equals(const ALeft, ARight: IX509Certificate): Boolean;
{$ENDIF}
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

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TX509CertificateEqualityComparer.GetHashCode(constref AValue: IX509Certificate): UInt32;
{$ELSE}
function TX509CertificateEqualityComparer.GetHashCode(const AValue: IX509Certificate): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  if AValue = nil then
  begin
    Result := 0;
    Exit;
  end;

  Result := AValue.GetHashCode();
end;

{ TX509Comparers }

class constructor TX509Comparers.Create;
begin
  FCertificateComparer := TX509CertificateComparer.Create();
  FCrlComparer := TX509CrlComparer.Create();
  FCertificateEqualityComparer := TX509CertificateEqualityComparer.Create();
end;

end.
