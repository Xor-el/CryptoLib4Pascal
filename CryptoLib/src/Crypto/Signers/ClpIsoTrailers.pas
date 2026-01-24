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

unit ClpIsoTrailers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpIDigest;

type
  /// <summary>
  /// Utility class for ISO/IEC 10118 trailer values used in X9.31 and ISO9796-2 signing.
  /// </summary>
  TIsoTrailers = class sealed(TObject)

  public
  const
    TRAILER_IMPLICIT = Int32($BC);
    TRAILER_RIPEMD160 = Int32($31CC);
    TRAILER_RIPEMD128 = Int32($32CC);
    TRAILER_SHA1 = Int32($33CC);
    TRAILER_SHA256 = Int32($34CC);
    TRAILER_SHA512 = Int32($35CC);
    TRAILER_SHA384 = Int32($36CC);
    TRAILER_WHIRLPOOL = Int32($37CC);
    TRAILER_SHA224 = Int32($38CC);
    TRAILER_SHA512_224 = Int32($39CC);
    TRAILER_SHA512_256 = Int32($40CC);

  strict private
  class var
    FTrailerMap: TDictionary<String, Int32>;

    class function CreateTrailerMap: TDictionary<String, Int32>; static;
    class constructor Create;
    class destructor Destroy;

  public
    /// <summary>
    /// Get the trailer value for the specified digest.
    /// </summary>
    /// <param name="digest">The digest to get the trailer for.</param>
    /// <returns>The trailer value.</returns>
    /// <exception cref="EInvalidOperationCryptoLibException">If no trailer is available for the digest.</exception>
    class function GetTrailer(const digest: IDigest): Int32; static;

    /// <summary>
    /// Check if a trailer is available for the specified digest.
    /// </summary>
    /// <param name="digest">The digest to check.</param>
    /// <returns>True if no trailer is available, False otherwise.</returns>
    class function NoTrailerAvailable(const digest: IDigest): Boolean; static;

  end;

implementation

{ TIsoTrailers }

class function TIsoTrailers.CreateTrailerMap: TDictionary<String, Int32>;
begin
  Result := TDictionary<String, Int32>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  Result.Add('RIPEMD128', TRAILER_RIPEMD128);
  Result.Add('RIPEMD160', TRAILER_RIPEMD160);

  Result.Add('SHA-1', TRAILER_SHA1);
  Result.Add('SHA-224', TRAILER_SHA224);
  Result.Add('SHA-256', TRAILER_SHA256);
  Result.Add('SHA-384', TRAILER_SHA384);
  Result.Add('SHA-512', TRAILER_SHA512);
  Result.Add('SHA-512/224', TRAILER_SHA512_224);
  Result.Add('SHA-512/256', TRAILER_SHA512_256);

  Result.Add('Whirlpool', TRAILER_WHIRLPOOL);
end;

class constructor TIsoTrailers.Create;
begin
  FTrailerMap := CreateTrailerMap;
end;

class destructor TIsoTrailers.Destroy;
begin
  FTrailerMap.Free;
end;

class function TIsoTrailers.GetTrailer(const digest: IDigest): Int32;
var
  LTrailer: Int32;
begin
  if FTrailerMap.TryGetValue(digest.AlgorithmName, LTrailer) then
  begin
    Result := LTrailer;
  end
  else
  begin
    raise EInvalidOperationCryptoLibException.Create('No trailer for digest');
  end;
end;

class function TIsoTrailers.NoTrailerAvailable(const digest: IDigest): Boolean;
begin
  Result := not FTrailerMap.ContainsKey(digest.AlgorithmName);
end;

end.
