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

unit ClpRfc5280Asn1Utilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpDateTimeUtilities,
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>
  /// RFC 5280 ASN.1 utilities for creating time objects.
  /// </summary>
  TRfc5280Asn1Utilities = class sealed(TObject)
  public
    /// <summary>
    /// Create a GeneralizedTime from a DateTime with second precision.
    /// </summary>
    class function CreateGeneralizedTime(const ADateTime: TDateTime): IAsn1GeneralizedTime; static;
    /// <summary>
    /// Create a UtcTime from a DateTime with 2049 as the two-digit year maximum.
    /// </summary>
    class function CreateUtcTime(const ADateTime: TDateTime): IAsn1UtcTime; static;
  end;

implementation

{ TRfc5280Asn1Utilities }

class function TRfc5280Asn1Utilities.CreateGeneralizedTime(const ADateTime: TDateTime): IAsn1GeneralizedTime;
begin
  Result := TDerGeneralizedTime.Create(TDateTimeUtilities.WithPrecisionSecond(ADateTime));
end;

class function TRfc5280Asn1Utilities.CreateUtcTime(const ADateTime: TDateTime): IAsn1UtcTime;
begin
  Result := TDerUtcTime.Create(ADateTime, 2049);
end;

end.
