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

unit ClpCTFieldArith;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCTFieldValue;

type
  /// <summary>
  /// Per-curve prime-field arithmetic as a base of <c>virtual; abstract</c>
  /// class methods over <see cref="TFe"/> records; a curve overrides each op
  /// and the generic <c>TCTPoint&lt;TOps: TCTFieldArithBase&gt;</c> dispatches to it.
  /// </summary>
  TCTFieldArithBase = class
  public
    /// <summary>uint32 limb count N for this curve (P-256 = 8).</summary>
    class function FieldLimbs: Int32; virtual; abstract;
    /// <summary>AZ := AX * AY mod p. ATT is caller-owned 2N scratch.</summary>
    class procedure Mul(const AX, AY: TFe; var AZ: TFe; var ATT: TFeExt); virtual; abstract;
    /// <summary>AZ := AX^2 mod p.</summary>
    class procedure Sqr(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual; abstract;
    /// <summary>AZ := AX + AY mod p.</summary>
    class procedure Add(const AX, AY: TFe; var AZ: TFe); virtual; abstract;
    /// <summary>AZ := AX - AY mod p.</summary>
    class procedure Sub(const AX, AY: TFe; var AZ: TFe); virtual; abstract;
    /// <summary>AZ := a * AX mod p (curve coefficient a).</summary>
    class procedure MulByA(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual; abstract;
    /// <summary>AZ := 3b * AX mod p (b3 = 3 * curve coefficient b).</summary>
    class procedure MulByB3(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual; abstract;
  end;

implementation

end.
