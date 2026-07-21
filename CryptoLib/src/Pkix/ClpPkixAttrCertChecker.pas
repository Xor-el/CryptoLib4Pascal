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

unit ClpPkixAttrCertChecker;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIX509V2AttributeCertificate,
  ClpIPkixTypes,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// The base for an additional check run against an attribute certificate during RFC 3281 path
  /// validation. A subclass reports the critical extension OIDs it understands, performs its check,
  /// and can clone itself.
  /// </summary>
  TPkixAttrCertCheckerBase = class abstract(TInterfacedObject, IPkixAttrCertChecker)

  public
    /// <summary>
    /// The X.509 attribute certificate extension OIDs this checker supports, or nil when it supports
    /// none. Every OID a checker might process should be listed.
    /// </summary>
    function GetSupportedExtensions: TCryptoLibStringArray; virtual; abstract;

    /// <summary>
    /// Check AAttrCert, removing every critical extension OID it handles from AUnresolvedCritExts.
    /// ACertPath belongs to the issuer public key certificate, AHolderCertPath to the holder.
    /// </summary>
    procedure Check(const AAttrCert: IX509V2AttributeCertificate; const ACertPath: IPkixCertPath;
      const AHolderCertPath: IPkixCertPath; const AUnresolvedCritExts: TList<String>); virtual; abstract;

    /// <summary>A copy of this checker.</summary>
    function Clone: IPkixAttrCertChecker; virtual; abstract;
  end;

implementation

end.
