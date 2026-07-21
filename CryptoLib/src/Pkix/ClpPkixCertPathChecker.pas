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

unit ClpPkixCertPathChecker;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIPkixTypes,
  ClpIX509Certificate,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base for an additional per-certificate check run by a path validator or builder.
  /// </summary>
  /// <remarks>
  /// A checker MUST support reverse checking (trust anchor towards target) and MAY support forward
  /// checking; <see cref="Init" /> says which direction the certificates will arrive in.
  /// </remarks>
  TPkixCertPathCheckerBase = class abstract(TInterfacedObject, IPkixCertPathChecker)

  public
    procedure Init(AForward: Boolean); virtual; abstract;
    function IsForwardCheckingSupported: Boolean; virtual; abstract;
    /// <summary>The critical extension OIDs this checker recognizes, or nil when none.</summary>
    function GetSupportedExtensions: TCryptoLibStringArray; virtual; abstract;
    /// <summary>Check ACert, removing every critical extension OID it processes from AUnresolvedCritExts.</summary>
    procedure Check(const ACert: IX509Certificate; const AUnresolvedCritExts: TList<String>);
      virtual; abstract;
    /// <summary>A checker carrying state must return an independent copy.</summary>
    function Clone: IPkixCertPathChecker; virtual; abstract;
  end;

implementation

end.
