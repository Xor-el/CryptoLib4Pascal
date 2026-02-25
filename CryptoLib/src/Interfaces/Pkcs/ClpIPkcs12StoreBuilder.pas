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

unit ClpIPkcs12StoreBuilder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIPkcs12Store,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Fluent builder for IPkcs12Store with configurable algorithms and options.
  /// </summary>
  IPkcs12StoreBuilder = interface(IInterface)
    ['{8E7F2D1C-9B4A-4E5F-8C3D-0A1B2C3D4E5F}']

    function Build: IPkcs12Store;
    function SetCertAlgorithm(const ACertAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    function SetCertAlgorithm(const ACertAlgorithm, ACertPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    /// <summary>
    /// Whether to include Oracle's TrustedKeyUsage attribute in CertBag attributes. Defaults to <c>true</c>.
    /// </summary>
    /// <remarks>The OID 2.16.840.1.113894.746875.1.1 is used for this attribute.</remarks>
    /// <param name="AEnableOracleTrustedKeyUsage"></param>
    /// <returns></returns>
    function SetEnableOracleTrustedKeyUsage(AEnableOracleTrustedKeyUsage: Boolean): IPkcs12StoreBuilder;
    function SetKeyAlgorithm(const AKeyAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    function SetKeyAlgorithm(const AKeyAlgorithm, AKeyPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    function SetOverwriteFriendlyName(AOverwriteFriendlyName: Boolean): IPkcs12StoreBuilder;
    function SetReverseCertificates(AReverseCertificates: Boolean): IPkcs12StoreBuilder;
    function SetUseDerEncoding(AUseDerEncoding: Boolean): IPkcs12StoreBuilder;
  end;

implementation

end.
