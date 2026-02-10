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

unit ClpIX509NameBuilder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Interface for building X509Name objects with method chaining.
  /// </summary>
  IX509NameBuilder = interface(IInterface)
    ['{F1A2B3C4-D5E6-7890-ABCD-EF1234567890}']

    /// <summary>
    /// Add an RDN (Relative Distinguished Name) by OID and value.
    /// </summary>
    function AddRdn(const AOid: IDerObjectIdentifier; const AValue: String): IX509NameBuilder; overload;

    /// <summary>
    /// Add an RDN by standard name (e.g., "C", "O", "CN") and value.
    /// </summary>
    function AddRdn(const AName: String; const AValue: String): IX509NameBuilder; overload;

    /// <summary>
    /// Add Country attribute.
    /// </summary>
    function AddCountry(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Organization attribute.
    /// </summary>
    function AddOrganization(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Organizational Unit attribute.
    /// </summary>
    function AddOrganizationalUnit(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Locality attribute.
    /// </summary>
    function AddLocality(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add State attribute.
    /// </summary>
    function AddState(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Common Name attribute.
    /// </summary>
    function AddCommonName(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Email Address attribute.
    /// </summary>
    function AddEmailAddress(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Reset the builder, clearing all added RDNs so it can be reused.
    /// </summary>
    function Reset(): IX509NameBuilder;

    /// <summary>
    /// Build and return the X509Name object.
    /// </summary>
    function Build(): IX509Name;

  end;

implementation

end.

