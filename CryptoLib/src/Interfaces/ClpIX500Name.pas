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

unit ClpIX500Name;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for X.500 Distinguished Name
  /// </summary>
  IX500Name = interface(IAsn1Encodable)
    ['{3216F2D5-BA2E-42E4-B439-F550D742F880}']
  end;

  /// <summary>
  /// Builder interface for constructing X.500 Names
  /// </summary>
  IX500NameBuilder = interface
    ['{B16CEFF4-EA57-43DC-A9F7-E01456798C82}']
    function AddRdn(const oid: IDerObjectIdentifier; const value: string): IX500NameBuilder;
    function AddCommonName(const value: string): IX500NameBuilder;
    function AddOrganization(const value: string): IX500NameBuilder;
    function AddOrganizationalUnit(const value: string): IX500NameBuilder;
    function AddCountry(const value: string): IX500NameBuilder;
    function AddState(const value: string): IX500NameBuilder;
    function AddLocality(const value: string): IX500NameBuilder;
    function AddEmailAddress(const value: string): IX500NameBuilder;
    function Build: IX500Name;
  end;

implementation

end.
