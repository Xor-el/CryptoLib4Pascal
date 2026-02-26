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

unit ClpIPkcs12Store;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  TypInfo,
  ClpIX509Certificate,
  ClpIX509CertificateEntry,
  ClpIAsymmetricKeyEntry,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for PKCS#12 store (keys and certificates). Load/Save PFX and manage aliases.
  /// </summary>
  IPkcs12Store = interface(IInterface)
    ['{2D3E4F5A-6B7C-8D9E-0F1A-2B3C4D5E6F7A}']

    procedure Load(const AInput: TStream; const APassword: TCryptoLibCharArray);
    function GetKey(const AAlias: String): IAsymmetricKeyEntry;
    function IsCertificateEntry(const AAlias: String): Boolean;
    function IsKeyEntry(const AAlias: String): Boolean;
    function GetAliases: TCryptoLibStringArray;
    function ContainsAlias(const AAlias: String): Boolean;
    function GetCertificate(const AAlias: String): IX509CertificateEntry;
    function GetCertificateAlias(const ACert: IX509Certificate): String;
    function GetCertificateChain(const AAlias: String): TCryptoLibGenericArray<IX509CertificateEntry>;
    procedure SetCertificateEntry(const AAlias: String; const ACertEntry: IX509CertificateEntry);
    procedure SetFriendlyName(const AAlias: String; const ANewFriendlyName: String);
    procedure SetKeyEntry(const AAlias: String; const AKeyEntry: IAsymmetricKeyEntry;
      const AChain: TCryptoLibGenericArray<IX509CertificateEntry>);
    procedure DeleteEntry(const AAlias: String);
    function IsEntryOfType(const AAlias: String; AEntryType: PTypeInfo): Boolean;
    function GetCount: Int32;
    procedure Save(const AStream: TStream; const APassword: TCryptoLibCharArray; const ARandom: ISecureRandom);

    property Count: Int32 read GetCount;
    property Aliases: TCryptoLibStringArray read GetAliases;
  end;

implementation

end.
