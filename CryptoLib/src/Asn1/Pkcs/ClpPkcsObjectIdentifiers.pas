{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpPkcsObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpDerObjectIdentifier,
  ClpIDerObjectIdentifier;

type
  TPkcsObjectIdentifiers = class abstract(TObject)

  strict private

    class var

      FMD2, FMD4, FMD5: IDerObjectIdentifier;

    class function GetMD2: IDerObjectIdentifier; static; inline;
    class function GetMD4: IDerObjectIdentifier; static; inline;
    class function GetMD5: IDerObjectIdentifier; static; inline;

    class constructor PkcsObjectIdentifiers();

  public

    const
    //
    // object identifiers for digests
    //
    DigestAlgorithm = '1.2.840.113549.2';

    //
    // md2 OBJECT IDENTIFIER ::=
    // {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 2}
    //
    class property MD2: IDerObjectIdentifier read GetMD2;
    //
    // md4 OBJECT IDENTIFIER ::=
    // {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 4}
    //
    class property MD4: IDerObjectIdentifier read GetMD4;
    //
    // md5 OBJECT IDENTIFIER ::=
    // {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 5}
    //
    class property MD5: IDerObjectIdentifier read GetMD5;

    class procedure Boot(); static;

  end;

implementation

{ TPkcsObjectIdentifiers }

class procedure TPkcsObjectIdentifiers.Boot;
begin
  FMD2 := TDerObjectIdentifier.Create(DigestAlgorithm + '.2');
  FMD4 := TDerObjectIdentifier.Create(DigestAlgorithm + '.4');
  FMD5 := TDerObjectIdentifier.Create(DigestAlgorithm + '.5');
end;

class function TPkcsObjectIdentifiers.GetMD2: IDerObjectIdentifier;
begin
  result := FMD2;
end;

class function TPkcsObjectIdentifiers.GetMD4: IDerObjectIdentifier;
begin
  result := FMD4;
end;

class function TPkcsObjectIdentifiers.GetMD5: IDerObjectIdentifier;
begin
  result := FMD5;
end;

class constructor TPkcsObjectIdentifiers.PkcsObjectIdentifiers;
begin
  TPkcsObjectIdentifiers.Boot;
end;

end.
