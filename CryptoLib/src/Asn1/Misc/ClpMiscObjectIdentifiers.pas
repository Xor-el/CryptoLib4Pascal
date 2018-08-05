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

unit ClpMiscObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpDerObjectIdentifier,
  ClpIDerObjectIdentifier;

type
  TMiscObjectIdentifiers = class abstract(TObject)

  strict private

  class var

    FIsBooted: Boolean;
    Fblake2, Fid_blake2b160, Fid_blake2b256, Fid_blake2b384, Fid_blake2b512,
      Fid_blake2s128, Fid_blake2s160, Fid_blake2s224, Fid_blake2s256
      : IDerObjectIdentifier;

    class function Getblake2: IDerObjectIdentifier; static; inline;

    class function Getid_blake2b160: IDerObjectIdentifier; static; inline;
    class function Getid_blake2b256: IDerObjectIdentifier; static; inline;
    class function Getid_blake2b384: IDerObjectIdentifier; static; inline;
    class function Getid_blake2b512: IDerObjectIdentifier; static; inline;

    class function Getid_blake2s128: IDerObjectIdentifier; static; inline;
    class function Getid_blake2s160: IDerObjectIdentifier; static; inline;
    class function Getid_blake2s224: IDerObjectIdentifier; static; inline;
    class function Getid_blake2s256: IDerObjectIdentifier; static; inline;

    class constructor MiscObjectIdentifiers();

  public

    class property blake2: IDerObjectIdentifier read Getblake2;

    class property id_blake2b160: IDerObjectIdentifier read Getid_blake2b160;
    class property id_blake2b256: IDerObjectIdentifier read Getid_blake2b256;
    class property id_blake2b384: IDerObjectIdentifier read Getid_blake2b384;
    class property id_blake2b512: IDerObjectIdentifier read Getid_blake2b512;

    class property id_blake2s128: IDerObjectIdentifier read Getid_blake2s128;
    class property id_blake2s160: IDerObjectIdentifier read Getid_blake2s160;
    class property id_blake2s224: IDerObjectIdentifier read Getid_blake2s224;
    class property id_blake2s256: IDerObjectIdentifier read Getid_blake2s256;

    class procedure Boot(); static;

  end;

implementation

{ TMiscObjectIdentifiers }

class function TMiscObjectIdentifiers.Getblake2: IDerObjectIdentifier;
begin
  result := Fblake2;
end;

class function TMiscObjectIdentifiers.Getid_blake2b160: IDerObjectIdentifier;
begin
  result := Fid_blake2b160;
end;

class function TMiscObjectIdentifiers.Getid_blake2b256: IDerObjectIdentifier;
begin
  result := Fid_blake2b256;
end;

class function TMiscObjectIdentifiers.Getid_blake2b384: IDerObjectIdentifier;
begin
  result := Fid_blake2b384;
end;

class function TMiscObjectIdentifiers.Getid_blake2b512: IDerObjectIdentifier;
begin
  result := Fid_blake2b512;
end;

class function TMiscObjectIdentifiers.Getid_blake2s128: IDerObjectIdentifier;
begin
  result := Fid_blake2s128;
end;

class function TMiscObjectIdentifiers.Getid_blake2s160: IDerObjectIdentifier;
begin
  result := Fid_blake2s160;
end;

class function TMiscObjectIdentifiers.Getid_blake2s224: IDerObjectIdentifier;
begin
  result := Fid_blake2s224;
end;

class function TMiscObjectIdentifiers.Getid_blake2s256: IDerObjectIdentifier;
begin
  result := Fid_blake2s256;
end;

class procedure TMiscObjectIdentifiers.Boot;
begin

  if not FIsBooted then
  begin
    //
    // Blake2b and Blake2s
    //
    Fblake2 := TDerObjectIdentifier.Create('1.3.6.1.4.1.1722.12.2');

    Fid_blake2b160 := blake2.Branch('1.5');
    Fid_blake2b256 := blake2.Branch('1.8');
    Fid_blake2b384 := blake2.Branch('1.12');
    Fid_blake2b512 := blake2.Branch('1.16');

    Fid_blake2s128 := blake2.Branch('2.4');
    Fid_blake2s160 := blake2.Branch('2.5');
    Fid_blake2s224 := blake2.Branch('2.7');
    Fid_blake2s256 := blake2.Branch('2.8');

    FIsBooted := True;
  end;
end;

class constructor TMiscObjectIdentifiers.MiscObjectIdentifiers;
begin
  TMiscObjectIdentifiers.Boot;
end;

end.
