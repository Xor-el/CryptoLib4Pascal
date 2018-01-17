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

unit ClpBerOutputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpDerOutputStream,
  ClpIBerOutputStream;

type
  // TODO Make Obsolete in favour of Asn1OutputStream?
  TBerOutputStream = class sealed(TDerOutputStream, IBerOutputStream)

  public

    constructor Create(os: TStream);

  end;

implementation

{ TBerOutputStream }

constructor TBerOutputStream.Create(os: TStream);
begin
  Inherited Create(os);
end;

end.
