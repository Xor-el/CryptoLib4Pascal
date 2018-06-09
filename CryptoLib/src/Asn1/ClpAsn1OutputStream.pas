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

unit ClpAsn1OutputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpDerOutputStream;

type
  TAsn1OutputStream = class sealed(TDerOutputStream)

  public
    constructor Create(os: TStream);

  end;

implementation

{ TAsn1OutputStream }

constructor TAsn1OutputStream.Create(os: TStream);
begin
  Inherited Create(os);
end;

end.
