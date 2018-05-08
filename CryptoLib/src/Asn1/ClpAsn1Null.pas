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

unit ClpAsn1Null;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Object,
  ClpIAsn1Null;

type
  /// <summary>
  /// A Null object.
  /// </summary>
  TAsn1Null = class abstract(TAsn1Object, IAsn1Null)

  public

    function ToString(): String; override;

  end;

implementation

{ TAsn1Null }

function TAsn1Null.ToString: String;
begin
  result := 'NULL';
end;

end.
