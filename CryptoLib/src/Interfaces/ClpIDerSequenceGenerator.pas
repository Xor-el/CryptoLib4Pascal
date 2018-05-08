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

unit ClpIDerSequenceGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIDerGenerator,
  ClpIProxiedInterface;

type
  IDerSequenceGenerator = interface(IDerGenerator)
    ['{1E0E4FD7-84CA-4D02-AB9E-5AF8461270DE}']
    procedure AddObject(const obj: IAsn1Encodable);
    function GetRawOutputStream(): TStream;
    procedure Close();
  end;

implementation

end.
