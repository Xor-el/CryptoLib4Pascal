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

unit ClpIBerGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIProxiedInterface,
  ClpIAsn1Generator;

type
  IBerGenerator = interface(IAsn1Generator)
    ['{9ED01B6B-EF67-46B2-8EF6-023CA3967345}']

    procedure WriteHdr(tag: Int32);

    procedure WriteBerHeader(tag: Int32);
    procedure WriteBerBody(contentStream: TStream);
    procedure WriteBerEnd();

    procedure AddObject(const obj: IAsn1Encodable);
    function GetRawOutputStream(): TStream;
    procedure Close();

  end;

implementation

end.
