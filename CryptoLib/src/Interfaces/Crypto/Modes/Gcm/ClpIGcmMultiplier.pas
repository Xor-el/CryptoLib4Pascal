{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIGcmMultiplier;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  IGcmMultiplier = interface(IInterface)
    ['{D116500F-7623-4FC6-A889-70EEC7214489}']

    procedure Init(const AH: TCryptoLibByteArray);
    procedure MultiplyH(const AX: TCryptoLibByteArray);
  end;

implementation

end.
