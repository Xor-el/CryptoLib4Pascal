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

unit ClpIGcmExponentiator;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  IGcmExponentiator = interface(IInterface)
    ['{F81FBBDC-96A9-473F-A1F3-2B5A6A5DA644}']

    procedure Init(const AX: TCryptoLibByteArray);
    procedure ExponentiateX(APow: Int64; const AOutput: TCryptoLibByteArray);
  end;

implementation

end.
