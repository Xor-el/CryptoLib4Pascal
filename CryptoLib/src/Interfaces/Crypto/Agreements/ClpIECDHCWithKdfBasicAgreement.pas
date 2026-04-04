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

unit ClpIECDHCWithKdfBasicAgreement;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECDHCBasicAgreement;

type
  IECDHCWithKdfBasicAgreement = interface(IECDHCBasicAgreement)
    ['{B4911A79-9B45-4ECC-BCC5-712E5F9E4817}']

  end;

implementation

end.
