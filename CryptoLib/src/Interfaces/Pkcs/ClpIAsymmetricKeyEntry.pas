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

unit ClpIAsymmetricKeyEntry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPkcs12Entry,
  ClpIAsymmetricKeyParameter;

type
  /// <summary>
  /// Interface for AsymmetricKeyEntry (PKCS#12 asymmetric key bag entry).
  /// </summary>
  IAsymmetricKeyEntry = interface(IPkcs12Entry)
    ['{C6DA2D43-8882-43E1-85F7-5561E91E97D6}']

    function GetKey: IAsymmetricKeyParameter;
    function Equals(const AOther: IAsymmetricKeyEntry): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property Key: IAsymmetricKeyParameter read GetKey;
  end;

implementation

end.
